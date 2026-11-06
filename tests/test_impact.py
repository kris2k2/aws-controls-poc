"""Impact (ADR-0012): replaying CloudTrail through the denies, and what it spares the people reviewing."""

import copy
import datetime as dt
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard.cli import main
from onboard.impact import ImpactError, load_records, replay
from tests.cloudtrail import ATHENA_VPCE, PREVIEW, normal_activity, record
from tests.test_review import RunCase


class ImpactTest(RunCase):
    def setUp(self):
        super().setUp()
        self.request_path, self.run = self.build()
        self.request = json.loads(self.request_path.read_text())

    def run_replay(self, log):
        policies = {p.stem: json.loads(p.read_text()) for p in (self.run / "org-policies").glob("*.json")}
        return replay(policies, json.loads((self.run / "composition.json").read_text()), self.request["org_state"],
                      log["Records"], source="test")

    def review_with_impact(self):
        return self.review(self.request_path, self.run, evidence=json.loads((self.run / "impact.json").read_text()))

    def cli(self, log, name="trail.json"):
        path = self.tmp / name
        path.write_text(json.dumps(log))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["impact", str(self.request_path), "--run", str(self.run),
                                   "--cloudtrail", str(path)]), 0)

    def test_normal_activity_answers_every_impact_question(self):
        result = self.run_replay(normal_activity())
        self.assertEqual({i["result"] for i in result["evidence"]["items"]}, {"pass"})
        report = {s["sid"]: s for s in result["report"]["statements"]}
        self.assertEqual(report["ORGC02"]["in_scope"], 40)  # the S3 reads, all to an organization bucket
        self.assertEqual(report["ORGC04"]["in_scope"], 0)  # nobody touched a protected role
        before = self.doubts(self.review(self.request_path, self.run), "needs acceptance")
        self.cli(normal_activity())
        after = self.doubts(self.review_with_impact(), "needs acceptance")
        asked = {d for d in before if d.startswith("evidence-impact:")}
        self.assertEqual(len(asked), 6)
        self.assertFalse({d for d in after if d.startswith("evidence-impact:")})

    def test_a_deny_that_would_break_a_running_call_blocks(self):
        log = normal_activity()
        when = dt.datetime(2026, 10, 1, 12, tzinfo=dt.timezone.utc)
        log["Records"].append(record(when, "athena.amazonaws.com", "StartQueryExecution", region="us-west-2",
                                     vpce=ATHENA_VPCE))
        result = self.run_replay(log)
        failed = [i for i in result["evidence"]["items"] if i["result"] == "fail"]
        self.assertEqual([i["sid"] for i in failed], ["ORGC01"])
        self.assertIn("athena:StartQueryExecution", failed[0]["detail"])
        self.cli(log)
        review = self.review_with_impact()
        self.assertEqual(review["decision"], "blocked")
        self.assertIn(("evidence-impact", "scp-org-guardrails/ORGC01"),
                      {(b["check"], b["subject"]) for b in review["blockers"]})

    def test_too_little_history_is_not_used(self):
        self.cli(normal_activity(days=10))
        review = self.review_with_impact()
        self.assertIn("evidence-impact:scp-org-guardrails/ORGC01", self.doubts(review, "needs acceptance"))
        self.assertTrue(any("less than 30 days" in p for p in review["problems"]))

    def test_a_call_it_cannot_judge_leaves_the_question_with_a_person(self):
        log = normal_activity()
        for r in log["Records"]:
            if r["eventSource"] == "s3.amazonaws.com":
                r.pop("resources")
                r["recipientAccountId"] = None  # the bucket's owner is unknown
        result = self.run_replay(log)
        self.assertNotIn("ORGC02", {i["sid"] for i in result["evidence"]["items"]})
        undetermined = {s["sid"]: s["undetermined"] for s in result["report"]["statements"]}
        self.assertEqual(undetermined["ORGC02"], 40)

    def test_an_outside_bucket_is_impact(self):
        log = normal_activity()
        when = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)
        log["Records"].append(record(when, "s3.amazonaws.com", "PutObject", vpce=None, recipient="999988887777",
                                     resources=[{"ARN": "arn:aws:s3:::someone-elses-bucket/x",
                                                 "accountId": "999988887777"}]))
        failed = {i["sid"] for i in self.run_replay(log)["evidence"]["items"] if i["result"] == "fail"}
        self.assertEqual(failed, {"ORGC02"})

    def test_bad_input_is_refused(self):
        with self.assertRaises(ImpactError):
            load_records(b"[1, 2]")
        with self.assertRaises(ImpactError):
            self.run_replay({"Records": [{"eventSource": "athena.amazonaws.com"}]})


class RunWithCloudTrailTest(unittest.TestCase):
    def test_onboard_run_replays_before_review(self):
        from tests.test_run import REQUEST, load, run_cycle
        from tests.test_assess import ATHENA, CATALOG_SNAPSHOT
        from tests.test_athena_acceptance import SNAPSHOT
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            trail = tmp / "trail.json"
            trail.write_text(json.dumps(normal_activity()))
            with redirect_stdout(io.StringIO()):
                code = main([str(a) for a in ["run", REQUEST, "--out", tmp / "athena", "--snapshot", SNAPSHOT,
                                              "--overlay", ATHENA / "overlay.json", "--control-catalog-snapshot",
                                              CATALOG_SNAPSHOT, "--cloudtrail", trail]])
            self.assertEqual(code, 3)
            log = load(tmp / "athena" / "run.json")
            self.assertIn("impact", [s["stage"] for s in log["stages"]])
            review = load(tmp / "athena" / "review.json")
            self.assertFalse([d for d in review["doubts"] if d["kind"] == "evidence-impact"
                              and d["status"] == "needs acceptance"])


if __name__ == "__main__":
    unittest.main()
