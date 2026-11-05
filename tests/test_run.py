"""The whole cycle (`onboard run`) and delivery (ADR-0008), on Athena at Private Preview.

Offline: the service reference and Control Catalog snapshots, and the
analyst overlay from tests/fixtures/athena/.
"""

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onboard.cli import main
from onboard.deliver import DeliverError, check_delivery, deliver
from tests.test_assess import ATHENA, CATALOG_SNAPSHOT, load
from tests.test_athena_acceptance import SNAPSHOT

REQUEST = ATHENA / "request-private-preview.json"


def onboard(*argv):
    with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
        return main([str(a) for a in argv])


def run_cycle(out, request=REQUEST, overlay=ATHENA / "overlay.json", acceptances=None):
    argv = ["run", request, "--out", out, "--snapshot", SNAPSHOT, "--overlay", overlay,
            "--control-catalog-snapshot", CATALOG_SNAPSHOT]
    return onboard(*argv, *(["--acceptances", acceptances] if acceptances else []))


def accept(review_path, out, by="analyst-b"):
    template = load(review_path)["acceptance_template"]
    for entry in template["acceptances"]:
        entry.update(accepted_by=by, expires="2099-01-01", rationale="checked in test")
    out.write_text(json.dumps(template))
    return out


class RunTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.run_dir = tmp / "athena"
        cls.first = run_cycle(cls.run_dir)
        cls.held = load(cls.run_dir / "run.json")
        cls.held_report = (cls.run_dir / "report.html").read_text(encoding="utf-8")
        cls.acceptances = accept(cls.run_dir / "review.json", tmp / "acceptances.json")
        cls.second = run_cycle(cls.run_dir, acceptances=cls.acceptances)
        cls.bundle = cls.run_dir / "delivery"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_a_first_run_holds_on_the_doubts_and_delivers_nothing(self):
        self.assertEqual(self.first, 3)
        self.assertEqual(self.held["result"], "hold")
        self.assertEqual([s["stage"] for s in self.held["stages"]],
                         ["resolve", "assess", "select", "generate", "verify", "compose", "review and deliver"])

    def test_with_the_checker_s_acceptances_it_delivers(self):
        self.assertEqual(self.second, 0)
        log = load(self.run_dir / "run.json")
        self.assertEqual((log["result"], log["service"]), ("delivered", "athena"))
        self.assertEqual(check_delivery(self.bundle), [])
        self.assertEqual(onboard("check-delivery", self.bundle), 0)

    def test_the_bundle_holds_exactly_the_reviewed_policies(self):
        manifest = load(self.bundle / "manifest.json")
        review = load(self.bundle / "review.json")
        self.assertEqual(manifest["decision"], "release")
        self.assertEqual(manifest["policy_set_sha256"], review["policy_set_sha256"])
        released = sorted(p.name for p in (self.bundle / "policies").iterdir())
        self.assertEqual(released, sorted(p.name for p in (self.run_dir / "org-policies").iterdir()))
        for name in released:
            self.assertEqual((self.bundle / "policies" / name).read_bytes(),
                             (self.run_dir / "org-policies" / name).read_bytes())
        self.assertEqual((self.bundle / "acceptances.json").read_bytes(), self.acceptances.read_bytes())
        self.assertEqual((self.bundle / "request.json").read_bytes(), REQUEST.read_bytes())
        self.assertEqual(manifest["composition_sha256"], review["composition_sha256"])
        for evidence in ("verification.json", "selection.json", "findings.json", "assessment.json", "composition.json"):
            self.assertTrue((self.bundle / evidence).is_file(), evidence)

    def test_every_outcome_gets_a_report_and_the_bundle_seals_it(self):
        self.assertEqual(self.held["report"], "report.html")  # the first run held, and still has one
        self.assertIn("On hold", self.held_report)
        bundled = (self.bundle / "report.html").read_bytes()
        self.assertEqual(bundled, (self.run_dir / "report.html").read_bytes())
        self.assertIn(b"Released", bundled)
        self.assertIn("report.html", load(self.bundle / "manifest.json")["files"])
        self.assertEqual(check_delivery(self.bundle), [])

    def test_the_bundle_holds_exactly_the_reviewed_detective_artifacts(self):
        manifest, review = load(self.bundle / "manifest.json"), load(self.bundle / "review.json")
        in_run = {p.relative_to(self.run_dir).as_posix(): p.read_bytes()
                  for p in (self.run_dir / "detective").rglob("*") if p.is_file()}
        self.assertTrue(in_run)
        self.assertEqual(sorted(manifest["artifacts"]), sorted(in_run))
        self.assertEqual(manifest["artifacts"], review["artifacts"])
        for path, raw in in_run.items():
            self.assertEqual((self.bundle / path).read_bytes(), raw, path)

    def test_a_changed_or_added_file_breaks_the_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            for change in ("edit", "add", "remove", "edit-detection", "add-detection"):
                with self.subTest(change=change):
                    copy = Path(tmp) / change
                    shutil.copytree(self.bundle, copy)
                    policy = copy / "policies" / "scp-org-guardrails.json"
                    detection = copy / "detective" / "eventbridge" / "ATH-C-03.json"
                    if change == "edit-detection":
                        doc = load(detection)
                        doc["rule"]["EventPattern"]["detail"]["eventName"].pop()
                        detection.write_text(json.dumps(doc))
                    elif change == "add-detection":
                        (detection.parent / "ATH-X-01.json").write_text("{}")
                    elif change == "edit":
                        doc = load(policy)
                        doc["Statement"].pop()
                        policy.write_text(json.dumps(doc))
                    elif change == "add":
                        (copy / "policies" / "scp-extra.json").write_text("{}")
                    else:
                        policy.unlink()
                    self.assertNotEqual(check_delivery(copy), [])
                    self.assertEqual(onboard("check-delivery", copy), 4)


class DeliverGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.run_dir = self.dir / "athena"
        self.assertEqual(run_cycle(self.run_dir), 3)
        self.acceptances = accept(self.run_dir / "review.json", self.dir / "acceptances.json")

    def tearDown(self):
        self.tmp.cleanup()

    def deliver_cli(self, *extra):
        return onboard("deliver", REQUEST, "--run", self.run_dir, *extra)

    def test_a_forged_release_in_the_run_is_not_trusted(self):
        review = load(self.run_dir / "review.json")
        review.update(decision="release", blockers=[], doubts=[])
        (self.run_dir / "review.json").write_text(json.dumps(review))
        self.assertEqual(self.deliver_cli(), 3)
        self.assertFalse((self.run_dir / "delivery").exists())

    def test_a_policy_edited_after_review_is_blocked(self):
        policy = self.run_dir / "org-policies" / "scp-athena-guardrails.json"
        doc = load(policy)
        doc["Statement"].pop()
        policy.write_text(json.dumps(doc))
        self.assertEqual(self.deliver_cli("--acceptances", self.acceptances), 4)
        self.assertFalse((self.run_dir / "delivery").exists())

    def test_a_detection_edited_after_review_is_blocked(self):
        detection = self.run_dir / "detective" / "eventbridge" / "ATH-C-03.json"
        detection.write_text(detection.read_text().replace("StartSession", "StartSessionX"))
        self.assertEqual(self.deliver_cli("--acceptances", self.acceptances), 4)
        self.assertFalse((self.run_dir / "delivery").exists())

    def test_the_maker_cannot_accept_their_own_doubts(self):
        own = accept(self.run_dir / "review.json", self.dir / "own.json", by="analyst-a")
        self.assertEqual(self.deliver_cli("--acceptances", own), 3)

    def test_deliver_refuses_a_review_that_does_not_match_the_files(self):
        self.assertEqual(self.deliver_cli("--acceptances", self.acceptances), 0)
        review = load(self.run_dir / "review.json")
        with self.assertRaises(DeliverError):  # not a release
            deliver({**review, "decision": "hold"}, self.run_dir, self.dir / "b1", request_bytes=b"{}")
        with self.assertRaises(DeliverError):  # the policy set changed since the review
            deliver({**review, "policy_set_sha256": "0" * 64}, self.run_dir, self.dir / "b2", request_bytes=b"{}")
        with self.assertRaisesRegex(DeliverError, "detective artifacts"):  # an artifact changed since the review
            deliver({**review, "artifacts": {**review["artifacts"], "detective/eventbridge/ATH-C-03.json": "0" * 64}},
                    self.run_dir, self.dir / "b3", request_bytes=b"{}")
        with self.assertRaises(DeliverError):  # never over an existing bundle
            deliver(review, self.run_dir, self.run_dir / "delivery", request_bytes=b"{}")
        self.assertFalse((self.dir / "b1").exists() or (self.dir / "b2.partial").exists())


class RunFailureTest(unittest.TestCase):
    def test_a_weak_overlay_stops_the_run_at_verify(self):
        overlay = load(ATHENA / "overlay.json")
        for c in overlay["candidates"]:
            if c["control_id"] == "ATH-C-03":
                c["guardrail"]["actions"] = c["guardrail"]["actions"][1:]  # drop a Spark action
        with tempfile.TemporaryDirectory() as tmp:
            weak = Path(tmp) / "overlay.json"
            weak.write_text(json.dumps(overlay))
            self.assertEqual(run_cycle(Path(tmp) / "athena", overlay=weak), 4)
            log = load(Path(tmp) / "athena" / "run.json")
            self.assertEqual((log["result"], log["stages"][-1]["stage"]), ("failed", "verify"))
            self.assertFalse((Path(tmp) / "athena" / "review.json").exists())

    def test_a_directory_it_did_not_write_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            keep = Path(tmp) / "notes.txt"
            keep.write_text("not a run")
            self.assertEqual(run_cycle(Path(tmp)), 2)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["notes.txt"])

    def test_a_stage_error_is_logged_and_stops_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = {**load(ATHENA / "overlay.json"), "service": "bedrock"}
            bad = Path(tmp) / "overlay.json"
            bad.write_text(json.dumps(other))
            self.assertEqual(run_cycle(Path(tmp) / "athena", overlay=bad), 2)
            log = load(Path(tmp) / "athena" / "run.json")
            self.assertEqual((log["result"], log["stages"][-1]["stage"]), ("failed", "assess"))
            self.assertIn("bedrock", log["stages"][-1]["error"])


if __name__ == "__main__":
    unittest.main()
