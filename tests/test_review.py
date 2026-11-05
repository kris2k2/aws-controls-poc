"""Review: the release decision on generated policy sets (ADR-0005, ADR-0006).

Runs are built with the real pipeline from the Athena fixtures, Resolve
included, so the reviewer's own run of Verify proves the guardrails. Impact
and calibration evidence here is synthetic (`source: "synthetic: test"`): no
stage produces it yet, so the tests supply it to show what the reviewer does
with it.
"""

import copy
import datetime as dt
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onboard.cli import main
from onboard.request import parse_request
from onboard.review import (
    ACCEPTANCES_SCHEMA, EVALUATOR_SHA256, EVIDENCE_SCHEMA, _Findings, check_policies, deny_statements, load_run,
    review, sha256,
)
from tests.test_athena_acceptance import SNAPSHOT
from tests.test_athena_journey import CATALOG, FIXTURES, load

TODAY = dt.date(2026, 11, 5)
CHECKER = "analyst-b"


def evidence_for(policies, result="pass", calibration=True):
    """Synthetic passing impact evidence for every deny in the policies, and calibration."""
    items = [{"kind": "impact", "policy": name, "sid": stmt["Sid"], "statement_sha256": sha256(stmt),
              "result": result, "source": "synthetic: test", "detail": "test"}
             for name, stmt in deny_statements(policies)]
    if calibration:
        items.append({"kind": "calibration", "evaluator_sha256": EVALUATOR_SHA256, "result": "pass",
                      "source": "synthetic: test"})
    return {"schema": EVIDENCE_SCHEMA, "items": items}


def accept_all(result, by=CHECKER, expires="2027-02-01"):
    """Sign every open doubt in a review's acceptance template."""
    template = copy.deepcopy(result["acceptance_template"])
    for entry in template["acceptances"]:
        entry.update(accepted_by=by, expires=expires, rationale="checked in test")
    return template


class RunCase(unittest.TestCase):
    """Builds Athena runs with the CLI in a temporary directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def build(self, tier="private-preview", name=None, findings=None, **overrides):
        data = load(f"request-{tier}.json")
        data.update(overrides)
        if tier != "private-preview" and "control_registry" not in data:
            pp_request, pp_run = self.build("private-preview", name="pp-base")
            data["control_registry"] = json.loads((pp_run / "registry.json").read_text())
        name = name or tier
        request_path, run = self.tmp / f"{name}.json", self.tmp / name
        request_path.write_text(json.dumps(data))
        findings_path = FIXTURES / "findings.json"
        if findings is not None:
            findings_path = self.tmp / f"{name}-findings.json"
            findings_path.write_text(json.dumps(findings))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["resolve", str(request_path), "--out", str(run), "--snapshot", str(SNAPSHOT)]), 0)
            self.assertEqual(main(["select", str(request_path), "--findings", str(findings_path),
                                   "--out", str(run)]), 0)
            self.assertEqual(main(["generate", str(request_path), "--run", str(run)]), 0)
        return request_path, run

    def review(self, request_path, run, **kwargs):
        request = parse_request(json.loads(request_path.read_text()), today=TODAY)
        files, problems = load_run(run)
        return review(request, files, catalog=CATALOG, load_problems=tuple(problems), today=TODAY, **kwargs)

    def doubts(self, result, status=None):
        return {d["id"]: d for d in result["doubts"] if status is None or d["status"] == status}


class DecisionTest(RunCase):
    def test_the_reviewer_proves_every_deny_itself(self):
        result = self.review(*self.build())
        self.assertEqual(result["decision"], "hold")
        self.assertEqual(result["blockers"], [])
        self.assertEqual(result["problems"], [])
        open_ = self.doubts(result, "needs acceptance")
        self.assertFalse([d for d in open_ if d.startswith("evidence-proof:")], "every deny is proved")
        # What is left about the proofs: the spec they are against isn't signed off, nor are its accepted risks.
        self.assertIn("security-spec:athena", open_)
        self.assertEqual({d for d in open_ if d.startswith("accepted-risk:")},
                         {"accepted-risk:AR-01", "accepted-risk:AR-02", "accepted-risk:AR-03", "accepted-risk:AR-05"})
        # Proofs say nothing about outages: organization-wide denies need impact replays, and they are High.
        self.assertEqual(result["residual_risk"], "High")
        self.assertEqual(open_["evidence-impact:scp-org-guardrails/ORGC01"]["risk"], "High")
        # On a new service nobody uses it yet, so its own denies break nothing running.
        self.assertNotIn("evidence-impact:scp-athena-guardrails/ATHC03", open_)
        self.assertIn("calibration:evaluator", open_)
        self.assertIn("break-glass:principals", open_)
        self.assertEqual(len(result["acceptance_template"]["acceptances"]), len(open_))
        # The numbers in docs/simulations/athena-journey.md, section 6.
        self.assertEqual(result["counts"], {"needs acceptance": 22, "accepted": 0, "auto-accepted": 11})

    def test_without_the_api_contract_nothing_is_proved(self):
        request_path, run = self.build()
        (run / "capability-profile.json").unlink()
        result = self.review(request_path, run)
        self.assertEqual(result["decision"], "hold")
        self.assertIn("evidence-proof:scp-athena-guardrails/ATHC03", self.doubts(result, "needs acceptance"))
        self.assertTrue(any("capability-profile.json is missing" in p for p in result["problems"]))

    def test_outside_proofs_are_ignored(self):
        request_path, run = self.build()
        (run / "capability-profile.json").unlink()
        files, _ = load_run(run)
        fake = {"schema": EVIDENCE_SCHEMA, "items": [
            {"kind": "proof", "statement_sha256": sha256(stmt), "result": "pass", "source": "someone"}
            for _, stmt in deny_statements(files["policies"])]}
        result = self.review(request_path, run, evidence=fake)
        self.assertIn("evidence-proof:scp-athena-guardrails/ATHC03", self.doubts(result, "needs acceptance"))
        self.assertTrue(any("proofs come only from the reviewer's own run of Verify" in p
                            for p in result["problems"]))

    def test_signed_off_specs_and_risks_raise_no_doubt(self):
        from onboard import review as review_module
        real = review_module.verify

        def signed(*args):
            result = real(*args)
            result["spec"]["status"] = "approved"
            for risk in result["accepted_risks"]:
                risk["status"] = "approved"
            return result

        request_path, run = self.build()
        (run / "verification.json").unlink(missing_ok=True)
        with mock.patch.object(review_module, "verify", signed):
            result = self.review(request_path, run)
        kinds = {d["kind"] for d in result["doubts"]}
        self.assertFalse(kinds & {"security-spec", "accepted-risk"})

    def test_low_risk_doubts_are_accepted_by_the_reviewer_at_moderate(self):
        result = self.review(*self.build())
        auto = self.doubts(result, "auto-accepted")
        self.assertIn("inferred-mapping:ORG-C-01", auto)
        self.assertIn("pending-artifacts:detective", auto)
        self.assertTrue(all(d["risk"] == "Low" for d in auto.values()))
        self.assertEqual(result["auto_accept_ceiling"], "Low")

    def test_at_high_criticality_every_doubt_needs_a_person(self):
        result = self.review(*self.build(criticality="High"))
        self.assertIsNone(result["auto_accept_ceiling"])
        self.assertEqual(self.doubts(result, "auto-accepted"), {})
        self.assertIn("inferred-mapping:ORG-C-01", self.doubts(result, "needs acceptance"))

    def test_evidence_and_acceptances_release_the_run(self):
        request_path, run = self.build()
        files, _ = load_run(run)
        evidence = evidence_for(files["policies"])
        first = self.review(request_path, run, evidence=evidence)
        self.assertEqual(first["decision"], "hold")
        # With proofs, impact replays and calibration, what is left is judgement: severities, break-glass,
        # the security spec and its accepted risks.
        self.assertEqual({d["kind"] for d in self.doubts(first, "needs acceptance").values()},
                         {"inferred-severity", "break-glass", "security-spec", "accepted-risk"})
        result = self.review(request_path, run, evidence=evidence, acceptances=accept_all(first))
        self.assertEqual(result["decision"], "release")
        self.assertIsNone(result["residual_risk"])
        self.assertEqual(result["acceptance_template"]["acceptances"], [])
        accepted = self.doubts(result, "accepted")["break-glass:principals"]
        self.assertEqual(accepted["acceptance"]["accepted_by"], CHECKER)
        self.assertEqual(result["policy_set_sha256"], sha256(files["policies"]))


class AcceptanceTest(RunCase):
    def setUp(self):
        super().setUp()
        self.request_path, self.run = self.build()
        self.first = self.review(self.request_path, self.run)

    def test_the_maker_cannot_accept_their_own_run(self):
        result = self.review(self.request_path, self.run, acceptances=accept_all(self.first, by="Analyst-A"))
        self.assertEqual(result["counts"]["accepted"], 0)
        self.assertTrue(any("maker" in p for p in result["problems"]))
        self.assertEqual(result["decision"], "hold")

    def test_an_expired_acceptance_does_not_count(self):
        result = self.review(self.request_path, self.run, acceptances=accept_all(self.first, expires="2026-11-05"))
        self.assertEqual(result["counts"]["accepted"], 0)
        self.assertTrue(any("expired" in p for p in result["problems"]))

    def test_an_incomplete_acceptance_does_not_count(self):
        acceptances = accept_all(self.first)
        acceptances["acceptances"][0]["rationale"] = ""
        result = self.review(self.request_path, self.run, acceptances=acceptances)
        self.assertEqual(result["counts"]["accepted"], len(acceptances["acceptances"]) - 1)

    def test_acceptances_carry_over_until_what_was_accepted_changes(self):
        files, _ = load_run(self.run)
        evidence = evidence_for(files["policies"])
        acceptances = accept_all(self.review(self.request_path, self.run, evidence=evidence))
        # Next run: nothing changed, so it releases with no person involved.
        request2, run2 = self.build(name="pp-again")
        files2, _ = load_run(run2)
        self.assertEqual(self.review(request2, run2, evidence=evidence_for(files2["policies"]),
                                     acceptances=acceptances)["decision"], "release")
        # Then the region policy opens a region. Verify proves the changed statement again on its own;
        # only its impact replay, which nobody has redone, comes back to a person.
        request3, run3 = self.build(name="pp-region", allowed_regions=["ca-central-1", "eu-west-1", "ca-west-1"])
        result = self.review(request3, run3, evidence=evidence, acceptances=acceptances)
        self.assertEqual(result["decision"], "hold")
        self.assertEqual(set(self.doubts(result, "needs acceptance")), {"evidence-impact:scp-org-guardrails/ORGC01"})
        self.assertEqual({e["sid"] for e in result["stale_evidence"]}, {"ORGC01"})


class BlockerTest(RunCase):
    def setUp(self):
        super().setUp()
        self.request_path, self.run = self.build()

    def edit(self, path, change):
        document = json.loads(path.read_text())
        change(document)
        path.write_text(json.dumps(document))

    def assertBlocked(self, result, check, subject=None):
        self.assertEqual(result["decision"], "blocked")
        hits = [b for b in result["blockers"] if b["check"] == check and (subject is None or b["subject"] == subject)]
        self.assertTrue(hits, result["blockers"])

    def test_a_policy_edited_after_generation_is_blocked(self):
        self.edit(self.run / "org-policies" / "scp-athena-guardrails.json",
                  lambda d: d["Statement"][2]["Action"].pop())
        self.assertBlocked(self.review(self.request_path, self.run), "reproducible",
                           "org-policies/scp-athena-guardrails.json")

    def test_a_weakened_control_record_is_blocked_even_when_regenerated(self):
        self.edit(self.run / "controls" / "ATH-C-03.json", lambda d: d["guardrail"]["actions"].pop())
        with redirect_stdout(io.StringIO()):
            main(["generate", str(self.request_path), "--run", str(self.run)])
        self.assertBlocked(self.review(self.request_path, self.run), "reproducible", "controls/ATH-C-03.json")

    def test_an_extra_policy_file_is_blocked(self):
        (self.run / "org-policies" / "scp-extra.json").write_text(json.dumps({"Statement": []}))
        self.assertBlocked(self.review(self.request_path, self.run), "reproducible",
                           "org-policies/scp-extra.json")

    def test_a_missing_artifact_is_blocked(self):
        (self.run / "generation.json").unlink()
        result = self.review(self.request_path, self.run)
        self.assertBlocked(result, "complete")
        self.assertEqual(result["doubts"], [])

    def test_findings_that_weaken_a_guardrail_fail_its_proof_and_cannot_be_accepted(self):
        # A bad Assess: the findings drop a Spark action from ATH-C-03. Select and Generate reproduce it
        # faithfully, so only the proof against the reviewed spec can catch it.
        findings = load("findings.json")
        ath_c_03 = next(c for c in findings["candidates"] if c["control_id"] == "ATH-C-03")
        ath_c_03["guardrail"]["actions"].remove("athena:UpdateNotebook")
        request_path, run = self.build(name="weak", findings=findings)
        first = self.review(request_path, run)
        self.assertBlocked(first, "evidence-proof", "scp-athena-guardrails/ATHC03")
        self.assertNotIn("reproducible", {b["check"] for b in first["blockers"]})
        result = self.review(request_path, run, acceptances=accept_all(first))
        self.assertBlocked(result, "evidence-proof")

    def test_an_edited_verification_report_is_blocked(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify", str(self.request_path), "--run", str(self.run)]), 0)
        self.assertEqual(self.review(self.request_path, self.run)["blockers"], [])
        self.edit(self.run / "verification.json", lambda d: d["proofs"][0].update(detail="looks fine"))
        self.assertBlocked(self.review(self.request_path, self.run), "reproducible", "verification.json")

    def test_a_failed_calibration_blocks(self):
        files, _ = load_run(self.run)
        evidence = evidence_for(files["policies"])
        evidence["items"][-1]["result"] = "fail"
        self.assertBlocked(self.review(self.request_path, self.run, evidence=evidence), "evidence-calibration")


class PolicyCheckTest(unittest.TestCase):
    """The checks on the documents themselves, which back up the reproduction check."""

    CONTROLS = {"ATH-C-03": {"mode": "Enforce"}, "ATH-H-01": {"mode": "Advise"}}
    GENERATION = {"service": "athena", "allow_list_prefixes": ["athena", "s3"]}

    def check(self, policies):
        out = _Findings()
        check_policies(policies, self.GENERATION, self.CONTROLS, out)
        return {(b["check"], b["subject"]) for b in out.blockers}

    def test_only_the_allow_list_and_endpoint_base_allow_may_grant(self):
        allow = {"Sid": "AllowList", "Effect": "Allow", "Resource": "*", "Action": ["athena:*", "s3:*"]}
        self.assertEqual(self.check({"scp-athena-allow": {"Statement": [allow]}}), set())
        wider = dict(allow, Action=["athena:*", "s3:*", "iam:*"])
        self.assertEqual(self.check({"scp-athena-allow": {"Statement": [wider]}}),
                         {("unexpected-allow", "scp-athena-allow/AllowList")})
        self.assertEqual(self.check({"scp-athena-guardrails": {"Statement": [dict(allow, Sid="X")]}}),
                         {("unexpected-allow", "scp-athena-guardrails/X")})

    def test_every_deny_traces_to_an_enforcing_control(self):
        deny = {"Effect": "Deny", "Action": "athena:StartSession", "Resource": "*"}
        self.assertEqual(self.check({"p": {"Statement": [dict(deny, Sid="ATHC03")]}}), set())
        self.assertEqual(self.check({"p": {"Statement": [dict(deny, Sid="ATHC99")]}}), {("traceable", "p/ATHC99")})
        self.assertEqual(self.check({"p": {"Statement": [dict(deny, Sid="ATHH01")]}}), {("traceable", "p/ATHH01")})

    def test_size_and_unresolved_parameters(self):
        deny = {"Sid": "ATHC03", "Effect": "Deny", "Action": ["athena:" + "x" * 5200], "Resource": "*"}
        self.assertIn(("size", "p"), self.check({"p": {"Statement": [deny]}}))
        deny = {"Sid": "ATHC03", "Effect": "Deny", "Action": "*", "Resource": "${protected_roles}"}
        self.assertEqual(self.check({"p": {"Statement": [deny]}}), {("parameters", "p")})


class JourneyReviewTest(RunCase):
    def test_promotion_to_contained_surfaces_what_it_lifts_and_leaves_unenforced(self):
        result = self.review(*self.build("contained"))
        self.assertEqual(result["decision"], "hold")
        open_ = self.doubts(result, "needs acceptance")
        self.assertIn("retired:ATH-C-01", open_)  # the preview-account restriction is lifted
        self.assertIn("trusted-accounts:resource-accounts", open_)
        # Enforce with override and no exception deploys nothing (F11): a person decides if that is acceptable.
        self.assertIn("unenforced:ATH-S-01", open_)
        # On a promotion, Athena's own denies reach workloads running in the preview, so they need impact replays.
        self.assertIn("evidence-impact:scp-athena-guardrails/ATHC03", open_)

    def test_an_exception_is_a_doubt(self):
        exception = {"principal": "arn:aws:iam::111122223333:role/migration", "control_id": "ATH-H-06",
                     "owner": "team-analytics", "expires": "2027-01-31", "rationale": "migration"}
        result = self.review(*self.build("hardened", criticality="High", exceptions=[exception]))
        self.assertIn("exception:ATH-H-06/arn:aws:iam::111122223333:role/migration",
                      self.doubts(result, "needs acceptance"))

    def test_the_cli_writes_the_review_and_exits_by_decision(self):
        request_path, run = self.build()
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["review", str(request_path), "--run", str(run)]), 3)
        result = json.loads((run / "review.json").read_text())
        self.assertEqual(result["decision"], "hold")
        self.assertTrue(out.getvalue().startswith("HOLD"))
        files, _ = load_run(run)
        (run / "evidence.json").write_text(json.dumps(evidence_for(files["policies"])))
        acceptances = accept_all(result)
        acceptances_path = self.tmp / "acceptances.json"
        acceptances_path.write_text(json.dumps(acceptances))
        with redirect_stdout(io.StringIO()):
            # evidence.json in the run is picked up; the old acceptances cover what is left.
            self.assertEqual(main(["review", str(request_path), "--run", str(run),
                                   "--acceptances", str(acceptances_path)]), 0)
            (run / "org-policies" / "scp-athena-allow.json").write_text("{}")
            self.assertEqual(main(["review", str(request_path), "--run", str(run)]), 4)
        self.assertEqual(acceptances["schema"], ACCEPTANCES_SCHEMA)


if __name__ == "__main__":
    unittest.main()
