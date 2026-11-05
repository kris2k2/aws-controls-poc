"""Verify: each generated guardrail proved against its security property (ADR-0006).

The proofs themselves are the adversarial suite's (`tests/test_athena_adversarial.py`);
these tests check that the Verify stage runs them on a run's files, reports
what it finds, and fails on every way a proof can be missing or wrong.
"""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onboard.cli import main
from onboard.controls import load_findings
from onboard.verify import VerifyError, sha256, verify
from tests.test_athena_acceptance import SNAPSHOT
from tests.test_athena_adversarial import CONTRACT, EXCEPTION
from tests.test_athena_journey import FIXTURES, load, run_tier

FINDINGS = load_findings(load("findings.json"))


def runs():
    """Each tier in order, plus High criticality with an exception (the override path)."""
    out, registry, registries = {}, None, {}
    for tier in ("private-preview", "contained", "hardened"):
        out[tier] = run_tier(tier, registry)
        registry = registries[tier] = out[tier][1]["registry"]
    out["hardened-high-exception"] = run_tier("hardened", registries["contained"], criticality="High",
                                              exceptions=[EXCEPTION])
    return out


RUNS = runs()


def run_verify(name="hardened", policies=None, controls=None, contract=CONTRACT, findings=FINDINGS):
    request, selected, generated = RUNS[name]
    return verify(request, findings, controls or selected["controls"], policies or generated["policies"], contract)


def edit_statement(name, sid, change):
    policies = copy.deepcopy(RUNS[name][2]["policies"])
    for doc in policies.values():
        for stmt in doc["Statement"]:
            if stmt.get("Sid") == sid:
                change(stmt)
    return policies


def proof(result, sid):
    return next(p for p in result["proofs"] if p["sid"] == sid)


class VerifyTest(unittest.TestCase):
    def test_every_statement_of_every_run_is_proved(self):
        for name, (request, selected, generated) in RUNS.items():
            result = run_verify(name)
            denies = {s["Sid"] for doc in generated["policies"].values() for s in doc["Statement"]
                      if s["Effect"] == "Deny"}
            with self.subTest(run=name):
                self.assertEqual(result["result"], "pass", [p["detail"] for p in result["proofs"]])
                self.assertEqual(result["failures"], [])
                self.assertEqual({p["sid"] for p in result["proofs"]}, denies)
                self.assertEqual(result["policy_set_sha256"], sha256(generated["policies"]))
                for p in result["proofs"]:
                    self.assertEqual(p["mutants"]["survived"], [])
                    self.assertEqual(p["mutants"]["caught"] + p["mutants"]["equivalent"], p["mutants"]["total"])
                    self.assertGreater(p["mutants"]["caught"], 0)
        # The exception's statement is proved with the exception exempt.
        self.assertEqual(proof(run_verify("hardened-high-exception"), "ATHH06")["result"], "pass")

    def test_proofs_bind_to_the_exact_statement(self):
        result = run_verify("private-preview")
        stmt = next(s for s in RUNS["private-preview"][2]["policies"]["scp-athena-guardrails"]["Statement"]
                    if s["Sid"] == "ATHC03")
        self.assertEqual(proof(result, "ATHC03")["statement_sha256"], sha256(stmt))

    def test_accepted_risks_apply_where_their_controls_are_preventive(self):
        ids = lambda name: [r["id"] for r in run_verify(name)["accepted_risks"]]  # noqa: E731
        self.assertEqual(ids("private-preview"), ["AR-01", "AR-02", "AR-03", "AR-05"])
        self.assertEqual(ids("contained"), ["AR-01", "AR-02", "AR-03", "AR-04", "AR-05"])

    def test_the_spec_is_reported_unsigned(self):
        spec = run_verify()["spec"]
        self.assertEqual(spec["service"], "athena")
        self.assertTrue(spec["status"].startswith("proposed"))
        self.assertRegex(spec["sha256"], r"^[0-9a-f]{64}$")

    def test_a_result_is_not_shared_with_the_caller(self):
        first = run_verify()
        first["proofs"].clear()
        self.assertTrue(run_verify()["proofs"])


class VerifyFailureTest(unittest.TestCase):
    def test_a_narrowed_statement_fails_with_a_counterexample(self):
        policies = edit_statement("hardened", "ATHC03", lambda s: s["Action"].remove("athena:UpdateNotebook"))
        p = proof(run_verify(policies=policies), "ATHC03")
        self.assertEqual(p["result"], "fail")
        self.assertIn("athena:UpdateNotebook", p["detail"])

    def test_a_widened_exemption_fails(self):
        def widen(stmt):
            stmt["Condition"]["ArnNotLike"]["aws:PrincipalArn"] = "arn:aws:iam::*:role/BreakGlass-*"
        p = proof(run_verify(policies=edit_statement("hardened", "ORGC01", widen)), "ORGC01")
        self.assertEqual(p["result"], "fail")

    def test_a_statement_reading_a_key_outside_the_model_fails(self):
        def add_key(stmt):
            stmt.setdefault("Condition", {}).setdefault("StringEquals", {})["aws:SourceIp"] = "192.0.2.1"
        p = proof(run_verify(policies=edit_statement("hardened", "ATHC02", add_key)), "ATHC02")
        self.assertEqual(p["result"], "fail")
        self.assertIn("aws:SourceIp, which the attacker model doesn't vary", p["detail"])

    def test_a_statement_in_the_wrong_kind_of_policy_fails(self):
        policies = copy.deepcopy(RUNS["hardened"][2]["policies"])
        stmt = next(s for s in policies["scp-athena-guardrails"]["Statement"] if s["Sid"] == "ATHC03")
        policies["scp-athena-guardrails"]["Statement"].remove(stmt)
        policies["rcp-org-guardrails"]["Statement"].append(stmt)
        p = proof(run_verify(policies=policies), "ATHC03")
        self.assertEqual(p["result"], "fail")
        self.assertIn("enforceable only with a scp policy", p["detail"])

    def test_a_surviving_mutant_fails_the_proof(self):
        # Clear the cache for the patched run, and restore it after: results from patched code mustn't leak.
        with mock.patch.dict("onboard.verify._CACHE", clear=True), \
                mock.patch("onboard.verify.mutants", lambda stmt: iter([("change nothing", copy.deepcopy(stmt))])):
            p = proof(run_verify(), "ATHC03")
        self.assertEqual(p["result"], "fail")
        self.assertEqual(p["mutants"]["survived"], ["change nothing"])

    def test_a_missing_statement_fails(self):
        policies = copy.deepcopy(RUNS["hardened"][2]["policies"])
        policies["scp-athena-guardrails"]["Statement"] = [
            s for s in policies["scp-athena-guardrails"]["Statement"] if s["Sid"] != "ATHC03"]
        result = run_verify(policies=policies)
        self.assertEqual(result["result"], "fail")
        self.assertIn("ATH-C-03 must be preventive in this run, but no statement was generated for it",
                      result["failures"])

    def test_a_deny_for_a_control_that_is_not_preventive_fails(self):
        policies = copy.deepcopy(RUNS["hardened"][2]["policies"])
        policies["scp-athena-guardrails"]["Statement"].append(
            {"Sid": "ATHH01", "Effect": "Deny", "Action": "athena:CreateWorkGroup", "Resource": "*"})
        result = run_verify(policies=policies)
        self.assertTrue(any("ATHH01 deploys a deny for ATH-H-01" in f for f in result["failures"]))

    def test_a_guardrail_without_a_property_fails(self):
        request, selected, generated = RUNS["hardened"]
        controls = copy.deepcopy(selected["controls"])
        policies = copy.deepcopy(generated["policies"])
        controls["ATH-C-09"] = dict(controls["ATH-C-02"], control_id="ATH-C-09")
        stmt = dict(next(s for s in policies["scp-athena-guardrails"]["Statement"] if s["Sid"] == "ATHC02"),
                    Sid="ATHC09")
        policies["scp-athena-guardrails"]["Statement"].append(stmt)
        p = proof(run_verify(controls=controls, policies=policies), "ATHC09")
        self.assertEqual(p["result"], "fail")
        self.assertIn("states no property for ATH-C-09", p["detail"])

    def test_an_unreviewed_contract_action_fails_the_capability_controls(self):
        result = run_verify(contract=CONTRACT + ["athena:StartSparkThing"])
        self.assertEqual(result["unclassified_actions"], ["StartSparkThing"])
        failed = {p["control_id"] for p in result["proofs"] if p["result"] == "fail"}
        self.assertEqual(failed, {"ATH-C-02", "ATH-C-03"})

    def test_a_service_without_a_spec_cannot_be_verified(self):
        findings = dict(FINDINGS, service="bedrock")
        with self.assertRaisesRegex(VerifyError, "no security spec for 'bedrock'"):
            run_verify(findings=findings)


class VerifyCliTest(unittest.TestCase):
    def test_verify_writes_the_report_and_exits_by_result(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as out:
            tmp = Path(tmp)
            request, run = FIXTURES / "request-private-preview.json", tmp / "run"
            self.assertEqual(main(["select", str(request), "--findings", str(FIXTURES / "findings.json"),
                                   "--out", str(run)]), 0)
            self.assertEqual(main(["generate", str(request), "--run", str(run)]), 0)
            # Without Resolve's contract there is nothing to prove against.
            self.assertEqual(main(["verify", str(request), "--run", str(run)]), 2)
            self.assertEqual(main(["resolve", str(request), "--out", str(run), "--snapshot", str(SNAPSHOT)]), 0)
            self.assertEqual(main(["verify", str(request), "--run", str(run)]), 0)
            report = json.loads((run / "verification.json").read_text())
            self.assertEqual(report["result"], "pass")
            self.assertEqual(len(report["proofs"]), 10)
            self.assertIn("PASS: 10 of 10 statements proved", out.getvalue())
            policy = run / "org-policies" / "scp-athena-guardrails.json"
            doc = json.loads(policy.read_text())
            doc["Statement"][2]["Action"].remove("athena:UpdateNotebook")
            policy.write_text(json.dumps(doc))
            self.assertEqual(main(["verify", str(request), "--run", str(run)]), 4)


if __name__ == "__main__":
    unittest.main()
