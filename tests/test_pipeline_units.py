import copy
import json
import unittest
from pathlib import Path

from onboard.catalog import load_index
from onboard.controls import FindingsError, load_findings
from onboard.evaluator import Request, evaluate, statement_applies
from onboard.generate import GenerateError, generate
from onboard.request import parse_request
from onboard.select import SelectError, select

FIXTURES = Path(__file__).parent / "fixtures" / "athena"
CATALOG = load_index()


def athena(name):
    return json.loads((FIXTURES / name).read_text())


def request(**overrides):
    data = athena("request-private-preview.json")
    data.update(overrides)
    return parse_request({k: v for k, v in data.items() if v is not None})


def r(action="athena:GetWorkGroup", **context):
    return Request(action=action, principal_arn="arn:aws:iam::111122223333:role/analyst",
                   principal_account="111122223333", region="ca-central-1", context=context)


def deny(condition=None, **stmt):
    return {"Sid": "T", "Effect": "Deny", "Action": "*", "Resource": "*", **({"Condition": condition} if condition else {}),
            **stmt}


ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


class EvaluatorTest(unittest.TestCase):
    def test_absent_keys(self):
        self.assertTrue(statement_applies(deny({"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}), r()))
        self.assertFalse(statement_applies(deny({"StringEquals": {"aws:SourceVpce": "vpce-1"}}), r()))
        self.assertTrue(statement_applies(deny({"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}}), r()))
        self.assertFalse(statement_applies(deny({"Bool": {"aws:ViaAWSService": "false"}}), r()))
        self.assertTrue(statement_applies(deny({"BoolIfExists": {"aws:ViaAWSService": "false"}}), r()))

    def test_null(self):
        stmt = deny({"Null": {"aws:RequestTag/cost-center": "true"}})
        self.assertTrue(statement_applies(stmt, r()))
        self.assertFalse(statement_applies(stmt, r(**{"aws:RequestTag/cost-center": "cc-1"})))

    def test_conditions_are_anded_and_values_ored(self):
        stmt = deny({"StringNotEquals": {"aws:RequestedRegion": ["ca-central-1", "eu-west-1"]},
                     "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass-*"}})
        self.assertFalse(statement_applies(stmt, r()))
        other = Request("athena:GetWorkGroup", "arn:aws:iam::111122223333:role/analyst", "111122223333", "us-west-2")
        self.assertTrue(statement_applies(stmt, other))

    def test_actions_and_not_actions(self):
        self.assertTrue(statement_applies(deny(Action=["Athena:Get*"]), r("athena:GetWorkGroup")))
        self.assertFalse(statement_applies(deny(Action=["athena:List*"]), r("athena:GetWorkGroup")))
        stmt = {"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}
        self.assertFalse(statement_applies(stmt, r("iam:ListRoles")))
        self.assertTrue(statement_applies(stmt, r("athena:GetWorkGroup")))

    def test_allow_needed_at_every_level(self):
        only_athena = {"Statement": [{"Effect": "Allow", "Action": "athena:*", "Resource": "*"}]}
        self.assertTrue(evaluate(r(), [[ALLOW_ALL], [only_athena]]).allowed)
        decision = evaluate(r("s3:GetObject"), [[ALLOW_ALL], [only_athena]])
        self.assertEqual((decision.allowed, decision.reason), (False, "no SCP allows it at level 1"))

    def test_rcps_apply_only_to_organization_resources(self):
        rcp = {"Statement": [deny(Principal="*")]}
        inside = r("s3:GetObject")
        outside = Request("s3:GetObject", inside.principal_arn, inside.principal_account, inside.region,
                          resource_in_org=False)
        self.assertFalse(evaluate(inside, [[ALLOW_ALL]], [[rcp]]).allowed)
        self.assertTrue(evaluate(outside, [[ALLOW_ALL]], [[rcp]]).allowed)


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.findings = athena("findings.json")

    def problems(self, findings):
        with self.assertRaises(FindingsError) as ctx:
            load_findings(findings)
        return "\n".join(ctx.exception.problems)

    def test_fixture_is_valid(self):
        load_findings(self.findings)

    def test_duplicate_ids(self):
        self.findings["candidates"].append(copy.deepcopy(self.findings["candidates"][0]))
        self.assertIn("is duplicated", self.problems(self.findings))

    def test_guardrail_needs_a_planned_implementation(self):
        cand = next(c for c in self.findings["candidates"] if c["control_id"] == "ATH-C-02")
        cand["implementations"]["scp"] = {"status": "not_expressible", "reason": "x"}
        self.assertIn("scp guardrail but implementations.scp is not planned", self.problems(self.findings))

    def test_unsupported_condition_operator(self):
        cand = next(c for c in self.findings["candidates"] if c["control_id"] == "ATH-C-01")
        cand["guardrail"]["conditions"] = {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}
        self.assertIn("unsupported condition operator NumericLessThan", self.problems(self.findings))

    def test_not_planned_needs_a_reason(self):
        self.findings["candidates"][0]["implementations"]["boundary"] = {"status": "not_applicable"}
        self.assertIn("needs a reason when not planned", self.problems(self.findings))


class SelectTest(unittest.TestCase):
    def setUp(self):
        self.findings = load_findings(athena("findings.json"))

    def test_missing_decision_fails_closed(self):
        with self.assertRaisesRegex(SelectError, "needs the decision 'network_perimeter'"):
            select(self.findings, request(decisions=None), CATALOG)

    def test_decision_can_exclude_a_control(self):
        sel = select(self.findings, request(decisions={"network_perimeter": "not-applicable"}), CATALOG)["selection"]
        self.assertNotIn("ATH-C-04", sel["controls"])
        self.assertEqual(sel["excluded_by_decision"],
                         [{"control_id": "ATH-C-04", "reason": "decision network_perimeter = not-applicable"}])

    def test_registry_keeps_the_higher_mode(self):
        # Another service already needs ORG-S-01 at Enforce for every criticality.
        data = athena("request-hardened.json")
        data["control_registry"] = {"controls": {"ORG-S-01": {
            "mode_by_criticality": {"Low": "Enforce", "Moderate": "Enforce", "High": "Enforce"},
            "services": ["s3"]}}}
        result = select(self.findings, parse_request(data), CATALOG)
        entry = result["registry"]["controls"]["ORG-S-01"]
        self.assertEqual(entry["mode_by_criticality"]["Low"], "Enforce")  # matrix alone says Enforce with override
        self.assertEqual(entry["services"], ["athena", "s3"])
        self.assertIn({"control_id": "ORG-S-01", "change": "reused, mode kept higher"},
                      result["selection"]["registry_changes"])


class GenerateTest(unittest.TestCase):
    def setUp(self):
        self.findings = load_findings(athena("findings.json"))

    def test_missing_parameter_fails_closed(self):
        org = athena("request-private-preview.json")["org_state"]
        org = {k: v for k, v in org.items() if k != "vpc_endpoints"}
        req = request(org_state=org)
        controls = select(self.findings, req, CATALOG)["controls"]
        with self.assertRaisesRegex(GenerateError, "ATH-C-04 needs the parameter 'vpce_ids'"):
            generate(self.findings, controls, req)

    def test_no_break_glass_means_no_exemption(self):
        req = request(break_glass_principals=None)
        controls = select(self.findings, req, CATALOG)["controls"]
        policy = generate(self.findings, controls, req)["policies"]["scp-athena-guardrails"]
        self.assertTrue(all("ArnNotLike" not in s.get("Condition", {}) for s in policy["Statement"]))


if __name__ == "__main__":
    unittest.main()
