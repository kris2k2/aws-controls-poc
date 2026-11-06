"""Detective and plan-time artifacts (ADR-0009): Config rules, EventBridge detections, Sentinel policies.

The renderers' output is checked as text; what each artifact means is checked
with the local evaluators (`detective.matches` for EventBridge patterns,
`detective.evaluate` for Guard and Sentinel checks) against synthetic
CloudTrail events, configuration items and Terraform plan values. None of it
has run in AWS Config, EventBridge or Sentinel.
"""

import copy
import json
import unittest

from onboard import detective
from onboard.controls import FindingsError, load_findings
from onboard.detective import evaluate, matches
from onboard.generate import generate
from onboard.select import select
from tests.test_athena_journey import CATALOG, OTHER, PREVIEW, VPCE, journey, load
from tests.test_pipeline_units import request

BREAK_GLASS = [{"wildcard": f"arn:aws:iam::{PREVIEW}:role/BreakGlass-*"},
               {"wildcard": f"arn:aws:iam::{OTHER}:role/BreakGlass-*"}]  # the request's patterns


def event(source, name, account=PREVIEW, region="ca-central-1", error=None, message=None, role="analyst", **fields):
    """A CloudTrail management event as EventBridge delivers its detail."""
    detail = {
        "eventSource": source, "eventName": name, "awsRegion": region, "recipientAccountId": account,
        "userIdentity": {"type": "AssumedRole", "accountId": account, "sessionContext": {
            "sessionIssuer": {"type": "Role", "arn": f"arn:aws:iam::{account}:role/{role}"}}},
        **fields,
    }
    if error:
        detail["errorCode"] = error
    if message:
        detail["errorMessage"] = message
    return detail


def denied(action, policy="service control policy", account=PREVIEW, **fields):
    service, name = action.split(":")
    message = (f"User: arn:aws:sts::{account}:assumed-role/analyst/s is not authorized to perform: {action} "
               f"on resource: * with an explicit deny in a {policy}")
    return event(f"{service}.amazonaws.com", name, account=account, error="AccessDeniedException",
                 message=message, **fields)


def rule_of(generated, cid, kind):
    status = generated["report"]["controls"][cid][kind]
    return status, json.loads(generated["artifacts"][status["file"]]) if status["status"] == "generated" else None


class PatternMatchingTest(unittest.TestCase):
    """The EventBridge filters the detections use, as AWS documents them."""

    def test_values_filters_and_arrays(self):
        self.assertTrue(matches({"a": ["x", "y"]}, {"a": "y"}))
        self.assertFalse(matches({"a": ["x"]}, {"a": "z"}))
        self.assertTrue(matches({"a": ["x"]}, {"a": ["z", "x"]}))  # any element of an event array
        self.assertTrue(matches({"a": [{"prefix": "Access"}]}, {"a": "AccessDenied"}))
        self.assertTrue(matches({"a": [{"wildcard": "*deny in a VPC*"}]}, {"a": "... explicit deny in a VPC endpoint"}))
        self.assertFalse(matches({"a": [{"wildcard": "*deny in a VPC*"}]}, {"a": "denied"}))

    def test_anything_but_needs_the_field(self):
        self.assertTrue(matches({"r": [{"anything-but": ["ca-central-1"]}]}, {"r": "us-east-1"}))
        self.assertFalse(matches({"r": [{"anything-but": ["ca-central-1"]}]}, {"r": "ca-central-1"}))
        self.assertFalse(matches({"r": [{"anything-but": ["ca-central-1"]}]}, {}))
        self.assertFalse(matches({"r": [{"anything-but": {"prefix": "ca-"}}]}, {"r": "ca-west-1"}))

    def test_exists(self):
        self.assertTrue(matches({"v": [{"exists": False}]}, {"other": 1}))
        self.assertFalse(matches({"v": [{"exists": False}]}, {"v": "vpce-1"}))
        self.assertTrue(matches({"v": [{"exists": True}]}, {"v": "vpce-1"}))

    def test_nested_objects_and_or(self):
        pattern = {"$or": [{"a": ["1"]}, {"b": {"c": ["2"]}}]}
        self.assertTrue(matches(pattern, {"b": {"c": "2"}}))
        self.assertTrue(matches(pattern, {"a": "1"}))
        self.assertFalse(matches(pattern, {"b": "2"}))


class CheckEvaluationTest(unittest.TestCase):
    def test_absent_values_fail_except_not_in(self):
        for check in ({"path": ["a"], "exists": True}, {"path": ["a"], "equals": True},
                      {"path": ["a"], "in": ["x"]}, {"path": ["a"], "not_empty": True}):
            self.assertFalse(evaluate([check], {}, "config"), check)
        self.assertTrue(evaluate([{"path": ["a"], "not_in": ["x"]}], {}, "sentinel"))
        self.assertFalse(evaluate([{"path": ["a"], "not_in": ["x"]}], {"a": "x"}, "sentinel"))

    def test_equals_is_typed(self):
        self.assertFalse(evaluate([{"path": ["a"], "equals": True}], {"a": "true"}, "sentinel"))

    def test_tags_have_a_different_shape_per_engine(self):
        check = [{"path": ["Tags"], "has_tag": "cost-center"}]
        self.assertTrue(evaluate(check, {"Tags": [{"Key": "cost-center", "Value": "cc-1"}]}, "config"))
        self.assertFalse(evaluate(check, {"Tags": {"cost-center": "cc-1"}}, "config"))
        self.assertTrue(evaluate(check, {"Tags": {"cost-center": "cc-1"}}, "sentinel"))


class DefinitionValidationTest(unittest.TestCase):
    def setUp(self):
        self.findings = load("findings.json")

    def candidate(self, cid):
        return next(c for c in self.findings["candidates"] if c["control_id"] == cid)

    def assertRejected(self, change, message):
        findings = copy.deepcopy(self.findings)
        self.findings = findings
        change(findings)
        with self.assertRaises(FindingsError) as caught:
            load_findings(findings)
        self.assertTrue(any(message in p for p in caught.exception.problems), caught.exception.problems)

    def test_the_fixture_is_valid(self):
        load_findings(self.findings)

    def test_one_config_source(self):
        self.assertRejected(lambda f: self.candidate("ATH-S-01")["implementations"]["config"].update(
            security_hub_control="Athena.1"), "at most one of managed, guard, security_hub_control")

    def test_the_sentinel_level_comes_from_the_mode(self):
        self.assertRejected(lambda f: self.candidate("ATH-C-02")["implementations"]["sentinel"].update(
            level="advisory"), "derived from the control's mode")

    def test_a_detection_names_its_event_source(self):
        self.assertRejected(lambda f: self.candidate("ATH-C-04")["implementations"]["cloudtrail"]["match"].pop(
            "eventSource"), "must filter on eventSource")

    def test_unknown_filters_and_operations_are_refused(self):
        self.assertRejected(lambda f: self.candidate("ATH-C-04")["implementations"]["cloudtrail"]["match"].update(
            vpcEndpointId=[{"numeric": [">", 0]}]), "filters need exactly one of")
        self.assertRejected(lambda f: self.candidate("ATH-S-05")["implementations"]["config"]["guard"]["checks"]
                            .append({"path": ["X"], "not_in": ["y"]}), "needs exactly one of exists")
        self.assertRejected(lambda f: self.candidate("ATH-S-05")["implementations"]["sentinel"]["plan"]["checks"]
                            .append({"path": ["bad-name"], "exists": True}), "path must be a list of field names")


class RenderingTest(unittest.TestCase):
    RECORD = {"control_id": "ATH-S-05", "title": "Query results location names its expected bucket owner",
              "mode": "Enforce with override", "severity": "Medium"}

    def test_a_guard_rule_on_the_configuration_item(self):
        impl = {"guard": {"resource_type": "AWS::Athena::WorkGroup", "checks": [
            {"path": ["WorkGroupConfiguration", "ResultConfiguration", "ExpectedBucketOwner"], "exists": True},
            {"path": ["State"], "in": ["ENABLED"]}, {"path": ["Tags"], "has_tag": "cost-center"}]}}
        path, text = detective.render_config(self.RECORD, impl)
        self.assertEqual(path, "detective/config-rules/ATH-S-05.json")
        doc = json.loads(text)
        self.assertEqual(doc["mode"], "Enforce with override")
        source = doc["rule"]["Source"]
        self.assertEqual(source["Owner"], "CUSTOM_POLICY")
        self.assertEqual(source["CustomPolicyDetails"]["PolicyRuntime"], "guard-2.x.x")
        self.assertEqual(source["CustomPolicyDetails"]["PolicyText"],
                         "# ATH-S-05: Query results location names its expected bucket owner\n"
                         'rule ath_s_05 when resourceType == "AWS::Athena::WorkGroup" {\n'
                         "    configuration.WorkGroupConfiguration.ResultConfiguration.ExpectedBucketOwner exists\n"
                         '    configuration.State IN ["ENABLED"]\n'
                         '    configuration.Tags[ Key == "cost-center" ] !empty\n'
                         "}\n")
        self.assertEqual(doc["rule"]["Scope"], {"ComplianceResourceTypes": ["AWS::Athena::WorkGroup"]})

    def test_a_sentinel_policy_on_planned_values(self):
        impl = {"plan": {"resource_types": ["aws_athena_workgroup"], "checks": [
            {"path": ["configuration", 0, "result_configuration", 0, "expected_bucket_owner"], "exists": True},
            {"path": ["configuration", 0, "engine_version", 0, "selected_engine_version"],
             "not_in": ["PySpark engine version 3"]}]}}
        path, text, level = detective.render_sentinel(self.RECORD, impl)
        self.assertEqual((path, level), ("detective/sentinel/ath-s-05.sentinel", "soft-mandatory"))
        self.assertIn('import "tfplan/v2" as tfplan', text)
        self.assertIn('rc.type in ["aws_athena_workgroup"] and', text)
        self.assertIn("(rc.change.after.configuration[0].result_configuration[0].expected_bucket_owner else null) "
                      "is not null and\n", text)
        self.assertIn('not in ["PySpark engine version 3"]', text)

    def test_forbid_and_the_policy_set(self):
        record = dict(self.RECORD, control_id="ATH-C-02", mode="Enforce")
        _, text, level = detective.render_sentinel(record, {"plan": {"resource_types": ["aws_athena_data_catalog"],
                                                                     "forbid": True}})
        self.assertIn("main = rule { length(resources) is 0 }", text)
        self.assertEqual(level, "hard-mandatory")
        self.assertEqual(detective.sentinel_config({"ath-c-02.sentinel": level}),
                         'policy "ath-c-02" {\n  source            = "./ath-c-02.sentinel"\n'
                         '  enforcement_level = "hard-mandatory"\n}\n')

    def test_every_mode_has_a_level_and_only_enforce_is_hard(self):
        self.assertEqual([detective.SENTINEL_LEVELS[m] for m in sorted(detective.SENTINEL_LEVELS)],
                         ["advisory", "advisory", "soft-mandatory", "hard-mandatory"])

    def test_a_detection_sees_read_only_calls_and_resolves_parameters(self):
        impl = {"match": {"eventSource": ["athena.amazonaws.com"],
                          "recipientAccountId": [{"anything-but": "${preview_accounts}"}]}}
        path, text = detective.render_detection(self.RECORD, impl, {"preview_accounts": [PREVIEW]})
        rule = json.loads(text)["rule"]
        self.assertEqual(rule["State"], "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS")
        self.assertEqual(rule["EventPattern"]["detail-type"], ["AWS API Call via CloudTrail"])
        self.assertEqual(rule["EventPattern"]["detail"]["recipientAccountId"], [{"anything-but": [PREVIEW]}])
        with self.assertRaisesRegex(detective.DetectiveError, "needs the parameter 'preview_accounts'"):
            detective.render_detection(self.RECORD, impl, {})
        with self.assertRaisesRegex(detective.DetectiveError, "can't take"):
            detective.render_detection(self.RECORD, impl, {"preview_accounts": ["1111*"]})

    def test_patterns_in_parameters_become_wildcards(self):
        impl = {"match": {"eventSource": [{"exists": True}], "userIdentity": {"arn": ["${bg}"]}}}
        _, text = detective.render_detection(self.RECORD, impl, {"bg": ["arn:aws:iam::111122223333:role/BG-*",
                                                                        "arn:aws:iam::111122223333:role/x"]})
        self.assertEqual(json.loads(text)["rule"]["EventPattern"]["detail"]["userIdentity"]["arn"],
                         [{"wildcard": "arn:aws:iam::111122223333:role/BG-*"}, "arn:aws:iam::111122223333:role/x"])
        with self.assertRaisesRegex(detective.DetectiveError, "uses \\?"):
            detective.render_detection(self.RECORD, impl, {"bg": ["arn:aws:iam::111122223333:role/BG-?"]})

    def test_an_empty_optional_parameter_drops_its_branch(self):
        impl = {"match": {"$or": [{"eventSource": ["athena.amazonaws.com"], "errorCode": ["AccessDenied"]},
                                  {"eventSource": [{"exists": True}], "userIdentity": {"arn": ["${bg}"]}}]},
                "optional_parameters": ["bg"]}
        _, text = detective.render_detection(self.RECORD, impl, {"bg": []})
        self.assertEqual(json.loads(text)["rule"]["EventPattern"]["detail"],
                         {"eventSource": ["athena.amazonaws.com"], "errorCode": ["AccessDenied"]})
        impl["match"] = impl["match"]["$or"][1]
        self.assertIsNone(detective.render_detection(self.RECORD, impl, {"bg": []}))


class AthenaArtifactsTest(unittest.TestCase):
    """The Athena journey's artifacts mean what the controls ask for."""

    @classmethod
    def setUpClass(cls):
        cls.results = journey()

    def generated(self, tier):
        return self.results[tier][2]

    def detection(self, tier, cid):
        status, doc = rule_of(self.generated(tier), cid, "cloudtrail")
        self.assertEqual(status["status"], "generated", status)
        return doc["rule"]["EventPattern"]

    def assertDetects(self, pattern, events, expected):
        for e in events:
            with self.subTest(event=e["eventName"], expected=expected):
                self.assertEqual(matches(pattern, e), expected)

    def check(self, tier, cid, positives, negatives):
        pattern = self.detection(tier, cid)
        self.assertDetects(pattern["detail"], positives, True)
        self.assertDetects(pattern["detail"], negatives, False)

    def test_detections_catch_what_the_guardrails_deny(self):
        self.check("hardened", "ORG-C-01",
                   [event("athena.amazonaws.com", "StartQueryExecution", region="us-east-1")],
                   [event("athena.amazonaws.com", "StartQueryExecution"),
                    event("iam.amazonaws.com", "CreateRole", region="us-east-1")])
        self.check("hardened", "ORG-C-04",
                   [event("iam.amazonaws.com", "UpdateAssumeRolePolicy", region="us-east-1",
                          requestParameters={"roleName": "BreakGlass-Responder"})],
                   [event("iam.amazonaws.com", "UpdateAssumeRolePolicy", region="us-east-1",
                          requestParameters={"roleName": "analytics-etl"})])
        self.check("hardened", "ATH-C-03", [denied("athena:StartSession")], [event("athena.amazonaws.com",
                                                                                   "StartQueryExecution")])
        self.check("hardened", "ATH-C-04", [event("athena.amazonaws.com", "StartQueryExecution")],
                   [event("athena.amazonaws.com", "StartQueryExecution", vpcEndpointId=VPCE)])
        self.check("hardened", "ORG-C-05", [denied("s3:GetObject", policy="VPC endpoint policy")],
                   [denied("s3:GetObject")])
        self.check("private-preview", "ATH-C-01", [event("athena.amazonaws.com", "ListWorkGroups", account=OTHER)],
                   [event("athena.amazonaws.com", "ListWorkGroups")])
        self.check("hardened", "ATH-H-06", [denied("athena:CreateWorkGroup")],
                   [event("athena.amazonaws.com", "CreateWorkGroup")])

    def test_supervision_sees_denials_and_break_glass_use(self):
        self.check("hardened", "ATH-S-06",
                   [denied("athena:StartSession"),
                    event("s3.amazonaws.com", "GetObject", role="BreakGlass-Responder")],
                   [event("athena.amazonaws.com", "StartQueryExecution"),
                    denied("athena:StartSession", policy="resource control policy")])
        branch = self.detection("hardened", "ATH-S-06")["detail"]["$or"][1]
        self.assertEqual(branch["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"], BREAK_GLASS)

    def test_every_action_a_guardrail_names_is_an_event_its_detection_watches(self):
        # A deny list and its detection drift apart unless they are compared (finding F13).
        generated = self.generated("hardened")
        controls = self.results["hardened"][1]["controls"]
        compared = []
        for cid, record in sorted(controls.items()):
            status = generated["report"]["controls"][cid]["cloudtrail"]
            if "guardrail" not in record or "actions" not in record["guardrail"] or status["status"] != "generated":
                continue
            names = json.loads(generated["artifacts"][status["file"]])["rule"]["EventPattern"]["detail"].get(
                "eventName")
            if names is None:
                continue  # the detection watches every call from the service
            actions = {a.split(":", 1)[1] for a in record["guardrail"]["actions"]} - {"PassRole"}  # not an API call
            with self.subTest(control=cid):
                self.assertLessEqual(actions, set(names))
            compared.append(cid)
        self.assertEqual(compared, ["ATH-C-02", "ATH-C-03", "ATH-H-06", "ORG-C-04", "ORG-C-07", "ORG-C-08", "ORG-S-01",
                                    "ORG-S-02"])

    def test_config_rules_and_sentinel_policies_judge_workgroups(self):
        generated = self.generated("hardened")
        hardened_ci = {"Name": "analytics", "Description": "Analytics team queries", "Tags": [
            {"Key": "cost-center", "Value": "cc-0001"}], "WorkGroupConfiguration": {
            "BytesScannedCutoffPerQuery": 10737418240, "EnforceWorkGroupConfiguration": True,
            "ResultConfiguration": {"ExpectedBucketOwner": PREVIEW, "EncryptionConfiguration": {
                "EncryptionOption": "SSE_KMS", "KmsKey": f"arn:aws:kms:ca-central-1:{PREVIEW}:key/example"}}}}
        hardened_plan = {"name": "analytics", "description": "Analytics team queries",
                         "tags": {"cost-center": "cc-0001"}, "configuration": [{
                             "bytes_scanned_cutoff_per_query": 10737418240, "enforce_workgroup_configuration": True,
                             "publish_cloudwatch_metrics_enabled": True,
                             "engine_version": [{"selected_engine_version": "AUTO"}],
                             "result_configuration": [{"expected_bucket_owner": PREVIEW, "encryption_configuration": [
                                 {"encryption_option": "SSE_KMS",
                                  "kms_key_arn": f"arn:aws:kms:ca-central-1:{PREVIEW}:key/example"}]}]}]}
        defaults = ({"Name": "primary"}, {"name": "primary"})
        guard, plan = [], []
        for cid, record in sorted(self.results["hardened"][1]["controls"].items()):
            impl = record["implementations"]
            if impl["config"].get("guard", {}).get("resource_type") == "AWS::Athena::WorkGroup":
                guard.append(cid)
                checks = impl["config"]["guard"]["checks"]
                self.assertTrue(evaluate(checks, hardened_ci, "config"), cid)
                self.assertFalse(evaluate(checks, defaults[0], "config"), cid)
            if impl["sentinel"].get("plan", {}).get("resource_types") == ["aws_athena_workgroup"]:
                plan.append(cid)
                checks = impl["sentinel"]["plan"]["checks"]
                self.assertTrue(evaluate(checks, hardened_plan, "sentinel"), cid)
                if cid != "ATH-C-03":  # the default engine isn't Spark, so a default workgroup passes ATH-C-03
                    self.assertFalse(evaluate(checks, defaults[1], "sentinel"), cid)
            self.assertTrue(generated["report"]["controls"][cid]["config"]["status"] != "pending"
                            or "guard" not in impl["config"])
        self.assertEqual(guard, ["ATH-H-05", "ATH-H-06", "ATH-S-02", "ATH-S-05"])
        self.assertEqual(plan, ["ATH-C-03", "ATH-H-01", "ATH-H-03", "ATH-H-04", "ATH-H-05", "ATH-H-06",
                                "ATH-S-01", "ATH-S-02", "ATH-S-03", "ATH-S-05"])
        spark = copy.deepcopy(hardened_plan)
        spark["configuration"][0]["engine_version"][0]["selected_engine_version"] = "PySpark engine version 3"
        checks = self.results["hardened"][1]["controls"]["ATH-C-03"]["implementations"]["sentinel"]["plan"]["checks"]
        self.assertFalse(evaluate(checks, spark, "sentinel"))

    def test_sentinel_levels_follow_the_mode(self):
        hcl = self.generated("hardened")["artifacts"]["detective/sentinel/sentinel.hcl"]
        levels = {}
        for block in hcl.strip().split("\n\n"):
            name = block.split('"')[1]
            levels[name] = block.rsplit('"', 2)[1]
        self.assertEqual(levels["ath-c-02"], "hard-mandatory")   # Enforce
        self.assertEqual(levels["ath-s-01"], "soft-mandatory")   # Enforce with override
        self.assertEqual(levels["ath-h-03"], "advisory")         # Advise
        self.assertEqual(levels["ath-h-04"], "advisory")         # Report

    def test_what_stays_pending_says_why(self):
        report = self.generated("hardened")["report"]["controls"]
        pending = sorted((cid, p) for cid, statuses in report.items() for p, s in statuses.items()
                         if s["status"] == "pending")
        self.assertEqual(pending, [
            ("ATH-S-04", "config"), ("ORG-C-01", "config"), ("ORG-C-01", "sentinel"), ("ORG-C-03", "config"),
            ("ORG-C-04", "sentinel"), ("ORG-C-05", "config"), ("ORG-C-05", "sentinel"), ("ORG-C-06", "config"),
            ("ORG-C-06", "sentinel"),
        ])
        self.assertEqual(report["ORG-C-01"]["config"]["reason"],
                         "no structured config definition in the control record yet")

    def test_artifacts_are_listed_with_their_hashes(self):
        generated = self.generated("hardened")
        self.assertEqual(sorted(generated["artifacts"]), sorted(generated["report"]["detective_artifacts"]))
        self.assertIn("detective/sentinel/sentinel.hcl", generated["artifacts"])
        self.assertTrue(generated["report"]["detective_notes"])


class ParameterTest(unittest.TestCase):
    def setUp(self):
        self.findings = load_findings(load("findings.json"))

    def test_no_protected_roles_means_no_role_detection(self):
        req = request(break_glass_principals=None)
        result = generate(self.findings, select(self.findings, req, CATALOG)["controls"], req)
        self.assertEqual(result["report"]["controls"]["ORG-C-04"]["cloudtrail"],
                         {"status": "not_deployed", "reason": "protected_role_names is empty, so there is nothing "
                                                              "to detect"})
        self.assertNotIn("detective/eventbridge/ORG-C-04.json", result["artifacts"])

    def test_exception_roles_are_watched_by_name(self):
        exception = {"principal": "arn:aws:iam::111122223333:role/team/migration", "control_id": "ATH-C-02",
                     "owner": "team-a", "expires": "2099-01-31", "rationale": "migration"}
        req = request(exceptions=[exception])
        result = generate(self.findings, select(self.findings, req, CATALOG)["controls"], req)
        rule = json.loads(result["artifacts"]["detective/eventbridge/ORG-C-04.json"])["rule"]
        self.assertIn("migration", rule["EventPattern"]["detail"]["requestParameters"]["roleName"])


if __name__ == "__main__":
    unittest.main()
