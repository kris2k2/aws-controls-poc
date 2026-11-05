"""The initial test case: Amazon Athena through Private Preview, Contained and Hardened.

Each tier runs the built pipeline (request validation, Resolve from the pinned
service reference snapshot, Select, Generate) and checks the outcomes:

- which controls are in scope, their modes, what retires on promotion;
- that the generated guardrails behave as intended, by running request
  vectors through the local evaluator, with at least one positive, one
  negative and (for enforcing modes) one exemption vector per generated
  statement (the spec's coverage rule);
- invariants across promotions: cumulative tiers, no mode ever drops,
  containment always Enforce, a detective platform and a NIST SP 800-53 r5
  mapping for every control, guardrail actions that exist in the API contract.

The candidate controls in tests/fixtures/athena/findings.json are a
hand-written stand-in for Assess; see docs/simulations/athena-journey.md.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard.catalog import load_index
from onboard.cli import main, snapshot_fetcher
from onboard.controls import load_findings
from onboard.evaluator import Request, evaluate
from onboard.generate import MAX_POLICY_CHARS, generate
from onboard.model import Criticality, Mode
from onboard.request import parse_request
from onboard.resolve import resolve
from onboard.select import select
from onboard.service_reference import ServiceReference
from tests.test_athena_acceptance import SNAPSHOT

FIXTURES = Path(__file__).parent / "fixtures" / "athena"
TIERS = ("private-preview", "contained", "hardened")
CATALOG = load_index()  # the pinned NIST SP 800-53 index in catalogs/

PREVIEW = "111122223333"
OTHER = "444455556666"   # an organization account not on the preview list
VPCE = "vpce-0example1111111111"
ORG, OTHER_ORG = "o-exampleorgid", "o-otherorgid"

# What the organization already allows for other services (an existing
# allow-list in org_state), so denies are tested against allowed actions.
BASELINE_ALLOW = {"Version": "2012-10-17", "Statement": [{
    "Sid": "BaselineAllowList", "Effect": "Allow", "Resource": "*",
    "Action": ["iam:*", "sts:*", "cloudtrail:*", "config:*", "organizations:Describe*"]}]}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def req(action, account=PREVIEW, region="ca-central-1", role="analyst", vpce=VPCE, **context):
    ctx = {"aws:ViaAWSService": "false", "aws:PrincipalIsAWSService": "false", "aws:PrincipalOrgID": ORG}
    if vpce:
        ctx["aws:SourceVpce"] = vpce
    ctx.update(context)
    name = "BreakGlass-Responder" if role == "break-glass" else role
    arn = f"arn:aws:iam::{account}:role/{name}"
    return Request(action=action, principal_arn=arn, principal_account=account, region=region, context=ctx)


def run_tier(tier, registry=None, criticality=None, exceptions=None):
    data = load(f"request-{tier}.json")
    if registry is not None:
        data["control_registry"] = registry
    if criticality:
        data["criticality"] = criticality
    if exceptions:
        data["exceptions"] = exceptions
    request = parse_request(data)
    findings = load_findings(load("findings.json"))
    selected = select(findings, request, CATALOG)
    generated = generate(findings, selected["controls"], request)
    return request, selected, generated


def journey(criticality=None):
    """Run the three tiers in order, carrying the registry forward."""
    results, registry = {}, None
    for tier in TIERS:
        results[tier] = run_tier(tier, registry, criticality)
        registry = results[tier][1]["registry"]
    return results


def levels(generated):
    """Root: organization-wide policies; account: the service's policies."""
    p = generated["policies"]
    root = [BASELINE_ALLOW, p["scp-athena-allow"]] + ([p["scp-org-guardrails"]] if "scp-org-guardrails" in p else [])
    account = [BASELINE_ALLOW, p["scp-athena-allow"]] + ([p["scp-athena-guardrails"]] if "scp-athena-guardrails" in p else [])
    rcps = [[p["rcp-org-guardrails"]]] if "rcp-org-guardrails" in p else []
    return [root, account], rcps


class Vectors:
    """Request vectors per control: (control_id, kind, request, allowed, expected Sid or None)."""

    CONTAINMENT = [
        ("ATH-C-01", "positive", req("athena:StartQueryExecution"), True, None),
        ("ATH-C-01", "negative", req("athena:StartQueryExecution", account=OTHER), False, "ATHC01"),
        ("ATH-C-01", "exemption", req("athena:StartQueryExecution", account=OTHER, role="break-glass"), True, None),
        ("ATH-C-02", "positive", req("athena:GetDataCatalog"), True, None),
        ("ATH-C-02", "negative", req("athena:CreateDataCatalog"), False, "ATHC02"),
        ("ATH-C-02", "exemption", req("athena:CreateDataCatalog", account=PREVIEW, role="break-glass"), True, None),
        ("ATH-C-03", "positive", req("athena:StartQueryExecution"), True, None),
        ("ATH-C-03", "negative", req("athena:StartSession"), False, "ATHC03"),
        ("ATH-C-03", "negative", req("athena:CreatePresignedNotebookUrl"), False, "ATHC03"),
        ("ATH-C-03", "exemption", req("athena:StartSession", role="break-glass"), True, None),
        ("ATH-C-04", "positive", req("athena:GetQueryResults"), True, None),
        ("ATH-C-04", "positive", req("athena:GetQueryResults", vpce=None, **{"aws:ViaAWSService": "true"}), True, None),
        ("ATH-C-04", "negative", req("athena:GetQueryResults", vpce=None), False, "ATHC04"),
        ("ATH-C-04", "negative", req("athena:GetQueryResults", vpce="vpce-0attacker000000000"), False, "ATHC04"),
        ("ATH-C-04", "exemption", req("athena:GetQueryResults", vpce=None, role="break-glass"), True, None),
        ("ORG-C-01", "positive", req("athena:StartQueryExecution", region="eu-west-1"), True, None),
        ("ORG-C-01", "positive", req("iam:ListRoles", region="us-east-1"), True, None),
        ("ORG-C-01", "negative", req("athena:StartQueryExecution", region="us-west-2"), False, "ORGC01"),
        ("ORG-C-01", "negative", req("athena:StartQueryExecution", region="us-east-1"), False, "ORGC01"),
        ("ORG-C-01", "exemption", req("athena:StartQueryExecution", region="us-west-2", role="break-glass"), True, None),
        ("ORG-C-02", "positive", req("s3:PutObject", **{"aws:ResourceOrgID": ORG}), True, None),
        ("ORG-C-02", "negative", req("s3:PutObject", **{"aws:ResourceOrgID": OTHER_ORG}), False, "ORGC02"),
        ("ORG-C-02", "exemption", req("s3:PutObject", role="break-glass", **{"aws:ResourceOrgID": OTHER_ORG}), True, None),
        ("ORG-C-03", "positive", req("s3:GetObject", **{"aws:ResourceOrgID": ORG}), True, None),
        ("ORG-C-03", "positive", req("kms:Decrypt", **{"aws:ResourceOrgID": ORG, "aws:PrincipalOrgID": OTHER_ORG,
                                                        "aws:PrincipalIsAWSService": "true"}), True, None),
        ("ORG-C-03", "negative", req("s3:GetObject", **{"aws:ResourceOrgID": ORG, "aws:PrincipalOrgID": OTHER_ORG}),
         False, "ORGC03"),
        ("ORG-C-03", "exemption", req("kms:Decrypt", role="break-glass",
                                      **{"aws:ResourceOrgID": ORG, "aws:PrincipalOrgID": OTHER_ORG}), True, None),
    ]
    # From Contained the preview restriction retires: other organization accounts may use Athena.
    PROMOTION = [("ATH-C-01", "retired", req("athena:StartQueryExecution", account=OTHER), True, None)]
    SUPERVISION = [
        ("ORG-S-01", "positive", req("cloudtrail:LookupEvents"), True, None),
        ("ORG-S-01", "negative", req("cloudtrail:StopLogging"), False, "ORGS01"),
        ("ORG-S-01", "exemption", req("cloudtrail:StopLogging", role="break-glass"), True, None),
        ("ORG-S-02", "positive", req("config:DescribeConfigurationRecorders"), True, None),
        ("ORG-S-02", "negative", req("config:StopConfigurationRecorder"), False, "ORGS02"),
        ("ORG-S-02", "exemption", req("config:StopConfigurationRecorder", role="break-glass"), True, None),
    ]
    UNTAGGED_CREATE = req("athena:CreateWorkGroup")
    TAGGED_CREATE = req("athena:CreateWorkGroup", **{"aws:RequestTag/cost-center": "cc-0001"})


class JourneyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = journey()

    def tier(self, name):
        request, selected, generated = self.results[name]
        return request, selected["selection"], selected["controls"], generated

    def check_vectors(self, tier, vectors):
        _, _, _, generated = self.tier(tier)
        scps, rcps = levels(generated)
        for cid, kind, request, allowed, sid in vectors:
            with self.subTest(tier=tier, control=cid, kind=kind, action=request.action):
                decision = evaluate(request, scps, rcps)
                self.assertEqual(decision.allowed, allowed, decision.reason)
                if sid:
                    self.assertEqual(decision.statement, sid)

    # --- Private Preview -------------------------------------------------------------
    def test_private_preview_scope(self):
        _, sel, controls, _ = self.tier("private-preview")
        self.assertEqual(sel["controls"], ["ATH-C-01", "ATH-C-02", "ATH-C-03", "ATH-C-04",
                                           "ORG-C-01", "ORG-C-02", "ORG-C-03"])
        self.assertEqual({c["mode"] for c in controls.values()}, {"Enforce"})
        self.assertEqual(sel["next_tier"]["tier"], "Contained")
        self.assertEqual(sel["next_tier"]["retires"], ["ATH-C-01"])
        self.assertEqual(len(sel["next_tier"]["adds"]), 8)

    def test_criticality_comes_from_the_internal_restricted_assumption(self):
        for tier in TIERS:
            _, sel, _, _ = self.tier(tier)
            self.assertEqual((sel["data_classification"], sel["criticality"], sel["criticality_source"]),
                             ("Internal Restricted", "Moderate", "default"), tier)

    def test_private_preview_guardrails_hold(self):
        self.check_vectors("private-preview", Vectors.CONTAINMENT)

    def test_private_preview_checker_items(self):
        _, sel, _, _ = self.tier("private-preview")
        items = {(i["control_id"], i["item"]) for i in sel["checker_items"]}
        self.assertIn(("ORG-C-03", "inferred severity Critical"), items)
        self.assertIn(("ATH-C-04", "Enforce on an inferred control"), items)

    # --- Contained -------------------------------------------------------------------
    def test_contained_scope(self):
        _, sel, controls, _ = self.tier("contained")
        self.assertNotIn("ATH-C-01", sel["controls"])
        self.assertEqual(sel["retired"], [{"control_id": "ATH-C-01", "reason": "applies until Private Preview"}])
        self.assertEqual(len(sel["controls"]), 14)
        self.assertEqual(sel["counts"]["class"], {"Containment": 6, "Supervision": 8})
        for cid, rec in controls.items():
            if rec["class"] == "Supervision":
                self.assertIn(rec["mode"], ("Enforce with override", "Enforce"), cid)
        self.assertEqual(controls["ATH-S-03"]["mode"], "Enforce with override")  # Medium, Security Hub
        self.assertEqual(controls["ORG-S-01"]["mode"], "Enforce")                # High

    def test_contained_guardrails_hold(self):
        containment = [v for v in Vectors.CONTAINMENT if v[0] != "ATH-C-01"]
        self.check_vectors("contained", containment + Vectors.PROMOTION + Vectors.SUPERVISION)

    def test_contained_configuration_controls_go_to_config_and_sentinel(self):
        _, _, _, generated = self.tier("contained")
        status = generated["report"]["controls"]["ATH-S-01"]
        self.assertEqual(status["scp"]["status"], "not_expressible")
        self.assertEqual(status["config"]["status"], "pending")
        self.assertEqual(status["sentinel"]["status"], "pending")

    def test_shared_controls_are_reused_from_the_registry(self):
        _, sel, _, _ = self.tier("contained")
        changes = {c["control_id"]: c["change"] for c in sel["registry_changes"]}
        self.assertEqual(changes, {"ORG-C-01": "reused", "ORG-C-02": "reused", "ORG-C-03": "reused",
                                   "ORG-S-01": "added", "ORG-S-02": "added"})

    # --- Hardened --------------------------------------------------------------------
    def test_hardened_scope(self):
        _, sel, controls, _ = self.tier("hardened")
        self.assertEqual(len(sel["controls"]), 20)
        self.assertIsNone(sel["next_tier"])
        self.assertEqual(sel["counts"]["mode"], {"Enforce": 9, "Enforce with override": 5, "Advise": 5, "Report": 1})
        self.assertEqual(controls["ATH-H-01"]["mode"], "Advise")   # Low, Security Hub, Moderate
        self.assertEqual(controls["ATH-H-04"]["mode"], "Report")   # Informational

    def test_hardened_guardrails_hold(self):
        containment = [v for v in Vectors.CONTAINMENT if v[0] != "ATH-C-01"]
        self.check_vectors("hardened", containment + Vectors.PROMOTION + Vectors.SUPERVISION)

    def test_advisory_tag_control_deploys_no_guardrail_at_moderate(self):
        _, _, _, generated = self.tier("hardened")
        self.assertEqual(generated["report"]["controls"]["ATH-H-06"]["scp"]["status"], "not_deployed")
        scps, rcps = levels(generated)
        self.assertTrue(evaluate(Vectors.UNTAGGED_CREATE, scps, rcps).allowed)

    def test_high_criticality_override_path(self):
        # At High criticality the Low tag control is Enforce with override: no guardrail
        # without exceptions, and with one, only the named principal is exempt.
        _, selected, generated = run_tier("hardened", registry=self.results["contained"][1]["registry"],
                                          criticality="High")
        self.assertEqual(selected["controls"]["ATH-H-06"]["mode"], "Enforce with override")
        self.assertEqual(generated["report"]["controls"]["ATH-H-06"]["scp"]["status"], "not_deployed")

        exception = {"principal": f"arn:aws:iam::{PREVIEW}:role/migration", "control_id": "ATH-H-06",
                     "owner": "team-analytics", "expires": "2099-01-31", "rationale": "workgroup migration"}
        _, _, generated = run_tier("hardened", registry=self.results["contained"][1]["registry"],
                                   criticality="High", exceptions=[exception])
        self.assertEqual(generated["report"]["controls"]["ATH-H-06"]["scp"]["status"], "generated")
        scps, rcps = levels(generated)
        denied = evaluate(Vectors.UNTAGGED_CREATE, scps, rcps)
        self.assertEqual((denied.allowed, denied.statement), (False, "ATHH06"))
        self.assertTrue(evaluate(Vectors.TAGGED_CREATE, scps, rcps).allowed)
        self.assertTrue(evaluate(req("athena:CreateWorkGroup", role="migration"), scps, rcps).allowed)

    # --- Across the journey ----------------------------------------------------------
    def test_tiers_are_cumulative(self):
        pp, ct, hd = (set(self.tier(t)[1]["controls"]) for t in TIERS)
        retired = {r["control_id"] for r in self.tier("contained")[1]["retired"]}
        self.assertLessEqual(pp - retired, ct)
        self.assertLessEqual(ct, hd)

    def test_no_mode_ever_drops_on_promotion(self):
        for earlier, later in zip(TIERS, TIERS[1:]):
            before, after = self.tier(earlier)[2], self.tier(later)[2]
            for cid in set(before) & set(after):
                for crit in Criticality:
                    with self.subTest(control=cid, criticality=crit.value, promotion=f"{earlier}->{later}"):
                        self.assertGreaterEqual(Mode(after[cid]["mode_by_criticality"][crit.value]),
                                                Mode(before[cid]["mode_by_criticality"][crit.value]))

    def test_containment_is_enforce_at_every_tier_and_criticality(self):
        for tier in TIERS:
            for cid, rec in self.tier(tier)[2].items():
                if rec["class"] == "Containment":
                    self.assertEqual(set(rec["mode_by_criticality"].values()), {"Enforce"}, f"{tier} {cid}")

    def test_every_control_has_a_detective_platform_and_a_nist_mapping(self):
        for cid, rec in self.tier("hardened")[2].items():
            with self.subTest(control=cid):
                self.assertTrue(rec["detective_platforms"])
                self.assertTrue(any(r["framework"] == "NIST-SP-800-53" and r["version"] == "r5"
                                    for r in rec["framework_refs"]))

    def test_nist_references_resolve_in_the_pinned_catalog(self):
        for tier in TIERS:
            _, sel, controls, _ = self.tier(tier)
            self.assertEqual((sel["nist_catalog"]["version"], sel["nist_catalog"]["source_sha256"]),
                             ("5.2.0", CATALOG["source_sha256"]), tier)
            for cid, rec in controls.items():
                for ref in rec["framework_refs"]:
                    if ref["framework"] == "NIST-SP-800-53":
                        entry = CATALOG["controls"][ref["id"]]
                        self.assertFalse(entry["withdrawn"], f"{tier} {cid} {ref['id']}")
                        self.assertEqual((ref["label"], ref["title"]), (entry["label"], entry["title"]))

    def test_guardrail_athena_actions_exist_in_the_api_contract(self):
        profile = resolve("Amazon Athena", ServiceReference(snapshot_fetcher(SNAPSHOT)))
        known = {a["action"] for a in profile["services"][0]["actions"]}
        for tier in TIERS:
            for name, policy in self.tier(tier)[3]["policies"].items():
                for stmt in policy["Statement"]:
                    for action in stmt.get("Action", []) + stmt.get("NotAction", []):
                        if action.startswith("athena:") and "*" not in action:
                            self.assertIn(action, known, f"{tier} {name} {stmt['Sid']}")

    def test_policies_fit_the_size_limit_and_trace_to_controls(self):
        for tier in TIERS:
            _, _, controls, generated = self.tier(tier)
            sids = {cid.replace("-", "") for cid in controls}
            for name, info in generated["report"]["policies"].items():
                self.assertLessEqual(info["characters"], MAX_POLICY_CHARS, f"{tier} {name}")
            for name, policy in generated["policies"].items():
                for stmt in policy["Statement"]:
                    if stmt["Effect"] == "Deny":
                        self.assertIn(stmt["Sid"], sids, f"{tier} {name}")

    def test_coverage_rule_for_every_generated_guardrail(self):
        vectors = Vectors.CONTAINMENT + Vectors.SUPERVISION
        for tier in TIERS:
            for cid, status in self.tier(tier)[3]["report"]["controls"].items():
                for platform in ("scp", "rcp"):
                    if status[platform]["status"] != "generated":
                        continue
                    kinds = {kind for vid, kind, *_ in vectors if vid == cid}
                    with self.subTest(tier=tier, control=cid, platform=platform):
                        self.assertLessEqual({"positive", "negative", "exemption"}, kinds)

    def test_allow_list_includes_the_dependencies(self):
        self.assertEqual(self.tier("private-preview")[3]["report"]["allow_list_prefixes"],
                         ["athena", "glue", "kms", "s3"])


class JourneyCliTest(unittest.TestCase):
    def test_the_three_tiers_through_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            tmp, registry = Path(tmp), None
            for tier in TIERS:
                data = load(f"request-{tier}.json")
                if registry is not None:
                    data["control_registry"] = registry
                request = tmp / f"{tier}.json"
                request.write_text(json.dumps(data))
                run = tmp / tier
                self.assertEqual(main(["resolve", str(request), "--out", str(run), "--snapshot", str(SNAPSHOT)]), 0)
                self.assertEqual(main(["select", str(request), "--findings", str(FIXTURES / "findings.json"),
                                       "--out", str(run)]), 0)
                self.assertEqual(main(["generate", str(request), "--run", str(run)]), 0)
                registry = json.loads((run / "registry.json").read_text())
            self.assertEqual(len(list((tmp / "hardened" / "controls").glob("*.json"))), 20)
            self.assertTrue((tmp / "hardened" / "org-policies" / "scp-org-guardrails.json").exists())


if __name__ == "__main__":
    unittest.main()
