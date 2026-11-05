"""Compose (ADR-0011): placement, budgets and the diff against org_state, on the Athena journey."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard.cli import main
from onboard.compose import ROOT, ComposeError, Organization, compose
from onboard.evaluator import evaluate
from onboard.request import parse_request
from tests.test_athena_journey import BASELINE_ALLOW, FIXTURES, OTHER, PREVIEW, journey, load, req

# What the policies org_state lists without documents mean, for the evaluator.
EXISTING = {
    "scp-baseline-allow": BASELINE_ALLOW,
    "scp-sagemaker-allow": {"Statement": [{"Effect": "Allow", "Action": "sagemaker:*", "Resource": "*"}]},
    "scp-sagemaker-guardrails": {"Statement": [{"Effect": "Deny", "Action": "sagemaker:CreatePresignedDomainUrl",
                                                "Resource": "*"}]},
}


def account_levels(composition, org_state, policies, account):
    """The SCPs attached at each level from the root to `account` once the composition is applied."""
    org = Organization(org_state)
    attached = {name: set(p["targets"]) for name, p in org.policies.items() if p["type"] == "scp"}
    for d in composition["diff"]["attachments"]:
        if composition["placements"].get(d["policy"], {}).get("type", "scp") == "scp":
            targets = attached.setdefault(d["policy"], set())
            (targets.add if d["change"] == "attach" else targets.discard)(d["target"])
    docs = {**EXISTING, **policies}
    return [[docs[n] for n, targets in sorted(attached.items()) if node in targets] for node in org.path_to(account)]


class ComposeJourneyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = journey()
        cls.composed = {tier: compose(r, g["report"], g["policies"]) for tier, (r, _, g) in cls.results.items()}

    def test_private_preview_places_the_service_on_its_preview_account(self):
        c = self.composed["private-preview"]
        self.assertEqual((c["strategy"], c["result"]), ("allow-list", "fits"))
        self.assertEqual(c["placements"]["scp-athena-allow"]["targets"],
                         [ROOT, "Sandbox", "Sandbox/Preview", PREVIEW])  # every level, root first
        self.assertEqual(c["placements"]["scp-athena-guardrails"]["targets"], [PREVIEW])
        self.assertEqual(c["placements"]["scp-org-guardrails"]["targets"], [ROOT])
        self.assertEqual(c["placements"]["rcp-org-guardrails"]["targets"], [ROOT])
        self.assertEqual(c["endpoints"]["vpce-org-guardrails"], ["vpce-0example1111111111", "vpce-0example2222222222"])
        self.assertEqual({d["change"] for d in c["diff"]["policies"]}, {"create"})
        self.assertEqual(c["removes_service_from"], [])

    def test_the_placement_means_what_scps_do(self):
        # Athena works in the preview account only: elsewhere no level path allows it.
        request, _, generated = self.results["private-preview"]
        c, org_state = self.composed["private-preview"], request.org_state
        for account, allowed in ((PREVIEW, True), (OTHER, False)):
            levels = account_levels(c, org_state, generated["policies"], account)
            decision = evaluate(req("athena:StartQueryExecution", account=account), levels)
            self.assertEqual(decision.allowed, allowed, (account, decision.reason))
        # The organization's guardrails hold everywhere, the sandbox included.
        levels = account_levels(c, org_state, generated["policies"], PREVIEW)
        self.assertFalse(evaluate(req("athena:StartQueryExecution", region="us-west-2"), levels).allowed)

    def test_promotion_moves_the_service_and_says_what_it_removes(self):
        c = self.composed["contained"]
        self.assertEqual(c["placements"]["scp-athena-allow"]["targets"],
                         [ROOT, "Workloads", "Workloads/Analytics", OTHER])  # and every account in the OU
        self.assertEqual(c["placements"]["scp-athena-guardrails"]["targets"], ["Workloads/Analytics"])
        moves = {(a["policy"], a["target"], a["change"]) for a in c["diff"]["attachments"]}
        self.assertLessEqual({("scp-athena-guardrails", PREVIEW, "detach"), ("scp-athena-allow", OTHER, "attach"),
                              ("scp-athena-guardrails", "Workloads/Analytics", "attach"),
                              ("scp-athena-allow", "Workloads", "attach")}, moves)
        self.assertNotIn(("scp-athena-allow", ROOT, "attach"), moves)  # already there
        # Guardrails go on first and come off last.
        order = [(a["policy"], a["change"]) for a in c["diff"]["attachments"]]
        self.assertEqual(order[0], ("scp-athena-guardrails", "attach"))
        self.assertEqual(order[-1], ("scp-athena-guardrails", "detach"))
        self.assertEqual([a["step"] for a in c["diff"]["attachments"]], list(range(1, len(order) + 1)))
        self.assertEqual(c["removes_service_from"], [PREVIEW, "Sandbox", "Sandbox/Preview"])
        self.assertEqual({d["change"] for d in c["diff"]["policies"]}, {"update"})
        request, _, generated = self.results["contained"]
        levels = account_levels(c, request.org_state, generated["policies"], OTHER)
        self.assertTrue(evaluate(req("athena:StartQueryExecution", account=OTHER), levels).allowed)

    def test_budgets_count_every_service_and_rcp_full_access(self):
        budgets = {(b["target"], b["type"]): b for b in self.composed["contained"]["budgets"]}
        analytics = budgets[("Workloads/Analytics", "scp")]
        self.assertEqual(analytics["policies"], ["scp-athena-allow", "scp-athena-guardrails", "scp-baseline-allow",
                                                 "scp-sagemaker-allow", "scp-sagemaker-guardrails"])
        self.assertEqual((analytics["attached"], analytics["limit"]), (5, 10))
        self.assertEqual(budgets[(ROOT, "rcp")]["policies"], ["RCPFullAWSAccess", "rcp-org-guardrails"])

    def test_detective_artifacts_are_scoped(self):
        artifacts = self.composed["hardened"]["artifacts"]
        self.assertEqual(artifacts["detective/eventbridge/ORG-C-04.json"]["scope"], [ROOT])
        self.assertEqual(artifacts["detective/eventbridge/ATH-C-03.json"]["scope"], ["Workloads/Analytics"])
        self.assertEqual(artifacts["detective/eventbridge/ATH-C-03.json"]["regions"], "every enabled Region")
        self.assertEqual(artifacts["detective/config-rules/ATH-S-02.json"]["regions"],
                         list(self.results["hardened"][0].allowed_regions))
        self.assertIn("Terraform", artifacts["detective/sentinel/ath-c-02.sentinel"]["scope"])


class ComposeRulesTest(unittest.TestCase):
    def tier(self, tier="contained", **org_changes):
        data = load(f"request-{tier}.json")
        org = data["org_state"]
        for key, change in org_changes.items():
            change(org) if callable(change) else org.__setitem__(key, change)
        registry = journey()["private-preview"][1]["registry"] if tier != "private-preview" else None
        if registry:
            data["control_registry"] = registry
        request = parse_request(data)
        _, _, generated = self._generate(request)
        return request, generated, compose(request, generated["report"], generated["policies"])

    def _generate(self, request):
        from onboard.controls import load_findings
        from onboard.generate import generate
        from onboard.select import select
        from tests.test_athena_journey import CATALOG
        findings = load_findings(load("findings.json"))
        selected = select(findings, request, CATALOG)
        return request, selected, generate(findings, selected["controls"], request)

    def test_a_deny_list_organization_takes_the_service_denies_on_the_root(self):
        def full_access(org):
            org["policies"].append({"name": "FullAWSAccess", "type": "scp",
                                    "targets": [ROOT, "Workloads", "Workloads/Analytics"]})
        _, _, c = self.tier(org=full_access)
        self.assertEqual(c["strategy"], "deny-list")
        self.assertEqual(c["placements"]["scp-athena-guardrails"]["targets"], [ROOT])
        self.assertEqual(c["placements"]["scp-athena-allow"]["targets"], [])
        self.assertIn("scp-athena-allow", {a["policy"] for a in c["diff"]["attachments"] if a["change"] == "detach"})

    def test_a_full_target_is_over_budget(self):
        def crowd(org):
            for i in range(6):
                org["policies"].append({"name": f"scp-other{i}-guardrails", "type": "scp", "sha256": "a" * 64,
                                        "targets": ["Workloads/Analytics"]})
        _, _, c = self.tier(org=crowd)
        self.assertEqual(c["result"], "over-budget")
        self.assertIn("Workloads/Analytics would have 11 SCPs attached, over the quota of 10", c["problems"][0])

    def test_rcps_run_out_first(self):
        def crowd(org):
            for i in range(4):
                org["policies"].append({"name": f"rcp-other{i}", "type": "rcp", "sha256": "b" * 64, "targets": [ROOT]})
        _, _, c = self.tier(org=crowd)
        self.assertEqual(c["result"], "over-budget")  # 4 + rcp-org-guardrails + RCPFullAWSAccess = 6
        self.assertTrue(any("6 RCPs" in p for p in c["problems"]))

    def test_a_policy_it_no_longer_produces_is_deleted(self):
        def legacy(org):
            org["policies"].append({"name": "scp-athena-legacy", "type": "scp", "sha256": "c" * 64,
                                    "targets": ["Workloads/Analytics"]})
        _, _, c = self.tier(org=legacy)
        self.assertIn({"name": "scp-athena-legacy", "change": "delete"}, c["diff"]["policies"])
        self.assertIn(("scp-athena-legacy", "Workloads/Analytics", "detach"),
                      {(a["policy"], a["target"], a["change"]) for a in c["diff"]["attachments"]})

    def test_targets_must_exist(self):
        with self.assertRaisesRegex(ComposeError, "target_scope Workloads/Missing"):
            data = load("request-contained.json")
            data["control_registry"] = journey()["private-preview"][1]["registry"]
            data["target_scope"] = ["Workloads/Missing"]
            request = parse_request(data)
            compose(request, {"service": "athena"}, {})
        with self.assertRaisesRegex(ComposeError, "preview accounts 999988887777"):
            data = load("request-private-preview.json")
            data["preview_accounts"] = ["999988887777"]
            compose(parse_request(data), {"service": "athena"}, {})

    def test_org_state_is_validated(self):
        org = load("request-contained.json")["org_state"]
        for change, message in (
            (lambda o: o["ous"].insert(0, {"path": "Orphan/Child"}), "parent Orphan must be listed before it"),
            (lambda o: o["ous"].extend({"path": "/".join("abcdef"[:i + 1])} for i in range(6)), "deeper than 5"),
            (lambda o: o["policies"][0]["targets"].append("Nowhere"), "target 'Nowhere'"),
            (lambda o: o["policies"][0].pop("sha256"), "needs its document or sha256"),
            (lambda o: o["policies"].append(copy.deepcopy(o["policies"][0])), "listed twice"),
            (lambda o: o["accounts"].append({"id": "12345", "ou": ROOT}), "12-digit"),
        ):
            broken = copy.deepcopy(org)
            change(broken)
            with self.assertRaisesRegex(ComposeError, message):
                Organization(broken)


class ComposeCliTest(unittest.TestCase):
    def test_compose_writes_composition_and_gates_on_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp, request = Path(tmp), FIXTURES / "request-private-preview.json"
            run = tmp / "run"
            with redirect_stdout(io.StringIO()):
                main(["select", str(request), "--findings", str(FIXTURES / "findings.json"), "--out", str(run)])
                main(["generate", str(request), "--run", str(run)])
                self.assertEqual(main(["compose", str(request), "--run", str(run)]), 0)
            self.assertEqual(json.loads((run / "composition.json").read_text())["result"], "fits")
            crowded = load("request-private-preview.json")
            crowded["org_state"]["policies"] += [{"name": f"rcp-x{i}", "type": "rcp", "sha256": "d" * 64,
                                                  "targets": [ROOT]} for i in range(4)]
            (tmp / "crowded.json").write_text(json.dumps(crowded))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["compose", str(tmp / "crowded.json"), "--run", str(run)]), 4)


if __name__ == "__main__":
    unittest.main()
