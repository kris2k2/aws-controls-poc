"""Adversarial tests for the generated Athena guardrails.

Layers (see `onboard/adversary.py` for the method and its limits):
1. The security spec, `onboard/specs/`: what each control must deny.
2. The attacker model, `onboard.adversary.Space`: what an attacker can vary.
3. Bounded proof: each generated statement denies exactly what its property denies.
4. Completeness against the API contract: every Athena action is reviewed.
5. Exemption hygiene: no exemption an attacker can match or create.
6. Mutation testing: every way of breaking a statement is caught.
7. Accepted risks: the gaps left open on purpose stay exactly that wide.
Plus a catalogue of named attacks, end to end through every policy.

Layers 3 and 6 are what the Verify stage runs on every run (`onboard/verify.py`);
the tests run them here directly, and check the Verify stage gives the same
answers in `tests/test_verify.py`. Layers 5 and 7 and the named attacks need a
test organization (an existing allow-list), so they stay here.
"""

import unittest

from onboard import adversary
from onboard.adversary import (ANONYMOUS, EXTERNAL_ACCOUNT, ORG_ACCOUNT_ON_NO_LIST, STANDALONE_ACCOUNT, Facts, Space,
                               role)
from onboard.cli import snapshot_fetcher
from onboard.controls import load_findings
from onboard.resolve import resolve
from onboard.service_reference import ServiceReference
from onboard.specs import load_spec
from onboard.specs.organization import ROLE_CHANGES
from onboard.verify import active_controls
from tests.test_athena_journey import BASELINE_ALLOW, ORG, OTHER, PREVIEW, SNAPSHOT, load, run_tier

SPEC = load_spec("athena")
BY_CONTROL = SPEC.by_control
ACTION_REVIEW = SPEC.action_review
ACCEPTED_RISKS = SPEC.accepted_risks

EXCEPTION_ROLE = f"arn:aws:iam::{PREVIEW}:role/migration"
EXCEPTION = {"principal": EXCEPTION_ROLE, "control_id": "ATH-H-06", "owner": "team-analytics",
             "expires": "2099-01-31", "rationale": "workgroup migration"}


def _contract() -> list[str]:
    profile = resolve("Amazon Athena", ServiceReference(snapshot_fetcher(SNAPSHOT)))
    return sorted(a["action"] for a in profile["services"][0]["actions"])


CONTRACT = _contract()
FINDINGS = load_findings(load("findings.json"))


class Scenario:
    """One generated run, with the facts and attacker model for its request."""

    def __init__(self, name, request, selected, generated):
        self.name, self.request, self.generated = name, request, generated
        self.controls = selected["controls"]
        self.facts = Facts.of(request, FINDINGS)
        self.space = Space(self.facts, CONTRACT)
        self.statements = {}  # control id -> (policy type, statement)
        for policy_name, policy in generated["policies"].items():
            for stmt in policy["Statement"]:
                if stmt["Effect"] == "Deny":
                    self.statements[stmt["Sid"]] = (policy_name.split("-")[0], stmt)
        self.allow = generated["policies"][f"scp-{FINDINGS['service']}-allow"]["Statement"][0]
        self.endpoint = [p for n, p in generated["policies"].items() if n.startswith("vpce-")]
        self.endpoint_allow = next((s for p in self.endpoint for s in p["Statement"] if s["Effect"] == "Allow"), None)

    def active(self):
        """Controls that must be preventive here, with the exceptions that apply to each."""
        return active_controls(self.request, self.controls)

    def statement(self, cid):
        return self.statements.get(cid.replace("-", ""), (None, None))

    def levels(self):
        p = self.generated["policies"]
        root = [BASELINE_ALLOW, p["scp-athena-allow"]] + [p[n] for n in ("scp-org-guardrails",) if n in p]
        account = [BASELINE_ALLOW, p["scp-athena-allow"]] + [p[n] for n in ("scp-athena-guardrails",) if n in p]
        return [root, account], [[p[n]] for n in ("rcp-org-guardrails",) if n in p]

    def decide(self, **overrides):
        point = adversary.default_point(self.facts, **overrides)
        scps, rcps = self.levels()
        return adversary.decide(point, self.facts, scps, rcps, self.endpoint)


def build_scenarios():
    out, registries, registry = {}, {}, None
    for tier in ("private-preview", "contained", "hardened"):
        request, selected, generated = run_tier(tier, registry)
        out[tier] = Scenario(tier, request, selected, generated)
        registry = registries[tier] = selected["registry"]
    # At High criticality the tag control is Enforce with override; one exception deploys it.
    request, selected, generated = run_tier("hardened", registries["contained"], criticality="High",
                                            exceptions=[EXCEPTION])
    out["hardened-high-exception"] = Scenario("hardened-high-exception", request, selected, generated)
    return out


class AdversarialTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = build_scenarios()


# --- Layer 1: the spec covers every preventive control -------------------------------
class SpecTest(AdversarialTestCase):
    def test_every_guardrail_in_the_findings_has_a_property(self):
        with_guardrail = {c["control_id"] for c in FINDINGS["candidates"] if "guardrail" in c}
        self.assertEqual(with_guardrail, set(BY_CONTROL))

    def test_each_property_names_the_policy_type_that_can_enforce_it(self):
        for c in FINDINGS["candidates"]:
            if "guardrail" in c:
                with self.subTest(control=c["control_id"]):
                    prop = BY_CONTROL[c["control_id"]]
                    self.assertEqual(c["guardrail"]["type"], adversary.POLICY_TYPE[prop.constrains])


# --- Layer 3: bounded proof, statement by statement ----------------------------------
class BoundedProofTest(AdversarialTestCase):
    def test_every_generated_statement_has_an_active_property(self):
        for name, sc in self.scenarios.items():
            active = {cid.replace("-", "") for cid in sc.active()}
            with self.subTest(scenario=name):
                self.assertLessEqual(set(sc.statements), active)

    def test_each_statement_denies_exactly_what_its_property_denies(self):
        for name, sc in self.scenarios.items():
            for cid, exceptions in sorted(sc.active().items()):
                gtype, stmt = sc.statement(cid)
                prop = BY_CONTROL[cid]
                with self.subTest(scenario=name, control=cid):
                    if stmt is not None:
                        self.assertEqual(gtype, adversary.POLICY_TYPE[prop.constrains])
                    found = adversary.counterexamples(stmt, prop, sc.space, exceptions)
                    self.assertEqual(found, [], f"{cid}: {prop.title}")

    def test_the_allow_list_opens_exactly_the_service_and_its_dependencies(self):
        for name, sc in self.scenarios.items():
            with self.subTest(scenario=name):
                self.assertEqual(adversary.allow_list_counterexamples(sc.allow, sc.space), [])

    def test_the_endpoint_policy_allows_everything_its_guardrails_do_not_deny(self):
        for name, sc in self.scenarios.items():
            with self.subTest(scenario=name):
                self.assertIsNotNone(sc.endpoint_allow, "no endpoint policy generated")
                self.assertEqual(adversary.endpoint_allow_counterexamples(sc.endpoint_allow, sc.space), [])

    def test_a_property_cannot_read_what_it_does_not_declare(self):
        sneaky = adversary.Property("ATH-C-04", "reads vpce undeclared", adversary.CONSTRAINS_PRINCIPALS,
                                    actions=("athena:*",), deny_when=lambda r, f: r.vpce is None)
        sc = self.scenarios["hardened"]
        with self.assertRaisesRegex(adversary.ModelError, "reads 'vpce' without declaring it"):
            adversary.counterexamples(sc.statement("ATH-C-04")[1], sneaky, sc.space)

    def test_a_statement_reading_a_key_outside_the_model_fails(self):
        stmt = {"Sid": "X", "Effect": "Deny", "Action": "athena:*", "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceIp": "192.0.2.1"}}}
        sc = self.scenarios["hardened"]
        with self.assertRaisesRegex(adversary.ModelError, "aws:SourceIp, which the attacker model doesn't vary"):
            adversary.counterexamples(stmt, BY_CONTROL["ATH-C-04"], sc.space)


# --- Layer 4: completeness against the API contract ---------------------------------
class ContractCompletenessTest(unittest.TestCase):
    def test_every_contract_action_has_been_reviewed(self):
        reviewed = {f"athena:{a}" for a in ACTION_REVIEW["actions"]}
        self.assertEqual(sorted(set(CONTRACT) - reviewed), [], "new actions in the contract: review them")
        self.assertEqual(sorted(reviewed - set(CONTRACT)), [], "actions gone from the contract: update the review")

    def test_every_capability_action_is_denied_or_allowed_with_a_reason(self):
        names = [a.split(":", 1)[1] for a in CONTRACT]
        for cid, cap in ACTION_REVIEW["capabilities"].items():
            with self.subTest(control=cid):
                deny, allow = set(cap["deny"]), set(cap["allow"])
                self.assertFalse(deny & allow)
                self.assertLessEqual(deny | allow, set(names))
                self.assertTrue(all(reason.strip() for reason in cap["allow"].values()))
                matched = {n for n in names if any(adversary.matches(m, n) for m in cap["match"])}
                self.assertEqual(sorted(matched - deny - allow), [], f"unclassified {cap['capability']} actions")

    def test_capability_guardrails_deny_the_reviewed_actions(self):
        guardrails = {c["control_id"]: c["guardrail"] for c in FINDINGS["candidates"] if "guardrail" in c}
        for cid, cap in ACTION_REVIEW["capabilities"].items():
            with self.subTest(control=cid):
                self.assertEqual(sorted(guardrails[cid]["actions"]), sorted(f"athena:{a}" for a in cap["deny"]))


# --- Layer 5: exemption hygiene -----------------------------------------------------
class ExemptionHygieneTest(AdversarialTestCase):
    def exempt_patterns(self, sc):
        for _, stmt in sc.statements.values():
            arns = stmt.get("Condition", {}).get("ArnNotLike", {}).get("aws:PrincipalArn", [])
            for arn in adversary._list(arns):
                yield stmt["Sid"], arn

    def test_exemptions_name_a_concrete_account_and_a_role(self):
        for name, sc in self.scenarios.items():
            for sid, arn in self.exempt_patterns(sc):
                with self.subTest(scenario=name, sid=sid, pattern=arn):
                    parts = arn.split(":", 5)
                    self.assertEqual(parts[:4], ["arn", "aws", "iam", ""])
                    self.assertRegex(parts[4], r"^\d{12}$")
                    self.assertRegex(parts[5], r"^role/[A-Za-z0-9_+=,.@/-]+\*?$")

    def test_every_exempt_role_is_protected_from_everyone_else(self):
        for name, sc in self.scenarios.items():
            patterns = {arn for _, arn in self.exempt_patterns(sc)}
            if not patterns:
                continue
            _, protect = sc.statement("ORG-C-04")
            with self.subTest(scenario=name):
                self.assertIsNotNone(protect, "exemptions are generated but ORG-C-04 is not")
            for pattern in sorted(patterns):
                for resource in adversary.sample(pattern):
                    for action in ROLE_CHANGES:
                        attacker = role(_account_of(pattern), "analyst", ORG)
                        decision = sc.decide(principal=attacker, action=action, resource=resource)
                        with self.subTest(scenario=name, resource=resource, action=action):
                            self.assertEqual((decision.allowed, decision.statement), (False, "ORGC04"))

    def test_exception_principals_are_protected_too(self):
        sc = self.scenarios["hardened-high-exception"]
        self.assertIn(EXCEPTION_ROLE, sc.facts.protected_roles)
        decision = sc.decide(principal=role(PREVIEW, "analyst", ORG), action="iam:UpdateAssumeRolePolicy",
                             resource=EXCEPTION_ROLE)
        self.assertEqual((decision.allowed, decision.statement), (False, "ORGC04"))


def _account_of(arn):
    return arn.split(":")[4]


# --- Layer 6: mutation testing ------------------------------------------------------
# Mutants that change nothing the model can observe are listed in the spec
# (EQUIVALENT_MUTANTS) with the reason. Each must keep surviving: if one starts
# being caught, or stops occurring, drop it there.


class MutationTest(AdversarialTestCase):
    def test_every_mutant_of_every_statement_is_caught(self):
        total, seen, caught = 0, set(), set()
        for name, sc in self.scenarios.items():
            for cid, exceptions in sorted(sc.active().items()):
                _, stmt = sc.statement(cid)
                if stmt is None:
                    continue
                for description, mutant in adversary.mutants(stmt):
                    total += 1
                    found = adversary.counterexamples(mutant, BY_CONTROL[cid], sc.space, exceptions, limit=1)
                    key = SPEC.equivalent(cid, description, sc.facts)
                    if key:
                        seen.add(key)
                        caught.update([(key, name, description)] if found else [])
                        continue
                    with self.subTest(scenario=name, control=cid, mutant=description):
                        self.assertTrue(found, "survived: the tests would not notice this bug")
        self.assertGreater(total, 150)  # the operators really ran
        self.assertEqual(seen, set(SPEC.equivalent_mutants), "a listed equivalent mutant no longer occurs: drop it")
        self.assertEqual(caught, set(), "a listed equivalent mutant is caught now: drop it")

    def test_every_endpoint_allow_mutant_is_caught(self):
        sc = self.scenarios["hardened"]
        self.assertIsNotNone(sc.endpoint_allow, "no endpoint policy generated")
        for description, mutant in adversary.endpoint_allow_mutants(sc.endpoint_allow, ORG):
            with self.subTest(mutant=description):
                self.assertTrue(adversary.endpoint_allow_counterexamples(mutant, sc.space, limit=1))

    def test_every_allow_list_mutant_is_caught(self):
        sc = self.scenarios["hardened"]
        for description, mutant in adversary.allow_list_mutants(sc.allow):
            with self.subTest(mutant=description):
                self.assertTrue(adversary.allow_list_counterexamples(mutant, sc.space, limit=1))


# --- Layer 7: accepted risks --------------------------------------------------------
# The register is in the spec (onboard/specs/). Each risk is pinned here, in the
# test organization: per tier, a request that must stay allowed, and boundary
# requests (overrides on adversary.default_point, Sid) that must stay denied.
RISK_PINS = {
    "AR-01": (("private-preview", "contained", "hardened"),
              {"action": "athena:StartQueryExecution", "vpce": None, "via": True},
              (({"action": "s3:PutObject", "vpce": None, "via": True, "resource_org": adversary.OTHER_ORG}, "ORGC02"),
               ({"principal": "external", "action": "s3:GetObject", "vpce": None, "via": True}, "ORGC03"))),
    "AR-02": (("private-preview", "contained", "hardened"),
              {"action": "athena:CreateWorkGroup", "tag": "cc-0001"},
              (({"action": "athena:StartSession"}, "ATHC03"),
               ({"action": "athena:StartCalculationExecution"}, "ATHC03"))),
    # The test organization's allow-list opens IAM, STS and Organizations reads, not CloudFront or Route 53.
    "AR-03": (("private-preview", "contained", "hardened"),
              {"action": "iam:ListRoles", "region": "us-west-2"},
              (({"action": "athena:StartQueryExecution", "region": "us-west-2"}, "ORGC01"),)),
    "AR-04": (("contained", "hardened"),
              {"action": "cloudtrail:StopLogging", "principal": "break-glass"},
              (({"action": "s3:PutObject", "principal": "break-glass", "resource_org": adversary.OTHER_ORG},
                "ORGC02"),)),
    "AR-05": (("private-preview", "contained", "hardened"),
              ({"principal": "external", "action": "s3:PutObject", "resource_org": adversary.OTHER_ORG, "vpce": None},
               # Organization credentials, off the endpoints, to an outside resource of a service other than S3
               # (the test organization's allow-list opens Glue, not SQS or SNS).
               {"action": "glue:CreateTable", "resource_org": adversary.OTHER_ORG, "resource_account": EXTERNAL_ACCOUNT,
                "vpce": None}),
              (({"principal": "external", "action": "s3:PutObject", "resource_org": adversary.OTHER_ORG,
                 "vpce": "vpce-0example2222222222"}, "ORGC05"),
               ({"principal": "anonymous", "action": "s3:PutObject", "resource_org": None,
                 "vpce": "vpce-0example2222222222"}, "ORGC05"),
               ({"action": "glue:CreateTable", "resource_org": adversary.OTHER_ORG, "resource_account": EXTERNAL_ACCOUNT,
                 "vpce": "vpce-0example2222222222"}, "ORGC06"),
               # They can't become outside principals to go further: no roles outside the organization.
               ({"action": "sts:AssumeRole", "resource_org": adversary.OTHER_ORG, "resource_account": EXTERNAL_ACCOUNT,
                 "vpce": None}, "ORGC08"))),
}


class AcceptedRiskTest(AdversarialTestCase):
    def resolve(self, sc, overrides):
        overrides = dict(overrides)
        if overrides.get("principal") == "break-glass":
            overrides["principal"] = role(_account_of(sc.facts.break_glass[0]), "BreakGlass-Responder", ORG)
        elif overrides.get("principal") == "external":
            overrides["principal"] = role(EXTERNAL_ACCOUNT, "analyst", adversary.OTHER_ORG)
        elif overrides.get("principal") == "anonymous":
            overrides["principal"] = ANONYMOUS
        return overrides

    def test_register_entries_are_complete_and_pinned(self):
        ids = [r.id for r in ACCEPTED_RISKS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(RISK_PINS), "every accepted risk needs a pin here, and only those")
        for risk in ACCEPTED_RISKS:
            with self.subTest(risk=risk.id):
                self.assertTrue(risk.risk and risk.why and risk.reach and risk.owner and risk.status)
                self.assertLessEqual(set(risk.controls), set(BY_CONTROL))

    def test_each_risk_applies_exactly_where_its_controls_are_preventive(self):
        for risk in ACCEPTED_RISKS:
            tiers = RISK_PINS[risk.id][0]
            for tier in ("private-preview", "contained", "hardened"):
                with self.subTest(risk=risk.id, tier=tier):
                    active = set(risk.controls) & set(self.scenarios[tier].active())
                    self.assertEqual(bool(active), tier in tiers)

    def test_each_accepted_gap_is_open_exactly_as_registered(self):
        for risk in ACCEPTED_RISKS:
            tiers, requests, _ = RISK_PINS[risk.id]
            for tier, request in ((t, r) for t in tiers for r in (requests if isinstance(requests, tuple) else (requests,))):
                sc = self.scenarios[tier]
                overrides = self.resolve(sc, request)
                with self.subTest(risk=risk.id, tier=tier, action=request.get("action")):
                    decision = sc.decide(**overrides)
                    self.assertTrue(decision.allowed, f"{risk.id} is closed now ({decision.statement}): "
                                                      "update the register")
                    point = adversary.default_point(sc.facts, **overrides)
                    for cid in risk.controls:
                        if cid in sc.active():
                            self.assertFalse(adversary.property_denies(BY_CONTROL[cid], point, sc.facts, ()),
                                             f"the spec for {cid} doesn't leave {risk.id} open")

    def test_each_accepted_gap_stops_at_its_registered_boundary(self):
        for risk in ACCEPTED_RISKS:
            tiers, _, boundary = RISK_PINS[risk.id]
            for tier in tiers:
                sc = self.scenarios[tier]
                for overrides, sid in boundary:
                    with self.subTest(risk=risk.id, tier=tier, boundary=overrides.get("action")):
                        decision = sc.decide(**self.resolve(sc, overrides))
                        self.assertEqual((decision.allowed, decision.statement), (False, sid),
                                         f"{risk.id} reaches further than registered")


# --- Named attacks, end to end -------------------------------------------------------
BREAK_GLASS_ROLE = f"arn:aws:iam::{PREVIEW}:role/BreakGlass-Responder"
S3_ENDPOINT = "vpce-0example2222222222"
TRUSTED_VENDOR = "123456789012"
ATTACKS = (
    # (id, scenario, what the attacker does, request overrides, expected Sid)
    ("A01", "hardened", "a role outside the organization named BreakGlass-x reads an organization S3 object",
     {"principal": role(EXTERNAL_ACCOUNT, "BreakGlass-x", "o-otherorgid"), "action": "s3:GetObject"}, "ORGC03"),
    ("A02", "hardened", "a member creates a role named BreakGlass-x to exempt itself",
     {"action": "iam:CreateRole", "resource": f"arn:aws:iam::{PREVIEW}:role/BreakGlass-x"}, "ORGC04"),
    ("A03", "hardened", "the same through a role path: role BreakGlass-/x matches BreakGlass-*",
     {"action": "iam:CreateRole", "resource": f"arn:aws:iam::{PREVIEW}:role/BreakGlass-/x"}, "ORGC04"),
    ("A04", "hardened", "a member rewrites the break-glass role's trust policy to assume it",
     {"action": "iam:UpdateAssumeRolePolicy", "resource": BREAK_GLASS_ROLE}, "ORGC04"),
    ("A05", "hardened", "a member passes the break-glass role to a service it controls",
     {"action": "iam:PassRole", "resource": BREAK_GLASS_ROLE}, "ORGC04"),
    ("A06", "hardened", "a role named BreakGlass-x in an organization account on no break-glass list stops CloudTrail",
     {"principal": role(ORG_ACCOUNT_ON_NO_LIST, "BreakGlass-x", ORG), "action": "cloudtrail:StopLogging"}, "ORGS01"),
    ("A07", "hardened", "a member edits a Spark notebook", {"action": "athena:UpdateNotebook"}, "ATHC03"),
    ("A08", "hardened", "a member edits Spark notebook metadata", {"action": "athena:UpdateNotebookMetadata"}, "ATHC03"),
    ("A09", "hardened", "a member reaches Athena through a VPC endpoint it created",
     {"action": "athena:StartQueryExecution", "vpce": adversary.ATTACKER_VPCE}, "ATHC04"),
    ("A10", "hardened", "a member spells the action in another case", {"action": "ATHENA:startsession"}, "ATHC03"),
    ("A11", "hardened", "a member uses Athena in a region outside the allow list",
     {"action": "athena:StartQueryExecution", "region": "us-west-2"}, "ORGC01"),
    ("A12", "hardened-high-exception", "a member takes over the exception role by rewriting its trust policy",
     {"action": "iam:UpdateAssumeRolePolicy", "resource": EXCEPTION_ROLE}, "ORGC04"),
    ("A13", "private-preview", "a role named BreakGlass-x in a non-preview account uses Athena",
     {"principal": role(ORG_ACCOUNT_ON_NO_LIST, "BreakGlass-x", ORG), "action": "athena:StartQueryExecution"},
     "ATHC01"),
    ("A14", "private-preview", "an organization role reads an S3 object owned outside the organization",
     {"action": "s3:GetObject", "resource_org": "o-otherorgid"}, "ORGC02"),
    ("A15", "hardened", "a break-glass session copies data to an S3 bucket outside the organization",
     {"principal": role(PREVIEW, "BreakGlass-Responder", ORG), "action": "s3:PutObject",
      "resource_org": "o-otherorgid"}, "ORGC02"),
    # Egress through the organization's own endpoints with someone else's credentials, or none.
    ("A16", "hardened", "third-party credentials upload data to their own bucket through the organization's S3 "
     "endpoint", {"principal": role(EXTERNAL_ACCOUNT, "exfil", "o-otherorgid"), "action": "s3:PutObject",
                  "resource_org": "o-otherorgid", "resource_account": EXTERNAL_ACCOUNT, "vpce": S3_ENDPOINT},
     "ORGC05"),
    ("A17", "private-preview", "an unsigned request writes to a public third-party bucket through the endpoint",
     {"principal": ANONYMOUS, "action": "s3:PutObject", "resource_org": None,
      "resource_account": STANDALONE_ACCOUNT, "vpce": S3_ENDPOINT}, "ORGC05"),
    ("A18", "hardened", "credentials from a standalone account (in no organization) use the endpoint",
     {"principal": role(STANDALONE_ACCOUNT, "exfil", None), "action": "s3:PutObject", "resource_org": None,
      "resource_account": STANDALONE_ACCOUNT, "vpce": S3_ENDPOINT}, "ORGC05"),
    ("A19", "hardened", "an organization role writes table metadata into a third-party Glue catalog through the "
     "endpoint", {"action": "glue:CreateTable", "resource_org": "o-otherorgid",
                  "resource_account": EXTERNAL_ACCOUNT, "vpce": S3_ENDPOINT}, "ORGC06"),
    ("A20", "hardened", "the same into a standalone account, where aws:ResourceOrgID is absent",
     {"action": "glue:CreateTable", "resource_org": None, "resource_account": STANDALONE_ACCOUNT,
      "vpce": S3_ENDPOINT}, "ORGC06"),
    # Workload IAM permissions used to step outside the guardrails.
    ("A21", "private-preview", "a member takes its account out of the organization, and every SCP and RCP with it",
     {"action": "organizations:LeaveOrganization"}, "ORGC07"),
    ("A22", "hardened", "a break-glass session takes its account out of the organization",
     {"principal": role(PREVIEW, "BreakGlass-Responder", ORG), "action": "organizations:LeaveOrganization"},
     "ORGC07"),
    ("A23", "hardened", "a member assumes a role in its own outside account, off the endpoints, to leave the SCPs "
     "behind", {"action": "sts:AssumeRole", "resource": f"arn:aws:iam::{EXTERNAL_ACCOUNT}:role/analyst",
                "resource_org": "o-otherorgid", "resource_account": EXTERNAL_ACCOUNT, "vpce": None}, "ORGC08"),
    ("A24", "hardened", "the same into a standalone account, where aws:ResourceOrgID is absent",
     {"action": "sts:AssumeRole", "resource_org": None, "resource_account": STANDALONE_ACCOUNT, "vpce": None},
     "ORGC08"),
    ("A25", "hardened", "an outside account assumes an organization role a member made it trust",
     {"principal": role(EXTERNAL_ACCOUNT, "analyst", "o-otherorgid"), "action": "sts:AssumeRole",
      "resource": f"arn:aws:iam::{PREVIEW}:role/analyst", "vpce": None}, "ORGC09"),
    ("A26", "hardened", "an outside account reads a secret a member shared through its resource policy",
     {"principal": role(EXTERNAL_ACCOUNT, "analyst", "o-otherorgid"), "action": "secretsmanager:GetSecretValue",
      "vpce": None}, "ORGC09"),
    ("A27", "hardened", "an anonymous caller reads a queue a member made public",
     {"principal": ANONYMOUS, "action": "sqs:ReceiveMessage", "vpce": None}, "ORGC09"),
    ("A28", "contained", "a member overwrites the Config recorder so it records nothing",
     {"action": "config:PutConfigurationRecorder"}, "ORGS02"),
    ("A29", "contained", "a member points the Config delivery channel at another bucket",
     {"action": "config:PutDeliveryChannel"}, "ORGS02"),
    ("A30", "contained", "a member creates a trail that delivers the account's events outside the organization",
     {"action": "cloudtrail:CreateTrail"}, "ORGS01"),
    ("A31", "contained", "a member creates a role named like the platform role to change recording",
     {"action": "iam:CreateRole", "resource": f"arn:aws:iam::{PREVIEW}:role/stacksets-exec-x"}, "ORGC04"),
    ("A32", "contained", "a role named like the platform role in an account on no list changes recording",
     {"principal": role(ORG_ACCOUNT_ON_NO_LIST, "stacksets-exec-x", ORG), "action": "config:PutConfigurationRecorder"},
     "ORGS02"),
)


class NamedAttackTest(AdversarialTestCase):
    def test_each_named_attack_is_denied_by_the_intended_control(self):
        for aid, scenario, what, overrides, sid in ATTACKS:
            with self.subTest(attack=aid, what=what):
                decision = self.scenarios[scenario].decide(**overrides)
                self.assertEqual((decision.allowed, decision.statement), (False, sid), decision.reason)

    def test_named_trusted_accounts_stay_reachable_and_others_do_not(self):
        vendor = {"action": "s3:GetObject", "resource_org": "o-otherorgid", "resource_account": TRUSTED_VENDOR,
                  "vpce": S3_ENDPOINT}
        for tier in ("contained", "hardened"):
            with self.subTest(tier=tier):
                self.assertTrue(self.scenarios[tier].decide(**vendor).allowed)
        # Private Preview names no trusted account, so the vendor is outside the perimeter there.
        decision = self.scenarios["private-preview"].decide(**vendor)
        self.assertEqual((decision.allowed, decision.statement), (False, "ORGC02"))

    def test_named_trusted_principal_accounts_stay_trusted_and_others_do_not(self):
        vendor = {"principal": role(TRUSTED_VENDOR, "analyst", "o-otherorgid"), "action": "sts:AssumeRole",
                  "resource": f"arn:aws:iam::{PREVIEW}:role/analyst", "vpce": None}
        self.assertTrue(self.scenarios["hardened"].decide(**vendor).allowed)
        # Contained names no trusted principal account.
        decision = self.scenarios["contained"].decide(**vendor)
        self.assertEqual((decision.allowed, decision.statement), (False, "ORGC09"))

    def test_the_platform_role_changes_recording_and_nothing_else(self):
        sc = self.scenarios["contained"]
        platform = role(PREVIEW, "stacksets-exec-0a1b2c3d4e5f", ORG)
        for action in ("config:PutConfigurationRecorder", "config:PutDeliveryChannel", "cloudtrail:CreateTrail"):
            with self.subTest(action=action):
                self.assertTrue(sc.decide(principal=platform, action=action).allowed)
        for overrides, sid in (({"action": "organizations:LeaveOrganization"}, "ORGC07"),
                               ({"action": "athena:StartSession"}, "ATHC03"),
                               ({"action": "s3:PutObject", "resource_org": "o-otherorgid"}, "ORGC02")):
            with self.subTest(action=overrides["action"]):
                decision = sc.decide(principal=platform, **overrides)
                self.assertEqual((decision.allowed, decision.statement), (False, sid))

    def test_legitimate_break_glass_still_works(self):
        sc = self.scenarios["hardened"]
        for account in (PREVIEW, OTHER):
            principal = role(account, "BreakGlass-Responder", ORG)
            for action, resource in (("cloudtrail:StopLogging", "*"), ("athena:StartSession", "*"),
                                     ("iam:UpdateAssumeRolePolicy", BREAK_GLASS_ROLE), ("s3:GetObject", "*")):
                with self.subTest(account=account, action=action):
                    self.assertTrue(sc.decide(principal=principal, action=action, resource=resource).allowed)


if __name__ == "__main__":
    unittest.main()
