"""Adversarial tests for the generated Athena guardrails.

Layers (see `tests/adversary.py` for the method and its limits):
1. The security spec, `tests/athena_security_spec.py`: what each control must deny.
2. The attacker model, `tests/adversary.Space`: what an attacker can vary.
3. Bounded proof: each generated statement denies exactly what its property denies.
4. Completeness against the API contract: every Athena action is reviewed.
5. Exemption hygiene: no exemption an attacker can match or create.
6. Mutation testing: every way of breaking a statement is caught.
7. Accepted risks: the gaps left open on purpose stay exactly that wide.
Plus a catalogue of named attacks, end to end through every policy.
"""

import re
import unittest

from onboard.cli import snapshot_fetcher
from onboard.controls import load_findings
from onboard.model import Mode
from onboard.resolve import resolve
from onboard.service_reference import ServiceReference
from tests import adversary
from tests.adversary import EXTERNAL_ACCOUNT, ORG_ACCOUNT_ON_NO_LIST, Facts, Space, role
from tests.athena_security_spec import ACCEPTED_RISKS, ACTION_REVIEW, BY_CONTROL, ROLE_CHANGES
from tests.test_athena_journey import BASELINE_ALLOW, ORG, OTHER, PREVIEW, SNAPSHOT, load, run_tier

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

    def active(self):
        """Controls that must be preventive here, with the exceptions that apply to each."""
        out = {}
        for cid, record in self.controls.items():
            if "guardrail" not in record:
                continue
            mode = Mode(record["mode"])
            approved = tuple(e.principal for e in self.request.exceptions if e.control_id == cid)
            if mode is Mode.ENFORCE:
                out[cid] = ()
            elif mode is Mode.ENFORCE_WITH_OVERRIDE and approved:
                out[cid] = approved
        return out

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
        return adversary.decide(point, self.facts, scps, rcps)


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

    def test_a_property_cannot_read_what_it_does_not_declare(self):
        sneaky = adversary.Property("ATH-C-04", "reads vpce undeclared", adversary.CONSTRAINS_PRINCIPALS,
                                    actions=("athena:*",), deny_when=lambda r, f: r.vpce is None)
        sc = self.scenarios["hardened"]
        with self.assertRaisesRegex(AssertionError, "reads 'vpce' without declaring it"):
            adversary.counterexamples(sc.statement("ATH-C-04")[1], sneaky, sc.space)

    def test_a_statement_reading_a_key_outside_the_model_fails(self):
        stmt = {"Sid": "X", "Effect": "Deny", "Action": "athena:*", "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceIp": "192.0.2.1"}}}
        sc = self.scenarios["hardened"]
        with self.assertRaisesRegex(AssertionError, "aws:SourceIp, which the attacker model doesn't vary"):
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
# Mutants that change nothing the model can observe, so no test could catch
# them. Each must keep surviving: if one starts being caught, drop it here.
# Keys are (control, regular expression over the mutant's description).
EQUIVALENT_MUTANTS = {
    ("ORG-C-02", r"(drop BoolIfExists|change BoolIfExists to Bool on) aws:PrincipalIsAWSService"):
        "SCPs never apply to AWS service principals, so the condition is always true where the SCP applies",
    ("ORG-C-03", r"drop (\S+ from )?ArnNotLike aws:PrincipalArn"):
        "break-glass principals are organization principals, which ORG-C-03 never denies: the exemption is inert",
    ("ORG-C-03", r"change BoolIfExists to Bool on aws:PrincipalIsAWSService"):
        "the model always sets aws:PrincipalIsAWSService; calibration against AWS should confirm it is always present",
    ("ATH-C-04", r"change BoolIfExists to Bool on aws:ViaAWSService"):
        "the model always sets aws:ViaAWSService; calibration against AWS should confirm it is always present",
    ("ATH-C-01", r"drop arn:aws:iam::111122223333:role/BreakGlass-\* from ArnNotLike aws:PrincipalArn"):
        "111122223333 is the preview account, where ATH-C-01 denies nobody",
}


def equivalent(cid, description):
    return next((key for key in EQUIVALENT_MUTANTS if key[0] == cid and re.fullmatch(key[1], description)), None)


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
                    key = equivalent(cid, description)
                    if key:
                        seen.add(key)
                        caught.update([(key, name, description)] if found else [])
                        continue
                    with self.subTest(scenario=name, control=cid, mutant=description):
                        self.assertTrue(found, "survived: the tests would not notice this bug")
        self.assertGreater(total, 150)  # the operators really ran
        self.assertEqual(seen, set(EQUIVALENT_MUTANTS), "a listed equivalent mutant no longer occurs: drop it")
        self.assertEqual(caught, set(), "a listed equivalent mutant is caught now: drop it")

    def test_every_allow_list_mutant_is_caught(self):
        sc = self.scenarios["hardened"]
        for description, mutant in adversary.allow_list_mutants(sc.allow):
            with self.subTest(mutant=description):
                self.assertTrue(adversary.allow_list_counterexamples(mutant, sc.space, limit=1))


# --- Layer 7: accepted risks --------------------------------------------------------
class AcceptedRiskTest(AdversarialTestCase):
    def resolve(self, sc, overrides):
        overrides = dict(overrides)
        if overrides.get("principal") == "break-glass":
            overrides["principal"] = role(_account_of(sc.facts.break_glass[0]), "BreakGlass-Responder", ORG)
        return overrides

    def test_register_entries_are_complete(self):
        ids = [r.id for r in ACCEPTED_RISKS]
        self.assertEqual(len(ids), len(set(ids)))
        for risk in ACCEPTED_RISKS:
            with self.subTest(risk=risk.id):
                self.assertTrue(risk.risk and risk.why and risk.owner and risk.status and risk.tiers)
                self.assertLessEqual(set(risk.controls), set(BY_CONTROL))

    def test_each_accepted_gap_is_open_exactly_as_registered(self):
        for risk in ACCEPTED_RISKS:
            for tier in risk.tiers:
                sc = self.scenarios[tier]
                overrides = self.resolve(sc, risk.request)
                with self.subTest(risk=risk.id, tier=tier):
                    decision = sc.decide(**overrides)
                    self.assertTrue(decision.allowed, f"{risk.id} is closed now ({decision.statement}): "
                                                      "update the register")
                    point = adversary.default_point(sc.facts, **overrides)
                    for cid in risk.controls:
                        if cid in sc.active():
                            self.assertFalse(adversary.property_denies(BY_CONTROL[cid], point, sc.facts, ()),
                                             f"the spec for {cid} doesn't leave {risk.id} open")


# --- Named attacks, end to end -------------------------------------------------------
BREAK_GLASS_ROLE = f"arn:aws:iam::{PREVIEW}:role/BreakGlass-Responder"
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
)


class NamedAttackTest(AdversarialTestCase):
    def test_each_named_attack_is_denied_by_the_intended_control(self):
        for aid, scenario, what, overrides, sid in ATTACKS:
            with self.subTest(attack=aid, what=what):
                decision = self.scenarios[scenario].decide(**overrides)
                self.assertEqual((decision.allowed, decision.statement), (False, sid), decision.reason)

    def test_legitimate_break_glass_still_works(self):
        sc = self.scenarios["hardened"]
        for account in (PREVIEW, OTHER):
            principal = role(account, "BreakGlass-Responder", ORG)
            for action, resource in (("cloudtrail:StopLogging", "*"), ("athena:StartSession", "*"),
                                     ("iam:UpdateAssumeRolePolicy", BREAK_GLASS_ROLE)):
                with self.subTest(account=account, action=action):
                    self.assertTrue(sc.decide(principal=principal, action=action, resource=resource).allowed)


if __name__ == "__main__":
    unittest.main()
