import datetime as dt
import unittest

from onboard.model import Criticality, Tier
from onboard.request import DEFAULT_ALLOWED_REGIONS, RequestError, parse_request

TODAY = dt.date(2026, 10, 30)


def preview_request(**overrides):
    request = {
        "service": "bedrock",
        "maturity_tier": "Private Preview",
        "preview_accounts": ["111122223333"],
        "non_production_attested": True,
        "org_state": {"ous": [], "policies": []},
        "maker": "analyst-a",
        "checker": "analyst-b",
    }
    request.update(overrides)
    return {k: v for k, v in request.items() if v is not None}


class ParseRequestTest(unittest.TestCase):
    def problems(self, data):
        with self.assertRaises(RequestError) as ctx:
            parse_request(data, today=TODAY)
        return "\n".join(ctx.exception.problems)

    def test_minimal_preview_request_gets_defaults(self):
        r = parse_request(preview_request(), today=TODAY)
        self.assertIs(r.maturity_tier, Tier.PRIVATE_PREVIEW)
        self.assertIs(r.criticality, Criticality.MODERATE)
        self.assertEqual(r.run_mode, "new")
        self.assertEqual(r.allowed_regions, DEFAULT_ALLOWED_REGIONS)
        self.assertEqual(r.regulatory_profile, "ca-frfi-global")
        self.assertEqual(r.framework_profile, "baseline")

    def test_rejects_non_object(self):
        self.assertIn("JSON object", self.problems([]))

    def test_maker_and_checker_must_differ(self):
        self.assertIn("two different people", self.problems(preview_request(checker=" Analyst-A ")))

    def test_maker_and_checker_required(self):
        problems = self.problems(preview_request(maker=None, checker=""))
        self.assertIn("maker is required", problems)
        self.assertIn("checker is required", problems)

    def test_private_preview_needs_accounts_and_attestation(self):
        problems = self.problems(preview_request(preview_accounts=None, non_production_attested=None))
        self.assertIn("preview_accounts is required", problems)
        self.assertIn("non_production_attested must be true", problems)

    def test_preview_accounts_are_account_ids(self):
        self.assertIn("12-digit", self.problems(preview_request(preview_accounts=["1234"])))

    def test_contained_needs_target_scope(self):
        data = preview_request(maturity_tier="Contained", preview_accounts=None)
        self.assertIn("target_scope is required at Contained", self.problems(data))
        r = parse_request({**data, "target_scope": ["Workloads/Prod"]}, today=TODAY)
        self.assertIs(r.maturity_tier, Tier.CONTAINED)

    def test_unknown_tier_and_criticality(self):
        problems = self.problems(preview_request(maturity_tier="GA", criticality="Severe"))
        self.assertIn("maturity_tier must be one of", problems)
        self.assertIn("criticality must be one of", problems)

    def test_diff_run_needs_registry(self):
        self.assertIn("control_registry is required for a diff run",
                      self.problems(preview_request(run_mode="diff")))

    def test_unknown_fields_are_refused(self):
        self.assertIn("unknown fields: critcality", self.problems(preview_request(critcality="High")))

    def test_org_state_required(self):
        self.assertIn("org_state is required", self.problems(preview_request(org_state=None)))

    def test_exceptions_need_every_field_and_a_future_expiry(self):
        valid = {"principal": "arn:aws:iam::111122223333:role/Example", "control_id": "EX-1",
                 "owner": "team-a", "expires": "2027-01-31", "rationale": "migration"}
        r = parse_request(preview_request(exceptions=[valid]), today=TODAY)
        self.assertEqual(r.exceptions[0].expires, dt.date(2027, 1, 31))

        problems = self.problems(preview_request(exceptions=[
            {**valid, "owner": ""},
            {**valid, "expires": "2026-10-30"},
            {**valid, "expires": "next year"},
        ]))
        self.assertIn("exceptions[0] is missing owner", problems)
        self.assertIn("exceptions[1] expired on 2026-10-30", problems)
        self.assertIn("exceptions[2].expires must be an ISO date", problems)

    def test_exception_principals_name_exactly_one_role(self):
        valid = {"principal": "arn:aws:iam::111122223333:role/Example", "control_id": "EX-1",
                 "owner": "team-a", "expires": "2027-01-31", "rationale": "migration"}
        for principal in ("arn:aws:iam::111122223333:role/Ex*", "arn:aws:iam::*:role/Example",
                          "arn:aws:iam::111122223333:user/Example", "Example"):
            with self.subTest(principal=principal):
                problems = self.problems(preview_request(exceptions=[{**valid, "principal": principal}]))
                self.assertIn("exceptions[0].principal must be one IAM role ARN in a 12-digit account", problems)

    def test_break_glass_principals_are_roles_in_named_accounts(self):
        ok = ["arn:aws:iam::111122223333:role/BreakGlass-*", "arn:aws:iam::111122223333:role/breakglass/*",
              "arn:aws:iam::444455556666:role/BreakGlass-Responder"]
        self.assertEqual(parse_request(preview_request(break_glass_principals=ok), today=TODAY).break_glass_principals,
                         tuple(ok))
        # A wildcard account matches a role of that name in any account, even outside the organization.
        for bad in ("arn:aws:iam::*:role/BreakGlass-*", "arn:aws:iam::111122223333:role/*",
                    "arn:aws:iam::111122223333:role/Break*Glass", "arn:*:iam::111122223333:role/BreakGlass-*",
                    "arn:aws:iam::111122223333:user/BreakGlass"):
            with self.subTest(principal=bad):
                self.assertIn("break_glass_principals must be IAM role ARNs in a 12-digit account",
                              self.problems(preview_request(break_glass_principals=[bad])))

    def test_internal_restricted_is_the_moderate_default(self):
        r = parse_request(preview_request(data_classification="Internal Restricted"), today=TODAY)
        self.assertEqual((r.criticality, r.criticality_source), (Criticality.MODERATE, "default"))

    def test_classification_raises_a_lower_declared_criticality(self):
        r = parse_request(preview_request(criticality="Low", data_classification="Internal Restricted"), today=TODAY)
        self.assertEqual((r.criticality, r.criticality_source),
                         (Criticality.MODERATE, "raised by data classification"))

    def test_classification_never_lowers_criticality(self):
        r = parse_request(preview_request(criticality="High", data_classification="Internal"), today=TODAY)
        self.assertEqual((r.criticality, r.criticality_source), (Criticality.HIGH, "declared"))

    def test_unmapped_classification_fails_closed(self):
        self.assertIn("data_classification 'Confidential' has no criticality mapping",
                      self.problems(preview_request(data_classification="Confidential")))

    def test_region_names_are_checked(self):
        self.assertIn("invalid region names: Canada",
                      self.problems(preview_request(allowed_regions=["ca-central-1", "Canada"])))

    def test_all_problems_are_reported_at_once(self):
        with self.assertRaises(RequestError) as ctx:
            parse_request({}, today=TODAY)
        self.assertGreaterEqual(len(ctx.exception.problems), 4)


if __name__ == "__main__":
    unittest.main()
