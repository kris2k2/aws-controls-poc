"""Acceptance: onboarding Amazon Athena at Private Preview, offline.

Runs the tool as far as it is built (request validation, the control model,
Resolve) against a pinned snapshot of the real AWS service reference, retrieved
2026-10-30. The walkthrough of the stages not built yet is in
docs/simulations/athena-private-preview.md. Refresh the snapshot together with
that document.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from onboard.cli import main
from onboard.model import ControlClass, Criticality, Mode, Severity, Tier, derive_mode

SNAPSHOT = Path(__file__).parent / "fixtures" / "service-reference" / "2026-10-30"
REQUEST = {
    "service": "Amazon Athena",
    "maturity_tier": "Private Preview",
    "preview_accounts": ["111122223333"],
    "non_production_attested": True,
    "org_state": {"ous": [], "policies": []},
    "maker": "analyst-a",
    "checker": "analyst-b",
}


class AthenaPrivatePreviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        request = Path(tmp.name) / "request.json"
        request.write_text(json.dumps(REQUEST))
        out = Path(tmp.name) / "run"
        with redirect_stdout(io.StringIO()):
            cls.check_exit = main(["check-request", str(request)])
            cls.resolve_exit = main(["resolve", str(request), "--out", str(out), "--snapshot", str(SNAPSHOT)])
        cls.profile = json.loads((out / "capability-profile.json").read_text())
        cls.athena = cls.profile["services"][0]
        cls.actions = {a["action"]: a for a in cls.athena["actions"]}

    def test_request_and_resolve_succeed(self):
        self.assertEqual((self.check_exit, self.resolve_exit), (0, 0))

    def test_resolves_to_the_athena_prefix_only(self):
        self.assertEqual(self.profile["prefixes"], ["athena"])
        self.assertEqual(self.profile["related_prefixes_to_confirm"], [])

    def test_api_contract(self):
        self.assertEqual(self.athena["summary"], {
            "actions": 81,
            "actions_by_risk_tier": {"permission-management": 0, "write": 33, "tagging": 2, "read": 34, "list": 12},
            "resource_types": 4,
            "condition_keys": 3,
        })
        self.assertEqual([r["resource_type"] for r in self.athena["resource_types"]],
                         ["capacity-reservation", "datacatalog", "session", "workgroup"])

    def test_only_global_tag_condition_keys(self):
        # Finding F1: no athena:* condition keys, so a guardrail can't scope by workgroup settings.
        self.assertEqual([k["condition_key"] for k in self.athena["condition_keys"]],
                         ["aws:RequestTag/${TagKey}", "aws:ResourceTag/${TagKey}", "aws:TagKeys"])

    def test_dependencies_are_invisible_in_the_contract(self):
        # Finding F2: queries read S3, Glue and KMS as the caller, but the only
        # cross-prefix action the operations list is iam:PassRole (Spark sessions).
        cross = sorted({a for o in self.athena["operations"] for a in o["authorized_actions"]
                        if not a.startswith("athena:")})
        self.assertEqual(cross, ["iam:PassRole"])
        query = next(o for o in self.athena["operations"] if o["operation"] == "StartQueryExecution")
        self.assertEqual(query["authorized_actions"], ["athena:StartQueryExecution"])

    def test_no_action_is_annotated_data_plane(self):
        # Finding F3: IsDataPlane can't drive CloudTrail data-event selection for Athena.
        self.assertFalse(any(a["data_plane"] for a in self.athena["actions"]))

    def test_egress_and_sharing_candidates_are_ordinary_writes(self):
        # Finding F4: risk tiers don't single out egress or sharing features.
        for action in ("athena:CreateDataCatalog", "athena:CreatePresignedNotebookUrl",
                       "athena:ExportNotebook", "athena:StartSession"):
            self.assertEqual(self.actions[action]["risk_tier"], "write", action)

    def test_containment_controls_enforce_whatever_the_severity(self):
        for severity in Severity:
            for criticality in Criticality:
                self.assertIs(derive_mode(severity, criticality, ControlClass.CONTAINMENT,
                                          Tier.PRIVATE_PREVIEW), Mode.ENFORCE)


if __name__ == "__main__":
    unittest.main()
