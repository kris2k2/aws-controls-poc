"""Security spec for Amazon Athena's own preventive controls (ATH-*)."""

from __future__ import annotations

import json
from pathlib import Path

from ..adversary import CONSTRAINS_PRINCIPALS as PRINCIPALS
from ..adversary import Property
from . import PROPOSED, AcceptedRisk, EquivalentMutant

STATUS = PROPOSED

# Every Athena action in the API contract, and how each capability the request
# excludes is handled: denied, or allowed with a reason. Verify fails a
# capability control whose contract has actions this file doesn't classify.
ACTION_REVIEW_FILE = Path(__file__).with_name("athena-action-review.json")
ACTION_REVIEW = json.loads(ACTION_REVIEW_FILE.read_text(encoding="utf-8"))
DATA_FILES = (ACTION_REVIEW_FILE,)


def _reviewed_deny(control: str) -> tuple[str, ...]:
    return tuple(f"athena:{a}" for a in ACTION_REVIEW["capabilities"][control]["deny"])


PROPERTIES = (
    Property("ATH-C-01", "Athena only in the authorized preview accounts", PRINCIPALS,
             actions=("athena:*",),
             deny_when=lambda r, f: r.principal.account not in f.preview_accounts),
    Property("ATH-C-02", "No federated or cross-account data catalogs", PRINCIPALS,
             actions=_reviewed_deny("ATH-C-02")),
    Property("ATH-C-03", "No Spark notebooks, sessions or calculations", PRINCIPALS,
             actions=_reviewed_deny("ATH-C-03")),
    Property("ATH-C-04", "Athena API only through the organization's VPC endpoints", PRINCIPALS,
             actions=("athena:*",), reads=("vpce", "via"),
             deny_when=lambda r, f: not r.via and r.vpce not in f.vpce_ids),
    Property("ATH-H-06", "Workgroups are created with a cost-center tag", PRINCIPALS,
             actions=("athena:CreateWorkGroup",), reads=("tag",),
             deny_when=lambda r, f: r.tag is None),
)

ACCEPTED_RISKS = (
    AcceptedRisk(
        "AR-01", ("ATH-C-04",),
        "Athena calls an AWS service makes on the caller's behalf (aws:ViaAWSService) skip the VPC endpoint check, "
        "for example Athena resources created through CloudFormation from outside the network.",
        "Services calling Athena never arrive through the organization's endpoint; denying them breaks "
        "CloudFormation and other integrations. The caller still needs IAM permission for the call.",
        "security-team", PROPOSED,
        reach="Organization principals only (SCPs bind no one else), but from any network: someone outside it "
              "holding a stolen organization credential can reach Athena through a service, limited to what that "
              "service does with Athena. The data perimeter still applies on that path."),
    AcceptedRisk(
        "AR-02", ("ATH-C-03",),
        "Workgroups with the Spark engine can still be created: the API contract has no condition key for the "
        "engine type.",
        "Such a workgroup is inert, because starting sessions and calculations and creating or editing notebooks "
        "are denied. The Sentinel policy is meant to catch it in Terraform plans.",
        "security-team", PROPOSED,
        reach="Organization principals only. Contained: the workgroup can't run Spark."),
)

EQUIVALENT_MUTANTS = (
    EquivalentMutant(
        "ATH-C-04", r"change BoolIfExists to Bool on aws:ViaAWSService",
        "the model always sets aws:ViaAWSService; calibration against AWS should confirm it is always present"),
    EquivalentMutant(
        "ATH-C-01", r"drop arn:aws:iam::(\d{12}):role/\S+ from ArnNotLike aws:PrincipalArn",
        "the exempt role is in a preview account, where ATH-C-01 denies nobody",
        when=lambda m, facts: m.group(1) in facts.preview_accounts),
)
