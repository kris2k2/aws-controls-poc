"""Security spec for Athena's preventive controls: what each one must deny.

This is the file the security team reviews instead of the generated JSON.
Each property says, in terms of the request, what a control must deny; it is
written from the control's title and objective, not from its guardrail. The
adversarial tests (`tests/test_athena_adversarial.py`) prove each generated
statement denies exactly this, no more and no less, over the attacker model
in `tests/adversary.py`.

Conventions:
- `deny_when(r, f)` reads the request `r` (only the dimensions in `reads`, plus
  `r.principal`) and the request's facts `f` (`adversary.Facts`).
- Break-glass principals, and approved exceptions for Enforce-with-override
  controls, are exempt from every property except the data perimeter
  (ORG-C-02, ORG-C-03, `break_glass_exempt=False`), and only while they are
  organization principals (`adversary.trusted`). That exemption is safe only
  because ORG-C-04 stops anyone else creating, changing or passing those roles.
- The accepted risks below are the gaps left open on purpose. Each states its
  reach (who can use it and from where), is pinned by a request that must stay
  allowed, and lists boundary requests that must stay denied. Closing or
  widening a gap shows up as a failing test and the register gets revisited.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from tests.adversary import CONSTRAINS_PRINCIPALS as PRINCIPALS
from tests.adversary import CONSTRAINS_RESOURCES as RESOURCES
from tests.adversary import OTHER_ORG, Property

ACTION_REVIEW = json.loads((Path(__file__).parent / "fixtures" / "athena" / "action-review.json").read_text())


def _reviewed_deny(control: str) -> tuple[str, ...]:
    return tuple(f"athena:{a}" for a in ACTION_REVIEW["capabilities"][control]["deny"])


# Global services: their endpoints don't follow the requested region.
GLOBAL_SERVICES = ("iam:*", "organizations:*", "sts:*", "route53:*", "cloudfront:*", "support:*")
# Every IAM action whose resource is a role and that can change who can use the
# role, what it may do, or hand it to a service (checked against the AWS service
# reference on 2026-11-05).
ROLE_CHANGES = tuple(f"iam:{a}" for a in (
    "AttachRolePolicy", "CreateRole", "DeleteRole", "DeleteRolePermissionsBoundary", "DeleteRolePolicy",
    "DetachRolePolicy", "PassRole", "PutRolePermissionsBoundary", "PutRolePolicy", "TagRole", "UntagRole",
    "UpdateAssumeRolePolicy", "UpdateRole", "UpdateRoleDescription"))
CLOUDTRAIL_CHANGES = ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                      "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors")
CONFIG_CHANGES = ("config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
                  "config:DeleteDeliveryChannel")

PROPERTIES = (
    Property("ORG-C-01", "Requests only in allowed regions", PRINCIPALS,
             not_actions=GLOBAL_SERVICES, reads=("region",),
             deny_when=lambda r, f: r.region not in f.allowed_regions),
    Property("ORG-C-02", "Organization principals reach only organization S3 resources", PRINCIPALS,
             actions=("s3:*",), reads=("resource_org",), break_glass_exempt=False,
             deny_when=lambda r, f: r.resource_org != f.org_id),
    Property("ORG-C-03", "Only organization principals (or AWS services) reach S3 and KMS resources", RESOURCES,
             actions=("s3:*", "kms:*"), break_glass_exempt=False,
             deny_when=lambda r, f: not r.principal.service and r.principal.org_id != f.org_id),
    Property("ORG-C-04", "Only break-glass principals change or pass break-glass and exception roles", PRINCIPALS,
             actions=ROLE_CHANGES, resources=lambda f: f.protected_roles),
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
    Property("ORG-S-01", "CloudTrail can't be stopped or reconfigured", PRINCIPALS, actions=CLOUDTRAIL_CHANGES),
    Property("ORG-S-02", "Config recording can't be stopped", PRINCIPALS, actions=CONFIG_CHANGES),
    Property("ATH-H-06", "Workgroups are created with a cost-center tag", PRINCIPALS,
             actions=("athena:CreateWorkGroup",), reads=("tag",),
             deny_when=lambda r, f: r.tag is None),
)
BY_CONTROL = {p.control: p for p in PROPERTIES}


@dataclass(frozen=True)
class AcceptedRisk:
    id: str
    controls: tuple[str, ...]
    risk: str
    why: str
    owner: str
    status: str
    tiers: tuple[str, ...]
    request: dict  # overrides on adversary.default_point; must stay allowed
    reach: str     # who can use the gap, and from where
    boundary: tuple[tuple[dict, str], ...] = ()  # (overrides, Sid): requests that must stay denied


_PROPOSED = "proposed: needs security team sign-off"

ACCEPTED_RISKS = (
    AcceptedRisk(
        "AR-01", ("ATH-C-04",),
        "Athena calls an AWS service makes on the caller's behalf (aws:ViaAWSService) skip the VPC endpoint check, "
        "for example Athena resources created through CloudFormation from outside the network.",
        "Services calling Athena never arrive through the organization's endpoint; denying them breaks "
        "CloudFormation and other integrations. The caller still needs IAM permission for the call.",
        "security-team", _PROPOSED, ("private-preview", "contained", "hardened"),
        {"action": "athena:StartQueryExecution", "vpce": None, "via": True},
        reach="Organization principals only (SCPs bind no one else), but from any network: someone outside it "
              "holding a stolen organization credential can reach Athena through a service, limited to what that "
              "service does with Athena. The data perimeter still applies on that path.",
        boundary=(({"action": "s3:PutObject", "vpce": None, "via": True, "resource_org": OTHER_ORG}, "ORGC02"),
                  ({"principal": "external", "action": "s3:GetObject", "vpce": None, "via": True}, "ORGC03"))),
    AcceptedRisk(
        "AR-02", ("ATH-C-03",),
        "Workgroups with the Spark engine can still be created: the API contract has no condition key for the "
        "engine type.",
        "Such a workgroup is inert, because starting sessions and calculations and creating or editing notebooks "
        "are denied. The Sentinel policy is meant to catch it in Terraform plans.",
        "security-team", _PROPOSED, ("private-preview", "contained", "hardened"),
        {"action": "athena:CreateWorkGroup", "tag": "cc-0001"},
        reach="Organization principals only. Contained: the workgroup can't run Spark.",
        boundary=(({"action": "athena:StartSession"}, "ATHC03"),
                  ({"action": "athena:StartCalculationExecution"}, "ATHC03"))),
    AcceptedRisk(
        "AR-03", ("ORG-C-01",),
        "Global services (IAM, Organizations, STS, Route 53, CloudFront, Support) are not region-restricted.",
        "Their endpoints don't follow the requested region; denying them outside the allowed regions breaks them.",
        "security-team", _PROPOSED, ("private-preview", "contained", "hardened"),
        {"action": "iam:ListRoles", "region": "us-west-2"},
        reach="Organization principals only, but not contained to the allowed regions: global services serve "
              "from everywhere (CloudFront caches at edge locations worldwide), which matters where personal "
              "data must stay in Canada. Only the global services the allow-list opens are reachable; this "
              "organization's allow-list opens IAM, STS and Organizations reads, not CloudFront or Route 53.",
        boundary=(({"action": "athena:StartQueryExecution", "region": "us-west-2"}, "ORGC01"),)),
    AcceptedRisk(
        "AR-04", ("ORG-S-01",),
        "Break-glass principals are exempt from every guardrail except the data perimeter, including the ones "
        "protecting CloudTrail.",
        "Break-glass access exists to recover from the guardrails themselves. ORG-C-04 stops anyone else "
        "creating, changing or passing those roles; their use is meant to be detected (ATH-S-06, pending).",
        "security-team", _PROPOSED, ("contained", "hardened"),
        {"action": "cloudtrail:StopLogging", "principal": "break-glass"},
        reach="Break-glass sessions only, but who can start one is set by the break-glass roles' trust "
              "policies, which this tool neither generates nor checks: a trust policy naming an outside account "
              "or an external identity provider brings outsiders in. ORG-C-04 stops organization members from "
              "changing those trust policies, not what is already in them; the management account isn't bound "
              "by SCPs. Break-glass is held to the data perimeter, so it can't move data out of the organization.",
        boundary=(({"action": "s3:PutObject", "principal": "break-glass", "resource_org": OTHER_ORG}, "ORGC02"),)),
)
