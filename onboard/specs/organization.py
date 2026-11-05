"""Security spec for the shared organization controls (ORG-*), used with every service."""

from __future__ import annotations

from ..adversary import CONSTRAINS_ENDPOINTS as ENDPOINTS
from ..adversary import CONSTRAINS_PRINCIPALS as PRINCIPALS
from ..adversary import CONSTRAINS_RESOURCES as RESOURCES
from ..adversary import Property
from . import PROPOSED, AcceptedRisk, EquivalentMutant

STATUS = PROPOSED

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
    Property("ORG-C-02", "Organization principals reach only organization S3 resources and named trusted accounts",
             PRINCIPALS, actions=("s3:*",), reads=("resource_org", "resource_account"), break_glass_exempt=False,
             deny_when=lambda r, f: r.resource_org != f.org_id
             and r.resource_account not in f.trusted_resource_accounts),
    Property("ORG-C-03", "Only organization principals (or AWS services) reach S3 and KMS resources", RESOURCES,
             actions=("s3:*", "kms:*"), break_glass_exempt=False,
             deny_when=lambda r, f: not r.principal.service and r.principal.org_id != f.org_id),
    # The data perimeter on the network path: whoever comes through the organization's VPC endpoints, with
    # whatever credentials (or none), reaches only the organization's resources and named trusted accounts.
    Property("ORG-C-05", "Only organization principals use the organization's VPC endpoints", ENDPOINTS,
             actions=("*",), break_glass_exempt=False,
             deny_when=lambda r, f: r.principal.org_id != f.org_id),
    Property("ORG-C-06", "The organization's VPC endpoints reach only organization resources and named trusted "
             "accounts", ENDPOINTS, actions=("*",), reads=("resource_org", "resource_account"),
             break_glass_exempt=False,
             deny_when=lambda r, f: r.resource_org != f.org_id
             and r.resource_account not in f.trusted_resource_accounts),
    Property("ORG-C-04", "Only break-glass principals change or pass break-glass and exception roles", PRINCIPALS,
             actions=ROLE_CHANGES, resources=lambda f: f.protected_roles),
    Property("ORG-S-01", "CloudTrail can't be stopped or reconfigured", PRINCIPALS, actions=CLOUDTRAIL_CHANGES),
    Property("ORG-S-02", "Config recording can't be stopped", PRINCIPALS, actions=CONFIG_CHANGES),
)

ACCEPTED_RISKS = (
    AcceptedRisk(
        "AR-03", ("ORG-C-01",),
        "Global services (IAM, Organizations, STS, Route 53, CloudFront, Support) are not region-restricted.",
        "Their endpoints don't follow the requested region; denying them outside the allowed regions breaks them.",
        "security-team", PROPOSED,
        reach="Organization principals only, but not contained to the allowed regions: global services serve "
              "from everywhere (CloudFront caches at edge locations worldwide), which matters where personal "
              "data must stay in Canada. Only the global services the allow-list opens are reachable."),
    AcceptedRisk(
        "AR-04", ("ORG-S-01",),
        "Break-glass principals are exempt from every guardrail except the data perimeter, including the ones "
        "protecting CloudTrail.",
        "Break-glass access exists to recover from the guardrails themselves. ORG-C-04 stops anyone else "
        "creating, changing or passing those roles; their use is meant to be detected (ATH-S-06, pending).",
        "security-team", PROPOSED,
        reach="Break-glass sessions only, but who can start one is set by the break-glass roles' trust "
              "policies, which this tool neither generates nor checks: a trust policy naming an outside account "
              "or an external identity provider brings outsiders in. ORG-C-04 stops organization members from "
              "changing those trust policies, not what is already in them; the management account isn't bound "
              "by SCPs. Break-glass is held to the data perimeter, so it can't move data out of the organization."),
    AcceptedRisk(
        "AR-05", ("ORG-C-05", "ORG-C-06"),
        "Traffic that doesn't come through the organization's VPC endpoints (a NAT or internet gateway, a proxy, "
        "a device off the network) is outside the endpoint policy, so third-party credentials can still move "
        "data out that way.",
        "Organization and endpoint policies can't see such traffic: no SCP or RCP applies to a third-party "
        "principal writing to a third-party resource. It has to be closed in the network (no internet egress "
        "from workload VPCs, egress filtering), which is outside this tool.",
        "security-team", PROPOSED,
        reach="Anyone with a network path that bypasses the organization's endpoints and credentials for an "
              "outside account (or none, for a public bucket)."),
)

EQUIVALENT_MUTANTS = (
    EquivalentMutant(
        "ORG-C-02", r"(drop BoolIfExists|change BoolIfExists to Bool on) aws:PrincipalIsAWSService",
        "SCPs never apply to AWS service principals, so the condition is always true where the SCP applies"),
    EquivalentMutant(
        "ORG-C-03", r"change BoolIfExists to Bool on aws:PrincipalIsAWSService",
        "the model always sets aws:PrincipalIsAWSService; calibration against AWS should confirm it is always "
        "present"),
)
