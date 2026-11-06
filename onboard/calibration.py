"""Calibration against AWS's documented evaluation behaviour (ADR-0012).

Proofs hold in the local evaluator's model of IAM (`onboard/evaluator.py`).
Calibrating it fully means replaying requests through the IAM policy
simulator and live calls, which needs AWS. Until then, this suite pins the
evaluator to what AWS documents: each case is a behaviour stated on an AWS
documentation page, quoted with its URL, turned into a request and the
documented outcome. Review runs it itself (nothing supplied from outside can
stand in for it): every case passing lowers the calibration doubt to Low; any
case failing blocks, because the evaluator then disagrees with AWS's own
description of IAM.

Only what the pages state is tested. What the evaluator assumes but the pages
read don't state is listed in `UNDOCUMENTED`; what they state but the
evaluator doesn't model is in `NOT_MODELLED` (both are blind spots of every
proof, already named on the controls).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evaluator import Request, evaluate

SCP_EVAL = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html"
RCP_PAGE = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html"
RCP_EVAL = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_evaluation.html"
CONDITIONS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html"
NOTACTION = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html"
DENY_ALLOW = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html"
ENDPOINTS = "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html"
CHECKED = "2026-11-06"

UNDOCUMENTED = (
    "multiple values for one condition key are ORed, multiple keys and operators ANDed (shown only in a figure)",
    "an explicit Deny in a VPC endpoint policy denies (not stated on the endpoint page)",
)
NOT_MODELLED = (
    "SCPs don't affect the management account or service-linked roles (SCP page)",
    "RCPs don't affect resources in the management account or calls by service-linked roles (RCP page)",
)

ACCOUNT, ORG = "111122223333", "o-exampleorgid"
ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _req(action="s3:GetObject", context=None, in_org=True, **kw) -> Request:
    return Request(action=action, principal_arn=f"arn:aws:iam::{ACCOUNT}:role/analyst", principal_account=ACCOUNT,
                   region="ca-central-1", context=dict(context or {}), resource_in_org=in_org, **kw)


def _deny(**stmt) -> dict:
    return {"Statement": [{"Effect": "Deny", "Resource": "*", **stmt}]}


@dataclass(frozen=True)
class Case:
    id: str
    url: str
    quote: str
    request: Request
    allowed: bool
    scps: list = field(default_factory=lambda: [[ALLOW_ALL]])
    rcps: list = field(default_factory=list)
    endpoint: list = field(default_factory=list)


CASES = (
    Case("SCP-1a", SCP_EVAL, "there must be an explicit Allow statement at every level from the root through each OU "
         "in the direct path to the account (including the target account itself)",
         _req(), True, scps=[[ALLOW_ALL], [ALLOW_ALL], [ALLOW_ALL]]),
    Case("SCP-1b", SCP_EVAL, "If an allow statement is not present in the SCPs at any of the levels such as Root, "
         "Production OU or Account B, the access is denied.",
         _req(), False, scps=[[ALLOW_ALL], [{"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}],
                              [ALLOW_ALL]]),
    Case("SCP-2", SCP_EVAL, "any SCP from the root through each OU in the direct path to the account (including the "
         "target account itself) can deny that permission",
         _req(), False, scps=[[ALLOW_ALL], [ALLOW_ALL], [ALLOW_ALL, _deny(Action="s3:*")]]),
    Case("EVAL-1", DENY_ALLOW, "If the enforcement code finds even one explicit deny that applies, the enforcement "
         "code returns a final decision of Deny.",
         _req(), False, scps=[[ALLOW_ALL, _deny(Action="s3:GetObject")]]),
    Case("RCP-2a", RCP_PAGE, "RCPs affect only resources that are managed by accounts that are part of the "
         "organization which has attached the RCPs.",
         _req(), False, rcps=[[_deny(Principal="*", Action="s3:*")]]),
    Case("RCP-2b", RCP_PAGE, "They don't affect resources from accounts outside the organization.",
         _req(in_org=False), True, rcps=[[_deny(Principal="*", Action="s3:*")]]),
    Case("RCP-7", RCP_EVAL, "any RCP from the root through each OU in the direct path to the account (including the "
         "target account itself) can deny that permission",
         _req(), False, rcps=[[], [], [_deny(Principal="*", Action="s3:GetObject")]]),
    Case("RCP-6", RCP_EVAL, "This default RCP allows all principals and actions access to pass through RCP "
         "evaluation ... This AWS managed policy does not grant access.",
         _req(), False, scps=[[{"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}]],
         rcps=[[{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}]]),
    Case("COND-a", CONDITIONS, "If the key that you specify in a policy condition is not present in the request "
         "context, the values do not match and the condition is false.",
         _req(), True, scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}})]]),
    Case("COND-b", CONDITIONS, "If the policy condition requires that the key is not matched, such as StringNotLike "
         "or ArnNotLike, and the right key is not present, the condition is true.",
         _req(), False, scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"StringNotLike": {"aws:SourceVpce": "vpce-*"}})]]),
    Case("COND-b2", CONDITIONS, "such as StringNotLike or ArnNotLike, and the right key is not present, the "
         "condition is true",
         _req(context={"aws:SourceArn": None}), False,
         scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"ArnNotLike": {"aws:SourceArn": "arn:aws:s3:::x"}})]]),
    Case("COND-c", CONDITIONS, "If you are using an \"Effect\": \"Deny\" element with a negated condition operator "
         "like StringNotEqualsIfExists, the request is still denied even if the condition key is not present.",
         _req(), False,
         scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"StringNotEqualsIfExists": {"aws:ResourceOrgID": ORG}})]]),
    Case("COND-c2", CONDITIONS, "If the key is not present, evaluate the condition element as true.",
         _req(), False,
         scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"StringEqualsIfExists": {"aws:ResourceOrgID": ORG}})]]),
    Case("COND-d", CONDITIONS, "use either true (the key doesn't exist — it is null) or false (the key exists and its "
         "value is not null)",
         _req(), False, scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"Null": {"aws:SourceVpce": "true"}})]]),
    Case("COND-d2", CONDITIONS, "false (the key exists and its value is not null)",
         _req(context={"aws:SourceVpce": "vpce-1"}), True,
         scps=[[ALLOW_ALL, _deny(Action="s3:*", Condition={"Null": {"aws:SourceVpce": "true"}})]]),
    Case("NA-1", NOTACTION, "to deny access to all of the listed resources except for the actions specified in the "
         "NotAction element",
         _req(), False, scps=[[ALLOW_ALL, _deny(NotAction="iam:*")]]),
    Case("NA-1b", NOTACTION, "Actions specified in NotAction are not impacted by the Allow or Deny effect in a "
         "policy statement.",
         _req(action="iam:ListRoles"), True, scps=[[ALLOW_ALL, _deny(NotAction="iam:*")]]),
    Case("VPCE-1", ENDPOINTS, "The default endpoint policy grants full access to the endpoint.",
         _req(context={"aws:SourceVpce": "vpce-1"}), True,
         endpoint=[{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}]),
)


def run() -> dict:
    """Every case through the evaluator: {"result", "cases": [...], "failed": [...]}."""
    cases, failed = [], []
    for case in CASES:
        # COND-b2 states the key as absent: drop context keys given as None.
        request = Request(**{**case.request.__dict__,
                             "context": {k: v for k, v in case.request.context.items() if v is not None}})
        decision = evaluate(request, case.scps, case.rcps, case.endpoint)
        ok = decision.allowed == case.allowed
        cases.append({"id": case.id, "url": case.url, "expected": "allow" if case.allowed else "deny",
                      "got": "allow" if decision.allowed else "deny", "ok": ok})
        if not ok:
            failed.append(f"{case.id}: AWS documents {'allow' if case.allowed else 'deny'}, the evaluator gives "
                          f"{decision.reason} ({case.url})")
    return {"result": "fail" if failed else "pass", "checked": CHECKED, "cases": cases, "failed": failed,
            "undocumented": list(UNDOCUMENTED), "not_modelled": list(NOT_MODELLED)}
