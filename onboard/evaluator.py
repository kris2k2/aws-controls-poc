"""A local evaluator for organization policies (SCPs and RCPs).

It implements the subset of the documented IAM policy evaluation logic the
generated guardrails use, so Level 1 unit tests can check every statement
against request vectors offline:

- SCPs: an explicit Deny at any level denies. Otherwise an Allow must exist at
  every level from the root to the account (default deny with an allow-list).
- RCPs: an explicit Deny at any level denies; RCPFullAWSAccess is implied.
  RCPs only apply to resources owned by accounts in the organization.
- Action, NotAction and Resource with * and ? wildcards (actions match
  case-insensitively).
- Condition operators listed in `onboard.controls.CONDITION_OPERATORS`, with
  IfExists. Keys absent from the request: negated operators match, positive
  operators don't, IfExists matches.

The spec requires these results to be replayed through the IAM policy
simulator and live calls (evaluator calibration). Until that runs, a pass
here means "as intended", not "proven against AWS".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

_NEGATED = {"StringNotEquals", "StringNotLike", "ArnNotLike"}


@dataclass(frozen=True)
class Request:
    action: str
    principal_arn: str
    principal_account: str
    region: str
    resource: str = "*"
    context: dict = field(default_factory=dict)
    resource_in_org: bool = True

    def keys(self) -> dict:
        """The request context, global keys included, with lower-case names."""
        base = {
            "aws:principalarn": self.principal_arn,
            "aws:principalaccount": self.principal_account,
            "aws:requestedregion": self.region,
        }
        base.update({k.lower(): v for k, v in self.context.items()})
        return base


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    statement: str | None = None


@lru_cache(maxsize=1024)
def _glob(pattern: str, ignore_case: bool) -> re.Pattern:
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern)
    return re.compile(f"^{regex}$", re.IGNORECASE if ignore_case else 0)


def _match(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    return bool(_glob(pattern, ignore_case).match(value))


def _list(value) -> list:
    return value if isinstance(value, list) else [value]


def _condition(op: str, key: str, expected, keys: dict) -> bool:
    if_exists = op.endswith("IfExists")
    base = op.removesuffix("IfExists")
    present = key.lower() in keys
    if base == "Null":
        want_absent = str(expected).lower() == "true"
        return present != want_absent
    if not present:
        return if_exists or base in _NEGATED
    actual = [str(v) for v in _list(keys[key.lower()])]
    expected = [str(v) for v in _list(expected)]
    if base == "Bool":
        return any(a.lower() == e.lower() for a in actual for e in expected)
    like = base.endswith("Like")
    hit = any((_match(e, a) if like else a == e) for a in actual for e in expected)
    return not hit if base in _NEGATED else hit


def statement_applies(stmt: dict, req: Request) -> bool:
    if "Action" in stmt:
        if not any(_match(p, req.action, ignore_case=True) for p in _list(stmt["Action"])):
            return False
    elif any(_match(p, req.action, ignore_case=True) for p in _list(stmt.get("NotAction", []))):
        return False
    if not any(_match(p, req.resource) for p in _list(stmt.get("Resource", "*"))):
        return False
    keys = req.keys()
    return all(_condition(op, key, value, keys)
               for op, conditions in stmt.get("Condition", {}).items()
               for key, value in conditions.items())


def _statements(policies: list[dict]):
    for policy in policies:
        yield from _list(policy.get("Statement", []))


def evaluate(req: Request, scp_levels: list[list[dict]], rcp_levels: list[list[dict]] = ()) -> Decision:
    """Decide whether organization policies permit the request.

    `scp_levels` and `rcp_levels` hold the policies attached at each level,
    root first and account last.
    """
    for level in scp_levels:
        for stmt in _statements(level):
            if stmt["Effect"] == "Deny" and statement_applies(stmt, req):
                return Decision(False, "explicit deny in an SCP", stmt.get("Sid"))
    if req.resource_in_org:
        for level in rcp_levels:
            for stmt in _statements(level):
                if stmt["Effect"] == "Deny" and statement_applies(stmt, req):
                    return Decision(False, "explicit deny in an RCP", stmt.get("Sid"))
    for depth, level in enumerate(scp_levels):
        if not any(stmt["Effect"] == "Allow" and statement_applies(stmt, req) for stmt in _statements(level)):
            return Decision(False, f"no SCP allows it at level {depth}")
    return Decision(True, "allowed by organization policies")
