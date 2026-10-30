"""Generate: render control records into artifacts.

This slice renders the guardrail artifacts: SCP and RCP statements, plus the
service's allow-list entry. Config rules, CloudTrail detections, Sentinel
policies and boundaries are reported as pending, not silently skipped.

What each mode does to a guardrail (spec, "What each mode does per artifact"):
Enforce deploys the deny with an exemption for break-glass principals only;
Enforce with override deploys it only when approved exceptions exist, naming
them in the condition; Advise and Report deploy no guardrail.
"""

from __future__ import annotations

import copy
import json
import re

from . import __version__
from .controls import GUARDRAIL_TYPES, PLATFORMS
from .model import Mode
from .request import OnboardingRequest

SCHEMA = "generation/v1"
MAX_POLICY_CHARS = 5120  # SCP and RCP size limit, counted without whitespace
_PARAMETER = re.compile(r"^\$\{([a-z_]+)\}$")


class GenerateError(ValueError):
    pass


def parameters(request: OnboardingRequest, service: str) -> dict[str, list[str]]:
    """Values the ${parameters} in guardrails resolve to, from the request."""
    org = request.org_state
    params = {
        "preview_accounts": list(request.preview_accounts),
        "allowed_regions": list(request.allowed_regions),
        "break_glass_principals": list(request.break_glass_principals),
    }
    if isinstance(org.get("organization_id"), str):
        params["org_id"] = [org["organization_id"]]
    endpoints = (org.get("vpc_endpoints") or {}).get(service)
    if isinstance(endpoints, list) and endpoints:
        params["vpce_ids"] = list(endpoints)
    return params


def _resolve(value, params: dict, cid: str):
    if isinstance(value, list):
        return [v for item in value for v in _as_list(_resolve(item, params, cid))]
    m = _PARAMETER.match(value) if isinstance(value, str) else None
    if not m:
        return value
    resolved = params.get(m.group(1))
    if not resolved:
        raise GenerateError(f"{cid} needs the parameter {m.group(1)!r}, which the request doesn't provide")
    return resolved if len(resolved) > 1 else resolved[0]


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _exempt(conditions: dict, principals: list[str]) -> None:
    """Add principals to the statement's ArnNotLike on aws:PrincipalArn."""
    if not principals:
        return
    arn_not_like = conditions.setdefault("ArnNotLike", {})
    existing = _as_list(arn_not_like.get("aws:PrincipalArn", []))
    merged = sorted(set(existing) | set(principals))
    arn_not_like["aws:PrincipalArn"] = merged if len(merged) > 1 else merged[0]


def statement(record: dict, request: OnboardingRequest, params: dict) -> tuple[dict | None, str]:
    """Render a control's guardrail, or return None with the reason it isn't deployed."""
    cid, mode = record["control_id"], Mode(record["mode"])
    guardrail = record["guardrail"]
    if not mode.enforcing:
        return None, f"{mode.value}: guardrails are deployed only for enforcing modes"
    exempt = list(request.break_glass_principals)
    if mode is Mode.ENFORCE_WITH_OVERRIDE:
        approved = [e.principal for e in request.exceptions if e.control_id == cid]
        if not approved:
            return None, "Enforce with override: no approved exceptions, so no guardrail"
        exempt += approved

    conditions = {op: {k: _resolve(v, params, cid) for k, v in keys.items()}
                  for op, keys in copy.deepcopy(guardrail.get("conditions", {})).items()}
    _exempt(conditions, exempt)
    stmt = {"Sid": cid.replace("-", ""), "Effect": "Deny"}
    if guardrail["type"] == "rcp":
        stmt["Principal"] = "*"
    if "actions" in guardrail:
        stmt["Action"] = guardrail["actions"]
    else:
        stmt["NotAction"] = guardrail["not_actions"]
    stmt["Resource"] = "*"
    if conditions:
        stmt["Condition"] = conditions
    return stmt, "generated"


def policy_size(policy: dict) -> int:
    return len(json.dumps(policy, separators=(",", ":")))


def generate(findings: dict, controls: dict[str, dict], request: OnboardingRequest) -> dict:
    """Return {"policies": {name: document}, "report": generation report}."""
    service = findings["service"]
    params = parameters(request, service)
    # Shared (registry) controls go to organization-wide policies; Compose places both.
    statements: dict[tuple[str, bool], list] = {(t, s): [] for t in GUARDRAIL_TYPES for s in (False, True)}
    per_control = {}
    for cid in sorted(controls):
        record = controls[cid]
        status = {}
        for platform in PLATFORMS:
            impl = record["implementations"][platform]
            if impl["status"] != "planned":
                status[platform] = {"status": impl["status"], "reason": impl["reason"]}
            elif platform in GUARDRAIL_TYPES:
                status[platform] = {"status": "pending", "reason": "no guardrail defined yet"}
            else:
                status[platform] = {"status": "pending", "reason": f"{platform} generator not built yet"}
        if "guardrail" in record:
            gtype = record["guardrail"]["type"]
            stmt, reason = statement(record, request, params)
            if stmt:
                statements[(gtype, bool(record.get("shared")))].append(stmt)
                status[gtype] = {"status": "generated", "sid": stmt["Sid"]}
            else:
                status[gtype] = {"status": "not_deployed", "reason": reason}
        per_control[cid] = status

    prefixes = [service] + sorted({d["prefix"] for d in findings.get("dependencies", [])})
    policies = {
        f"scp-{service}-allow": {"Version": "2012-10-17", "Statement": [{
            "Sid": "AllowList", "Effect": "Allow", "Action": [f"{p}:*" for p in prefixes], "Resource": "*"}]},
    }
    for (gtype, shared), stmts in sorted(statements.items()):
        if stmts:
            name = f"{gtype}-{'org' if shared else service}-guardrails"
            policies[name] = {"Version": "2012-10-17", "Statement": stmts}

    report = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "maturity_tier": request.maturity_tier.value,
        "criticality": request.criticality.value,
        "allow_list_prefixes": prefixes,
        "policies": {name: {"characters": policy_size(doc), "limit": MAX_POLICY_CHARS,
                            "over_limit": policy_size(doc) > MAX_POLICY_CHARS}
                     for name, doc in policies.items()},
        "controls": per_control,
    }
    return {"policies": policies, "report": report}
