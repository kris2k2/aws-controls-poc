"""Generate: render control records into artifacts.

It renders the guardrail artifacts: SCP, RCP and VPC endpoint policy
statements, plus the service's allow-list entry; and the detective and
plan-time artifacts (Config rules, CloudTrail detections, Sentinel policies)
that a control record defines in structured form (ADR-0009, `detective.py`).
The endpoint policy goes on every VPC endpoint the organization runs: a base
allow, so the endpoint stops only what its guardrails deny, then those
denies. A guardrail applies to every resource unless it names `resources`
(ARN patterns or ${parameters}). A detective platform
without a structured definition, and every permissions boundary, is reported
as pending, not silently skipped.

What each mode does to a guardrail (spec, "What each mode does per artifact"):
Enforce deploys the deny with an exemption for break-glass principals only
(none when the guardrail sets `break_glass_exempt: false`, as the data
perimeter does);
Enforce with override deploys it only when approved exceptions exist, naming
them in the condition; Advise and Report deploy no guardrail.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re

from . import __version__, detective
from .controls import GUARDRAIL_TYPES, PLATFORMS
from .model import Mode
from .request import OnboardingRequest

SCHEMA = "generation/v1"
ENDPOINT_BASE_ALLOW = {"Sid": "AllowUnlessDenied", "Effect": "Allow", "Principal": "*", "Action": ["*"],
                       "Resource": "*"}
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
        "trusted_resource_accounts": list(request.trusted_resource_accounts),
        # Every role some guardrail exempts. Exemptions hold only while nobody
        # else can create, change or pass these roles (ORG-C-04).
        "protected_roles": sorted(set(request.break_glass_principals)
                                  | {e.principal for e in request.exceptions}),
    }
    # The same roles by name, as CloudTrail records them in requestParameters.roleName.
    params["protected_role_names"] = sorted({arn.rsplit("/", 1)[-1] for arn in params["protected_roles"]})
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
    exempt = list(request.break_glass_principals) if guardrail.get("break_glass_exempt", True) else []
    if mode is Mode.ENFORCE_WITH_OVERRIDE:
        approved = [e.principal for e in request.exceptions if e.control_id == cid]
        if not approved:
            return None, "Enforce with override: no approved exceptions, so no guardrail"
        exempt += approved

    resources = guardrail.get("resources", ["*"])
    for value in resources:
        m = _PARAMETER.match(value)
        if m and m.group(1) in params and not params[m.group(1)]:
            # A deny on no resources is a no-op: say so rather than fail.
            return None, f"{m.group(1)} is empty, so the guardrail applies to no resources"
    resources = _resolve(resources, params, cid)

    # A condition on an optional parameter the request leaves empty is dropped:
    # an empty exception list means no exception, not a broken guardrail.
    optional = set(guardrail.get("optional_parameters", []))

    def empty_optional(value) -> bool:
        m = _PARAMETER.match(value) if isinstance(value, str) else None
        return bool(m) and m.group(1) in optional and not params.get(m.group(1))

    conditions = {op: {k: _resolve(v, params, cid) for k, v in keys.items() if not empty_optional(v)}
                  for op, keys in copy.deepcopy(guardrail.get("conditions", {})).items()}
    conditions = {op: keys for op, keys in conditions.items() if keys}
    _exempt(conditions, exempt)
    stmt = {"Sid": cid.replace("-", ""), "Effect": "Deny"}
    if guardrail["type"] in ("rcp", "vpce"):
        stmt["Principal"] = "*"
    if "actions" in guardrail:
        stmt["Action"] = guardrail["actions"]
    else:
        stmt["NotAction"] = guardrail["not_actions"]
    stmt["Resource"] = resources if len(resources) > 1 else resources[0]
    if conditions:
        stmt["Condition"] = conditions
    return stmt, "generated"


def policy_size(policy: dict) -> int:
    return len(json.dumps(policy, separators=(",", ":")))


def _detective(platform: str, record: dict, impl: dict, params: dict, artifacts: dict, levels: dict) -> dict:
    """Render one detective or plan-time artifact into `artifacts`; return its status."""
    try:
        if platform == "config":
            path, text = detective.render_config(record, impl)
        elif platform == "cloudtrail":
            rendered = detective.render_detection(record, impl, params)
            if rendered is None:
                empty = ", ".join(sorted(impl.get("optional_parameters", [])))
                return {"status": "not_deployed", "reason": f"{empty} is empty, so there is nothing to detect"}
            path, text = rendered
        else:
            path, text, level = detective.render_sentinel(record, impl)
            levels[path.rsplit("/", 1)[-1]] = level
    except detective.DetectiveError as exc:
        raise GenerateError(str(exc)) from exc
    artifacts[path] = text
    return {"status": "generated", "file": path}


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate(findings: dict, controls: dict[str, dict], request: OnboardingRequest) -> dict:
    """Return {"policies": {name: document}, "artifacts": {path: text}, "report": generation report}.

    `artifacts` are the detective and plan-time files, by their path in the run directory."""
    service = findings["service"]
    params = parameters(request, service)
    # Shared (registry) controls go to organization-wide policies; Compose places both.
    statements: dict[tuple[str, bool], list] = {(t, s): [] for t in GUARDRAIL_TYPES for s in (False, True)}
    per_control = {}
    artifacts: dict[str, str] = {}
    sentinel_levels: dict[str, str] = {}
    for cid in sorted(controls):
        record = controls[cid]
        status = {}
        for platform in PLATFORMS:
            impl = record["implementations"][platform]
            if impl["status"] != "planned":
                status[platform] = {"status": impl["status"], "reason": impl["reason"]}
            elif platform in GUARDRAIL_TYPES:
                status[platform] = {"status": "pending", "reason": "no guardrail defined yet"}
            elif detective.defined(platform, impl):
                status[platform] = _detective(platform, record, impl, params, artifacts, sentinel_levels)
            elif platform in ("config", "cloudtrail", "sentinel"):
                status[platform] = {"status": "pending",
                                    "reason": f"no structured {platform} definition in the control record yet"}
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
            if gtype == "vpce":  # endpoint policies replace the default full access, so allow first
                stmts = [ENDPOINT_BASE_ALLOW] + stmts
            policies[name] = {"Version": "2012-10-17", "Statement": stmts}
    if sentinel_levels:
        artifacts["detective/sentinel/sentinel.hcl"] = detective.sentinel_config(sentinel_levels)
    endpoints = sorted({e for ids in (request.org_state.get("vpc_endpoints") or {}).values() for e in ids})

    report = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "maturity_tier": request.maturity_tier.value,
        "criticality": request.criticality.value,
        "allow_list_prefixes": prefixes,
        # Attach every vpce-* policy to each of these (and to endpoints created later).
        "vpc_endpoints": endpoints,
        "policies": {name: {"characters": policy_size(doc), "limit": MAX_POLICY_CHARS,
                            "over_limit": policy_size(doc) > MAX_POLICY_CHARS}
                     for name, doc in policies.items()},
        "controls": per_control,
        # Config rules, EventBridge detections and Sentinel policies, by path in the run.
        "detective_artifacts": {path: text_sha256(text) for path, text in sorted(artifacts.items())},
        "detective_notes": list(detective.NOTES) if artifacts else [],
    }
    return {"policies": policies, "artifacts": artifacts, "report": report}
