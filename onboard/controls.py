"""Findings and control records: the artifact-neutral definition of each control.

Assess writes `findings.json`, one candidate control per entry; Select turns the
candidates in scope into control records. Every artifact is generated from a
control record, so the shape is checked strictly here and nowhere else.
"""

from __future__ import annotations

import re
from typing import Any

from .catalog import CATALOG_ID, FRAMEWORK as NIST
from .model import ControlClass, Severity, Tier

FINDINGS_SCHEMA = "findings/v1"
PLATFORMS = ("scp", "rcp", "boundary", "config", "cloudtrail", "sentinel")
DETECTIVE_PLATFORMS = ("config", "cloudtrail")
STATUSES = ("planned", "not_expressible", "not_applicable")
SEVERITY_SOURCES = ("security-hub", "rubric")
MAPPING_TYPES = ("aws-mapped", "publisher-mapped", "inferred")
VERIFICATIONS = ("verified", "unverifiable", "contradicted", "not-run")
GUARDRAIL_TYPES = ("scp", "rcp")
CONDITION_OPERATORS = (
    "StringEquals", "StringNotEquals", "StringLike", "StringNotLike",
    "StringEqualsIfExists", "StringNotEqualsIfExists", "StringLikeIfExists", "StringNotLikeIfExists",
    "ArnLike", "ArnNotLike", "ArnLikeIfExists", "ArnNotLikeIfExists",
    "Bool", "BoolIfExists", "Null",
)
_CONTROL_ID = re.compile(r"^[A-Z]{2,5}-[A-Z]{1,3}-\d{2}$")
_PARAMETER = re.compile(r"^\$\{([a-z_]+)\}$")


class FindingsError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid findings:\n  - " + "\n  - ".join(problems))


def parameters_of(guardrail: dict) -> set[str]:
    """Names of the ${parameters} a guardrail's conditions refer to."""
    names = set()
    for keys in guardrail.get("conditions", {}).values():
        for value in keys.values():
            m = _PARAMETER.match(value) if isinstance(value, str) else None
            if m:
                names.add(m.group(1))
    return names


def _check_guardrail(g: Any, where: str, problems: list[str]) -> None:
    if not isinstance(g, dict):
        problems.append(f"{where}.guardrail must be an object")
        return
    if g.get("type") not in GUARDRAIL_TYPES:
        problems.append(f"{where}.guardrail.type must be one of {', '.join(GUARDRAIL_TYPES)}")
    has_actions, has_not = "actions" in g, "not_actions" in g
    if has_actions == has_not:
        problems.append(f"{where}.guardrail needs exactly one of actions or not_actions")
    for key in ("actions", "not_actions"):
        if key in g and (not isinstance(g[key], list) or not g[key]
                         or not all(isinstance(a, str) and ":" in a for a in g[key])):
            problems.append(f"{where}.guardrail.{key} must be a list of prefix:Action strings")
    conditions = g.get("conditions", {})
    if not isinstance(conditions, dict):
        problems.append(f"{where}.guardrail.conditions must be an object")
        return
    for op, keys in conditions.items():
        if op not in CONDITION_OPERATORS:
            problems.append(f"{where}.guardrail uses unsupported condition operator {op}")
        elif not isinstance(keys, dict) or not all(isinstance(v, (str, list)) for v in keys.values()):
            problems.append(f"{where}.guardrail.conditions.{op} must map keys to a value or list")


def check_candidate(c: Any, where: str, problems: list[str]) -> None:
    if not isinstance(c, dict):
        problems.append(f"{where} must be an object")
        return
    cid = c.get("control_id")
    if not isinstance(cid, str) or not _CONTROL_ID.match(cid):
        problems.append(f"{where}.control_id must look like ATH-C-01")
    for name in ("title", "objective"):
        if not isinstance(c.get(name), str) or not c[name].strip():
            problems.append(f"{where}.{name} is required")
    for name, cls in (("class", ControlClass), ("severity", Severity)):
        try:
            cls(c.get(name))
        except ValueError:
            problems.append(f"{where}.{name} must be one of {', '.join(m.value for m in cls)}")
    if c.get("severity_source") not in SEVERITY_SOURCES:
        problems.append(f"{where}.severity_source must be one of {', '.join(SEVERITY_SOURCES)}")
    if c.get("until_tier") is not None:
        try:
            Tier(c["until_tier"])
        except ValueError:
            problems.append(f"{where}.until_tier must be a maturity tier")

    refs = c.get("framework_refs")
    if not isinstance(refs, list) or not refs:
        problems.append(f"{where}.framework_refs needs at least one entry")
        refs = []
    for i, ref in enumerate(refs):
        if not isinstance(ref, dict) or not all(isinstance(ref.get(k), str) for k in ("framework", "version", "id")):
            problems.append(f"{where}.framework_refs[{i}] needs framework, version and id")
        elif ref.get("mapping_type") not in MAPPING_TYPES:
            problems.append(f"{where}.framework_refs[{i}].mapping_type must be one of {', '.join(MAPPING_TYPES)}")
        elif ref.get("verification") not in VERIFICATIONS:
            problems.append(f"{where}.framework_refs[{i}].verification must be one of {', '.join(VERIFICATIONS)}")
        elif ref["framework"] == NIST and (not CATALOG_ID.match(ref["id"])
                                           or not isinstance(ref.get("catalog_version"), str)):
            # Catalog form (ac-3, ac-2.1) plus the catalog version, so Select can resolve it.
            problems.append(f"{where}.framework_refs[{i}] needs a NIST catalog id (like ac-3) and catalog_version")
    if refs and not any(isinstance(r, dict) and r.get("framework") == NIST for r in refs):
        problems.append(f"{where}.framework_refs needs at least one {NIST} reference (the join key)")

    impls = c.get("implementations")
    if not isinstance(impls, dict) or set(impls) != set(PLATFORMS):
        problems.append(f"{where}.implementations must have exactly {', '.join(PLATFORMS)}")
    else:
        for platform, impl in impls.items():
            if not isinstance(impl, dict) or impl.get("status") not in STATUSES:
                problems.append(f"{where}.implementations.{platform}.status must be one of {', '.join(STATUSES)}")
            elif impl["status"] != "planned" and not impl.get("reason"):
                problems.append(f"{where}.implementations.{platform} needs a reason when not planned")
        if "guardrail" in c:
            gtype = c["guardrail"].get("type") if isinstance(c["guardrail"], dict) else None
            if gtype in GUARDRAIL_TYPES and impls.get(gtype, {}).get("status") != "planned":
                problems.append(f"{where} has a {gtype} guardrail but implementations.{gtype} is not planned")
    if "guardrail" in c:
        _check_guardrail(c["guardrail"], where, problems)

    decision = c.get("requires_decision")
    if decision is not None and (not isinstance(decision, dict)
                                 or not all(isinstance(decision.get(k), str) for k in ("key", "include_when"))):
        problems.append(f"{where}.requires_decision needs key and include_when")


def load_findings(data: Any) -> dict:
    """Validate a findings document; returns it unchanged."""
    if not isinstance(data, dict) or data.get("schema") != FINDINGS_SCHEMA:
        raise FindingsError([f"findings must be an object with schema {FINDINGS_SCHEMA}"])
    problems: list[str] = []
    if not isinstance(data.get("service"), str):
        problems.append("service is required")
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        problems.append("candidates must be a non-empty list")
        candidates = []
    seen = set()
    for i, c in enumerate(candidates):
        check_candidate(c, f"candidates[{i}]", problems)
        cid = c.get("control_id") if isinstance(c, dict) else None
        if cid in seen:
            problems.append(f"candidates[{i}].control_id {cid} is duplicated")
        seen.add(cid)
    deps = data.get("dependencies", [])
    if not isinstance(deps, list) or not all(isinstance(d, dict) and isinstance(d.get("prefix"), str) for d in deps):
        problems.append("dependencies must be a list of {prefix, ...} entries")
    if problems:
        raise FindingsError(problems)
    return data


def detective_platforms(record: dict) -> list[str]:
    impls = record["implementations"]
    return [p for p in DETECTIVE_PLATFORMS if impls[p]["status"] == "planned"]
