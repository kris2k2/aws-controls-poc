"""Select: choose the control set for the requested tier and derive each mode.

Reads `findings.json` (from Assess) and the request; writes one control record
per selected control, the registry changes, and `selection.json`, which lists
what was selected, what was left for a later tier, what the checker must
approve, and what the next tier would add.
"""

from __future__ import annotations

import copy
from typing import Mapping

from . import __version__
from .controls import detective_platforms
from .model import (
    DEFAULT_MATRIX, ControlClass, Criticality, Mode, Severity, Tier, escalate, in_scope,
    matrix_changes, mode_by_criticality,
)
from .request import OnboardingRequest

SCHEMA = "selection/v1"


class SelectError(ValueError):
    pass


def _active(candidate: dict, tier: Tier) -> bool:
    """In scope for the tier, and not retired by an earlier tier's promotion."""
    if not in_scope(ControlClass(candidate["class"]), tier):
        return False
    until = candidate.get("until_tier")
    return until is None or tier <= Tier(until)


def _decision_excludes(candidate: dict, request: OnboardingRequest) -> str | None:
    decision = candidate.get("requires_decision")
    if not decision:
        return None
    value = request.decisions.get(decision["key"])
    if value is None:
        raise SelectError(f"{candidate['control_id']} needs the decision {decision['key']!r} in the request")
    if value != decision["include_when"]:
        return f"decision {decision['key']} = {value}"
    return None


def _all_inferred(candidate: dict) -> bool:
    return all(r["mapping_type"] == "inferred" for r in candidate["framework_refs"])


def select(findings: dict, request: OnboardingRequest,
           matrix: Mapping[Severity, Mapping[Criticality, Mode]] = DEFAULT_MATRIX) -> dict:
    """Return {"selection": ..., "controls": {id: record}, "registry": ...}."""
    tier, criticality = request.maturity_tier, request.criticality
    registry = copy.deepcopy(request.control_registry or {"controls": {}})
    registry.setdefault("controls", {})
    service = findings["service"]

    controls, excluded, later, retired, checker_items, registry_changes = {}, [], [], [], [], []
    for cand in findings["candidates"]:
        cid, cls = cand["control_id"], ControlClass(cand["class"])
        if not in_scope(cls, tier):
            later.append(cid)
            continue
        if not _active(cand, tier):
            retired.append({"control_id": cid, "reason": f"applies until {cand['until_tier']}"})
            continue
        reason = _decision_excludes(cand, request)
        if reason:
            excluded.append({"control_id": cid, "reason": reason})
            continue

        severity = Severity(cand["severity"])
        modes = mode_by_criticality(severity, cls, tier, matrix)
        if cand.get("shared"):
            entry = registry["controls"].get(cid)
            if entry:
                kept = {c: escalate(modes[c], Mode(entry["mode_by_criticality"][c.value])) for c in Criticality}
                change = "reused" if kept == modes else "reused, mode kept higher"
                modes = kept
            else:
                entry, change = {"mode_by_criticality": {}, "services": []}, "added"
            entry["mode_by_criticality"] = {c.value: m.value for c, m in modes.items()}
            entry["services"] = sorted(set(entry["services"]) | {service})
            registry["controls"][cid] = entry
            registry_changes.append({"control_id": cid, "change": change})

        mode = modes[criticality]
        record = copy.deepcopy(cand)
        record["mode_by_criticality"] = {c.value: m.value for c, m in modes.items()}
        record["mode"] = mode.value
        record["detective_platforms"] = detective_platforms(cand)
        record["approvals"] = {"maker": None, "checker": None}
        controls[cid] = record

        if cand["severity_source"] == "rubric" and severity >= Severity.HIGH:
            checker_items.append({"control_id": cid, "item": f"inferred severity {severity.value}"})
        if mode.enforcing and _all_inferred(cand):
            checker_items.append({"control_id": cid, "item": f"{mode.value} on an inferred control"})

    changes = matrix_changes(matrix)
    checker_items += [{"control_id": None, "item": f"matrix change {c['severity']}/{c['criticality']}"}
                      for c in changes]
    next_tier = None
    if tier is not Tier.HARDENED:
        nxt = list(Tier)[tier.rank + 1]
        next_tier = {"tier": nxt.value,
                     "adds": [c["control_id"] for c in findings["candidates"]
                              if c["control_id"] in later and in_scope(ControlClass(c["class"]), nxt)],
                     "retires": [c["control_id"] for c in findings["candidates"]
                                 if c["control_id"] in controls and c.get("until_tier") == tier.value]}

    counts: dict[str, dict[str, int]] = {"class": {}, "mode": {}, "severity": {}}
    for rec in controls.values():
        for key, value in (("class", rec["class"]), ("mode", rec["mode"]), ("severity", rec["severity"])):
            counts[key][value] = counts[key].get(value, 0) + 1

    selection = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "maturity_tier": tier.value,
        "criticality": criticality.value,
        "criticality_source": request.criticality_source,
        "data_classification": request.data_classification,
        "run_mode": request.run_mode,
        "controls": sorted(controls),
        "counts": counts,
        "excluded_by_decision": excluded,
        "retired": retired,
        "later_tiers": later,
        "next_tier": next_tier,
        "matrix_changes": changes,
        "checker_items": checker_items,
        "registry_changes": registry_changes,
    }
    return {"selection": selection, "controls": controls, "registry": registry}
