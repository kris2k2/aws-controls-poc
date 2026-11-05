"""Assess: turn a capability profile into candidate controls (`findings.json`).

ADR-0007. Assess writes findings from four sources, in this order, and records
where every candidate came from in `assessment.json`:

1. **The organization baseline** (`onboard/baseline/organization.json`): the
   shared `ORG-*` candidates, reviewed once and reused for every service
   through the control registry.
2. **Derived from the request:** the preview restriction (`<CODE>-C-01`), the
   service's actions only in the authorized preview accounts until promotion.
3. **The AWS Control Catalog:** each Security Hub control that governs the
   service's resources becomes a detective candidate (`<CODE>-SH-<n>` for
   Security Hub control `<Service>.<n>`) with AWS's severity and AWS's
   NIST SP 800-53 Rev 5 mappings, each resolved in the pinned catalog
   (ADR-0002). A control without such a mapping isn't imported; it is listed
   for the analyst with the reason.
4. **The analyst overlay** (optional, `findings-overlay/v1`): the candidates
   that need judgment (a service's own containment, rubric-rated supervision
   and hardening) and the service's dependencies. The overlay can add
   candidates, never replace or drop the others.

The result is checked with `controls.load_findings` like any findings file,
so Select, Generate, Verify and Review treat it no differently. No model is
called; given the same inputs (and a snapshot of the catalog) the output is
the same.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from . import __version__
from .catalog import FRAMEWORK as NIST, summary as catalog_summary
from .control_catalog import HOST, ControlCatalog
from .controls import FINDINGS_SCHEMA, FindingsError, load_findings
from .model import Severity
from .request import OnboardingRequest
from .resolve import normalize

SCHEMA = "assessment/v1"
OVERLAY_SCHEMA = "findings-overlay/v1"
BASELINE_SCHEMA = "organization-baseline/v1"
BASELINE = Path(__file__).resolve().parent / "baseline" / "organization.json"
SECURITY_HUB = "AWS::SecurityHub::SecurityControl"

# Service key -> control ID code, where the first letters of the name don't
# make one (the ID pattern needs 2 to 5 letters).
CODES: dict[str, str] = {}
# Service key -> CloudFormation namespace (AWS::<Namespace>::...), where it isn't
# the service key itself. Security Hub controls are matched on the resources
# they govern.
CFN_NAMESPACES: dict[str, str] = {}

# How the Control Catalog names NIST SP 800-53 Rev 5 in a framework mapping.
# The exact spelling isn't documented; this accepts the plausible spellings,
# and every framework name a run sees is recorded in assessment.json, so the
# first live run shows which one AWS uses (ADR-0007).
NIST_R5 = re.compile(r"^NIST[-_ .]*(SP[-_ .]*)?800[-_ .]*53[-_ .]*(r|rev|revision)[-_ .]*5$", re.IGNORECASE)
_NIST_ITEM = re.compile(r"^([A-Za-z]{2})-(\d{1,2})(?:\s*\((\d{1,2})\)|\.(\d{1,2}))?$")
_SH_ID = re.compile(r"^([A-Za-z0-9]+)\.(\d{1,3})$")
SEVERITIES = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}

_NOT_APPLICABLE = {
    "boundary": "a detective control, not a delegated-role control",
    "rcp": "a detective control from the Control Catalog",
    "vpce": "not a network-path control",
    "cloudtrail": "configuration state, evaluated by the Security Hub control",
    "scp": "a detective control from the Control Catalog; Assess derives no preventive form from it",
    "sentinel": "the Control Catalog gives no plan-time check; the analyst overlay can add one",
}


class AssessError(ValueError):
    pass


def _sha256(document) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def service_key(profile: dict) -> str:
    """The prefix the findings are for: the service's own name if it is one of its prefixes."""
    prefixes = profile.get("prefixes") or []
    if not prefixes:
        raise AssessError("capability-profile.json lists no prefixes: run resolve first")
    base = normalize(profile.get("service", ""))
    return base if base in prefixes else prefixes[0]


def control_code(key: str) -> str:
    code = CODES.get(key) or "".join(ch for ch in key.upper() if ch.isalpha())[:3]
    if not 2 <= len(code) <= 5:
        raise AssessError(f"no control ID code for {key!r}: add it to onboard.assess.CODES")
    return code


def display_name(service: str) -> str:
    return re.sub(r"^(amazon|aws)\s+", "", service.strip(), flags=re.IGNORECASE)


def load_baseline(path: Path = BASELINE) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AssessError(f"cannot read the organization baseline {path}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != BASELINE_SCHEMA:
        raise AssessError(f"{path} is not a {BASELINE_SCHEMA} document")
    if not all(isinstance(c, dict) and str(c.get("control_id", "")).startswith("ORG-") and c.get("shared")
               for c in doc.get("candidates", [])):
        raise AssessError(f"{path}: every baseline candidate must be a shared ORG-* control")
    return doc


def check_overlay(overlay: dict | None, key: str) -> dict:
    if overlay is None:
        return {"candidates": [], "dependencies": []}
    if not isinstance(overlay, dict) or overlay.get("schema") != OVERLAY_SCHEMA:
        raise AssessError(f"the analyst overlay must be an object with schema {OVERLAY_SCHEMA}")
    if overlay.get("service") != key:
        raise AssessError(f"the analyst overlay is for {overlay.get('service')!r}, not {key!r}")
    for c in overlay.get("candidates", []):
        cid = c.get("control_id", "") if isinstance(c, dict) else ""
        if cid.startswith("ORG-"):
            raise AssessError(f"the analyst overlay can't define {cid}: shared controls come only from the "
                              "organization baseline, which every service reuses")
    return overlay


# ---------------------------------------------------------------- derived


def preview_candidate(code: str, name: str, prefixes: list[str]) -> dict:
    """The Private Preview restriction: the service only in the authorized preview accounts.

    Applies until Private Preview, so the next tier's selection lists it as
    retired. Its property is in the service's security spec.
    """
    return {
        "control_id": f"{code}-C-01",
        "title": f"{name} only in the authorized preview accounts",
        "class": "Containment",
        "objective": "preview-accounts",
        "severity": "High",
        "severity_source": "rubric",
        "until_tier": "Private Preview",
        "citations": [{"anchor": "Private Preview authorization", "retrieved": "2026-10-30",
                       "url": "spec:AWS Service Onboarding Tool Spec v0.1", "verification": "not-run"}],
        "framework_refs": [
            {"catalog_version": "5.2.0", "framework": NIST, "id": "ac-3", "mapping_type": "inferred",
             "verification": "not-run", "version": "r5"},
            {"catalog_version": "5.2.0", "framework": NIST, "id": "cm-7", "mapping_type": "inferred",
             "verification": "not-run", "version": "r5"},
        ],
        "guardrail": {"type": "scp", "actions": [f"{p}:*" for p in prefixes],
                      "conditions": {"StringNotEquals": {"aws:PrincipalAccount": "${preview_accounts}"}}},
        "implementations": {
            "boundary": {"status": "not_applicable", "reason": "not a delegated-role control"},
            "cloudtrail": {"status": "planned",
                           "detects": f"denied {name} calls from accounts not on the preview list"},
            "config": {"status": "not_applicable", "reason": "not configuration state"},
            "rcp": {"status": "not_applicable", "reason": "not a resource-side control"},
            "scp": {"status": "planned"},
            "sentinel": {"status": "not_expressible", "reason": "the plan doesn't reliably carry the target account"},
            "vpce": {"status": "not_applicable", "reason": "not a network-path control"},
        },
    }


# ---------------------------------------------------------------- Control Catalog


def _governs(control: dict, namespace: str) -> bool:
    governed = control.get("GovernedResources") or []
    if not isinstance(governed, list):
        return False
    if governed:
        return any(isinstance(r, str) and r.count("::") == 2 and r.split("::")[1].lower() == namespace.lower()
                   for r in governed)
    # No resource types given: fall back to the Security Hub ID's prefix.
    m = _SH_ID.match(((control.get("Implementation") or {}).get("Identifier")) or "")
    return bool(m) and m.group(1).lower() == namespace.lower()


def nist_id(item: str) -> str | None:
    """'AC-2(1)', 'AC-2 (1)' or 'AC-2.1' -> 'ac-2.1' (catalog form)."""
    m = _NIST_ITEM.match(item.strip())
    if not m:
        return None
    enhancement = m.group(3) or m.group(4)
    return f"{m.group(1).lower()}-{int(m.group(2))}" + (f".{int(enhancement)}" if enhancement else "")


def nist_refs(mappings: list[dict], index: dict, verification: str) -> tuple[list[dict], list[str], set[str]]:
    """Return (refs, problems, framework names seen) from a control's FRAMEWORK mappings."""
    refs, problems, seen = {}, [], set()
    for mapping in mappings:
        framework = ((mapping or {}).get("Mapping") or {}).get("Framework") or {}
        name, item = framework.get("Name"), framework.get("Item")
        if mapping.get("MappingType") != "FRAMEWORK" or not isinstance(name, str) or not isinstance(item, str):
            continue
        seen.add(name)
        if not NIST_R5.match(name):
            continue
        cid = nist_id(item)
        entry = index["controls"].get(cid) if cid else None
        if entry is None:
            problems.append(f"{item!r} ({name}) is not a control in NIST SP 800-53 {index['version']}")
        elif entry["withdrawn"]:
            problems.append(f"{item!r} ({name}) is withdrawn in NIST SP 800-53 {index['version']}")
        else:
            refs[cid] = {"framework": NIST, "version": "r5", "id": cid, "catalog_version": index["version"],
                         "mapping_type": "aws-mapped", "verification": verification}
    return [refs[k] for k in sorted(refs)], problems, seen


def security_hub_candidates(catalog: ControlCatalog, key: str, code: str, index: dict,
                            source: dict) -> tuple[list[dict], dict]:
    """Candidates from the Security Hub controls that govern the service, and a report of what was skipped."""
    namespace = CFN_NAMESPACES.get(key, key)
    # A synthetic snapshot proves the code path, not AWS's content.
    verification = "unverifiable" if source.get("synthetic") else "verified"
    candidates, skipped, frameworks = [], [], set()
    for control in catalog.list_controls(SECURITY_HUB):
        if not isinstance(control, dict) or not _governs(control, namespace):
            continue
        arn, name = control.get("Arn"), control.get("Name")
        ident = (control.get("Implementation") or {}).get("Identifier") or ""
        m = _SH_ID.match(ident)
        why = None
        if not isinstance(arn, str) or not isinstance(name, str) or not name.strip():
            why = "no ARN or name"
        elif not m:
            why = f"Security Hub identifier {ident!r} isn't <Service>.<number>"
        elif control.get("Behavior") != "DETECTIVE":
            why = f"behavior {control.get('Behavior')!r}, not DETECTIVE"
        elif control.get("Severity") not in SEVERITIES:
            why = f"severity {control.get('Severity')!r} isn't one of {', '.join(SEVERITIES)}"
        if why:
            skipped.append({"arn": arn, "identifier": ident or None, "reason": why})
            continue
        refs, problems, seen = nist_refs(catalog.framework_mappings(arn), index, verification)
        frameworks |= seen
        if not refs:
            skipped.append({"arn": arn, "identifier": ident, "reason": "no NIST SP 800-53 Rev 5 mapping that "
                            "resolves in the pinned catalog; an analyst can add it in the overlay",
                            "problems": problems, "frameworks_seen": sorted(seen)})
            continue
        severity = SEVERITIES[control["Severity"]]
        impls = {p: {"status": "not_applicable", "reason": r} for p, r in _NOT_APPLICABLE.items()}
        impls["config"] = {"status": "planned", "rule": f"Security Hub control {ident} (AWS-managed)"}
        candidates.append({
            "control_id": f"{code}-SH-{int(m.group(2)):02d}",
            "title": name.strip(),
            "class": "Supervision" if severity >= Severity.MEDIUM else "Hardening",
            "objective": f"security-hub {ident}",
            "severity": severity.value,
            "severity_source": "control-catalog",
            "security_hub_id": ident,
            "control_catalog_arn": arn,
            "citations": [{"url": f"https://{HOST}/list-controls", "retrieved": source.get("retrieved") or "",
                           "anchor": f"{arn} {ident}: {name.strip()} (Severity {control['Severity']})",
                           "verification": verification}],
            "framework_refs": refs,
            "implementations": impls,
            **({"mapping_problems": problems} if problems else {}),
        })
    ids = [c["control_id"] for c in candidates]
    duplicated = sorted({i for i in ids if ids.count(i) > 1})
    if duplicated:
        raise AssessError(f"Security Hub controls map to the same ID: {', '.join(duplicated)}")
    candidates.sort(key=lambda c: c["control_id"])
    return candidates, {"namespace": namespace, "skipped": skipped, "frameworks_seen": sorted(frameworks)}


# ---------------------------------------------------------------- assess


def assess(request: OnboardingRequest, profile: dict, catalog: ControlCatalog, nist_index: dict, *,
           overlay: dict | None = None, baseline: dict | None = None, source: dict | None = None) -> dict:
    """Return {"findings": findings/v1, "assessment": assessment/v1}.

    `source` describes where the catalog responses came from (live or a
    snapshot: retrieved, region, synthetic) and is recorded as is.
    """
    source = dict(source or {})
    key = service_key(profile)
    code = control_code(key)
    baseline = baseline if baseline is not None else load_baseline()
    overlay = check_overlay(overlay, key)
    prefixes = list(profile["prefixes"])

    org = [copy.deepcopy(c) for c in baseline["candidates"]]
    derived = [preview_candidate(code, display_name(request.service), prefixes)]
    imported, report = security_hub_candidates(catalog, key, code, nist_index, source)
    analyst = [copy.deepcopy(c) for c in overlay.get("candidates", [])]

    origin = {}
    for name, group in (("organization-baseline", org), ("derived", derived),
                        ("control-catalog", imported), ("analyst-overlay", analyst)):
        for c in group:
            cid = c.get("control_id")
            if cid in origin:
                raise AssessError(f"{cid} comes from both the {origin[cid]} and the {name}; "
                                  "the overlay can add controls, not replace them")
            origin[cid] = name

    findings = {
        "schema": FINDINGS_SCHEMA,
        "service": key,
        "assessed": {"tool_version": __version__, "by": "onboard assess (ADR-0007)",
                     "report": "assessment.json"},
        "candidates": org + derived + analyst + imported,
        "dependencies": copy.deepcopy(overlay.get("dependencies", [])),
    }
    try:
        load_findings(findings)
    except FindingsError as exc:
        raise AssessError(f"the assessed findings don't validate:\n  - " + "\n  - ".join(exc.problems)) from exc

    assessment = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": key,
        "control_code": code,
        "maturity_tier": request.maturity_tier.value,
        "findings_sha256": _sha256(findings),
        "sources": {
            "organization_baseline": {"sha256": _sha256(baseline), "status": baseline.get("status"),
                                      "candidates": len(org)},
            "control_catalog": {"host": HOST, "implementation_type": SECURITY_HUB, **source,
                                "namespace": report["namespace"], "imported": len(imported),
                                "skipped": report["skipped"], "frameworks_seen": report["frameworks_seen"],
                                "nist_framework_names": sorted(n for n in report["frameworks_seen"]
                                                               if NIST_R5.match(n))},
            "analyst_overlay": ({"sha256": _sha256(overlay), "candidates": len(analyst)}
                                if analyst or overlay.get("dependencies") else None),
            "nist_catalog": catalog_summary(nist_index),
        },
        "candidates": [{"control_id": c["control_id"], "class": c["class"], "severity": c["severity"],
                        "severity_source": c["severity_source"], "origin": origin[c["control_id"]]}
                       for c in findings["candidates"]],
        "counts": {name: sum(o == name for o in origin.values())
                   for name in ("organization-baseline", "derived", "control-catalog", "analyst-overlay")},
        # Assess makes no judgment calls; these are left to the analyst overlay.
        "for_the_analyst": [
            "the service's own containment controls (excluded capabilities, data egress, network path)",
            "supervision and hardening that Security Hub doesn't cover, and Config rules for them",
            "the Security Hub controls listed under sources.control_catalog.skipped",
            "the service's dependencies (KMS, S3, Glue, iam:PassRole, ...)",
        ],
    }
    return {"findings": findings, "assessment": assessment}
