"""Verify: prove each generated guardrail against its security property (ADR-0006).

For every statement the run deploys, Verify checks, over the whole attacker
model (`onboard/adversary.py`), that it denies exactly what its control's
property in the security spec (`onboard/specs/`) denies: no more (collateral
damage) and no less (a bypass). Then it mutates the statement the ways a
generator bug would and requires every mutant to be caught, so a pass means
the check could have failed. It writes `verification.json`, which the
reviewer recomputes and relies on (ADR-0005).

A proof fails when:
- the statement and its property disagree anywhere in the model (the result
  lists counterexamples);
- a mutant survives that the spec doesn't list as equivalent;
- the control's property, or a statement for an active property, is missing;
- the statement reads a condition key the attacker model doesn't vary;
- for a control that denies a reviewed capability, the API contract has
  actions the action review doesn't classify.

Like ADR-0003's tests, a pass means "holds in the local evaluator's model of
IAM" until the evaluator is calibrated against AWS.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__, adversary
from .adversary import POLICY_TYPE, Facts, ModelError, Space, counterexamples, matches, mutants
from .model import Mode
from .request import OnboardingRequest
from .specs import Spec, SpecError, load_spec

SCHEMA = "verification/v1"
ATTACKER_MODEL_SHA256 = hashlib.sha256(Path(adversary.__file__).read_bytes()).hexdigest()
# Verification is a pure function of its inputs and this code, and the reviewer and the tests
# re-run it often. A test that patches this module must clear the cache (mock.patch.dict).
_CACHE: dict[str, dict] = {}


class VerifyError(ValueError):
    pass


def sha256(document) -> str:
    """The hash of a JSON document in canonical form (sorted keys, no whitespace)."""
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def deny_statements(policies: dict) -> list[tuple[str, dict]]:
    return [(name, stmt) for name, doc in sorted(policies.items())
            for stmt in doc.get("Statement", []) if stmt.get("Effect") == "Deny"]


def contract_actions(profile: dict, service: str) -> list[str]:
    """The service's actions from the capability profile Resolve wrote."""
    for entry in profile.get("services", []):
        if entry.get("prefix") == service:
            return sorted(a["action"] for a in entry.get("actions", []))
    raise VerifyError(f"capability-profile.json has no contract for {service!r}: run resolve into the run")


def active_controls(request: OnboardingRequest, controls: dict) -> dict[str, tuple[str, ...]]:
    """Controls that must be preventive in this run, with the exception principals each exempts."""
    out = {}
    for cid, record in sorted(controls.items()):
        if "guardrail" not in record:
            continue
        mode = Mode(record["mode"])
        approved = tuple(e.principal for e in request.exceptions if e.control_id == cid)
        if mode is Mode.ENFORCE:
            out[cid] = ()
        elif mode is Mode.ENFORCE_WITH_OVERRIDE and approved:
            out[cid] = approved
    return out


def unclassified_actions(spec: Spec, contract: list[str]) -> list[str]:
    """Contract actions the action review hasn't seen, or that match a capability without a decision."""
    review = spec.action_review
    if review is None:
        return []
    prefix = f"{spec.service}:"
    names = [a.removeprefix(prefix) for a in contract if a.startswith(prefix)]
    missing = sorted(set(names) - set(review["actions"]))
    for cap in review["capabilities"].values():
        decided = set(cap["deny"]) | set(cap["allow"])
        missing += [n for n in names if n not in decided and any(matches(m, n) for m in cap["match"])]
    return sorted(set(missing))


def _prove(cid: str, prop, stmt: dict, spec: Spec, space: Space, exceptions: tuple[str, ...]) -> tuple[list, dict]:
    problems, mutation = [], {"total": 0, "caught": 0, "equivalent": 0, "survived": []}
    try:
        found = counterexamples(stmt, prop, space, exceptions, limit=3)
    except ModelError as exc:
        return [str(exc)], mutation
    if found:
        problems.append("disagrees with its property, for example: " + json.dumps(found[0], sort_keys=True))
        return problems, mutation
    for description, mutant in mutants(stmt):
        mutation["total"] += 1
        if spec.equivalent(cid, description, space.facts):
            mutation["equivalent"] += 1
        elif counterexamples(mutant, prop, space, exceptions, limit=1):
            mutation["caught"] += 1
        else:
            mutation["survived"].append(description)
    if mutation["survived"]:
        problems.append("mutants survive, so the proof can't tell these bugs from the statement: "
                        + "; ".join(mutation["survived"]))
    return problems, mutation


def verify(request: OnboardingRequest, findings: dict, controls: dict, policies: dict,
           contract: list[str]) -> dict:
    """Return the verification document for a run (see the module docstring)."""
    service = findings["service"]
    try:
        spec = load_spec(service)
    except SpecError as exc:
        raise VerifyError(str(exc)) from exc
    facts = Facts.of(request, findings)
    key = sha256({"facts": repr(facts), "exceptions": [repr(e) for e in request.exceptions],
                  "controls": controls, "policies": policies, "contract": contract, "spec": spec.sha256,
                  "model": ATTACKER_MODEL_SHA256, "tier": request.maturity_tier.value,
                  "criticality": request.criticality.value})
    if key in _CACHE:
        return json.loads(json.dumps(_CACHE[key]))
    space = Space(facts, contract)
    active = active_controls(request, controls)
    sids = {cid.replace("-", ""): cid for cid in controls}
    statements = {stmt.get("Sid"): (name, stmt) for name, stmt in deny_statements(policies)}
    unclassified = unclassified_actions(spec, contract)
    capability_controls = set((spec.action_review or {}).get("capabilities", {}))

    failures, proofs = [], []
    for sid, (name, _) in sorted(statements.items()):
        cid = sids.get(sid)
        if cid not in active:
            failures.append(f"{name}/{sid} deploys a deny for {cid or 'no control'}, "
                            "which is not preventive in this run")
    for cid, exceptions in sorted(active.items()):
        prop = spec.by_control.get(cid)
        name, stmt = statements.get(cid.replace("-", ""), (None, None))
        if stmt is None:
            failures.append(f"{cid} must be preventive in this run, but no statement was generated for it")
            continue
        problems, mutation = [], {"total": 0, "caught": 0, "equivalent": 0, "survived": []}
        if prop is None:
            problems.append(f"the {service} security spec states no property for {cid}")
        else:
            expected = POLICY_TYPE[prop.constrains]
            if not name.startswith(f"{expected}-"):
                problems.append(f"its property constrains {prop.constrains}, enforceable only with a {expected} "
                                f"policy, but it is in {name}")
            else:
                problems, mutation = _prove(cid, prop, stmt, spec, space, exceptions)
            if cid in capability_controls and unclassified:
                problems.append("the API contract has actions the action review doesn't classify: "
                                + ", ".join(unclassified))
        proofs.append({
            "kind": "proof", "policy": name, "sid": stmt["Sid"], "control_id": cid,
            "statement_sha256": sha256(stmt), "property": prop.title if prop else None,
            "result": "fail" if problems else "pass", "source": f"onboard verify {__version__}",
            "detail": "; ".join(problems) or "denies exactly what its property denies, over the whole "
                                              "attacker model; every mutant is caught",
            "mutants": mutation,
        })

    risks = [{"id": r.id, "controls": list(r.controls), "risk": r.risk, "why": r.why, "reach": r.reach,
              "owner": r.owner, "status": r.status}
             for r in sorted(spec.accepted_risks, key=lambda r: r.id) if set(r.controls) & set(active)]
    result = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "maturity_tier": request.maturity_tier.value,
        "criticality": request.criticality.value,
        # Proofs hold for exactly these documents, this spec and this attacker model.
        "policy_set_sha256": sha256(policies),
        "spec": {"service": spec.service, "sha256": spec.sha256, "status": spec.status},
        "attacker_model": {"sha256": ATTACKER_MODEL_SHA256, "actions": len(space.actions),
                           "principals": len(space.values["principal"]), "resources": len(space.resources)},
        "result": "fail" if failures or any(p["result"] == "fail" for p in proofs) else "pass",
        "failures": failures,
        "proofs": proofs,
        "unclassified_actions": unclassified,
        "accepted_risks": risks,
    }
    if len(_CACHE) > 64:
        _CACHE.clear()
    _CACHE[key] = result
    return json.loads(json.dumps(result))
