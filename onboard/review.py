"""Review: decide whether a run's policy set may be released without a person.

The reviewer is deterministic: the decision is a function of the run
directory, the verification evidence, the recorded human acceptances, the
request and the date. It never edits the run and it deploys nothing; it
writes `review.json`, which a deployment pipeline reads (ADR-0005).

It is deliberately critical. It trusts nothing the earlier stages say about
themselves: it re-runs Select, Generate and Verify from the run's findings,
request and API contract and requires the same files byte for byte, then
checks the policies it is about to release on its own terms. Proofs come
only from its own run of Verify (ADR-0006); outside evidence can supply
impact replays and calibration, never proofs. What it finds is either:

- a **blocker**: the run is wrong or unproven in a way no person may wave
  through (a tampered file, a failed proof, an unexpected Allow). The run must
  be fixed and reviewed again.
- a **doubt**: a known gap in the evidence, with a risk level and the exact
  question a person answers by accepting it. Doubts at or under the
  auto-accept ceiling for the request's criticality are accepted by the
  reviewer and recorded as such; the rest need a named person other than the
  maker. An acceptance is bound to a fingerprint of what was doubted, so it
  carries over to later runs until that thing changes, then lapses.

Outcomes: `release` (no blockers, every doubt accepted), `hold` (no blockers,
some doubts await a person: the review lists them with a ready-to-fill
acceptance template) and `blocked`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from . import __version__, evaluator
from .catalog import load_index
from .controls import GUARDRAIL_TYPES, FindingsError, load_findings
from .generate import ENDPOINT_BASE_ALLOW, MAX_POLICY_CHARS, GenerateError, generate, policy_size, text_sha256
from .model import Criticality, Mode, _Ordered
from .request import OnboardingRequest
from .select import SelectError, select
from .verify import VerifyError, contract_actions, deny_statements, sha256, verify

SCHEMA = "review/v1"
EVIDENCE_SCHEMA = "evidence/v1"
ACCEPTANCES_SCHEMA = "acceptances/v1"
EVIDENCE_KINDS = ("proof", "impact", "calibration")
EXTERNAL_KINDS = ("impact", "calibration")  # proofs come only from the reviewer's own run of Verify
RESULTS = ("pass", "fail")


class Risk(_Ordered):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


# The highest risk the reviewer accepts on its own, by criticality. Above it, a
# person must. At High criticality every doubt needs a person. Changing this
# table is a policy change: it needs an ADR, not a flag.
AUTO_ACCEPT_CEILING: dict[Criticality, Risk | None] = {
    Criticality.LOW: Risk.MEDIUM,
    Criticality.MODERATE: Risk.LOW,
    Criticality.HIGH: None,
}

# Calibration evidence holds only for the evaluator it was produced against.
EVALUATOR_SHA256 = hashlib.sha256(Path(evaluator.__file__).read_bytes()).hexdigest()


def _plain(document):
    """The document as it reads back from JSON (tuples become lists)."""
    return json.loads(json.dumps(document))


# ---------------------------------------------------------------- loading


def _read(path: Path, problems: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        problems.append(f"cannot read {path.name}: {exc}")
        return None


def load_run(run: Path) -> tuple[dict, list[str]]:
    """Read what Select and Generate wrote. Problems are returned, not raised:
    an incomplete run is reviewed, and blocked."""
    problems: list[str] = []
    files = {name: _read(run / f"{name}.json", problems)
             for name in ("findings", "selection", "registry", "generation")}
    files["controls"] = {p.stem: _read(p, problems) for p in sorted((run / "controls").glob("*.json"))}
    files["policies"] = {p.stem: _read(p, problems) for p in sorted((run / "org-policies").glob("*.json"))}
    # Detective and plan-time artifacts, compared as text: Sentinel files aren't JSON.
    # Undecodable bytes are replaced, so a planted binary file is a difference, not a crash.
    files["artifacts"] = {p.relative_to(run).as_posix(): p.read_bytes().decode("utf-8", errors="replace")
                          for p in sorted((run / "detective").rglob("*")) if p.is_file()}
    if not files["policies"]:
        problems.append("org-policies/ holds no policies: run generate first")
    # Resolve's contract and Verify's report are optional: without the contract
    # there are no proofs (doubts); a verification.json present must reproduce.
    for name, key in (("capability-profile", "profile"), ("verification", "verification")):
        path = run / f"{name}.json"
        files[key] = _read(path, problems) if path.exists() else None
    return files, problems


def load_optional(path: Path | None, schema: str, problems: list[str]) -> dict | None:
    if path is None:
        return None
    document = _read(path, problems)
    if document is not None and (not isinstance(document, dict) or document.get("schema") != schema):
        problems.append(f"{path.name} must be a JSON object with schema {schema!r}")
        return None
    return document


# ---------------------------------------------------------------- checks


class _Findings:
    def __init__(self):
        self.blockers: list[dict] = []
        self.doubts: list[dict] = []

    def block(self, check: str, subject: str, detail: str) -> None:
        self.blockers.append({"check": check, "subject": subject, "detail": detail})

    def doubt(self, kind: str, subject: str, risk: Risk, detail: str, accept_means: str, material) -> None:
        self.doubts.append({
            "id": f"{kind}:{subject}", "kind": kind, "subject": subject, "risk": risk.value,
            "detail": detail, "accept_means": accept_means,
            # What was doubted, hashed: an acceptance holds while this is unchanged.
            "fingerprint": sha256({"kind": kind, "subject": subject, "material": _plain(material)}),
        })


def _reproduce(request: OnboardingRequest, run: dict, catalog: dict, out: _Findings) -> None:
    """Re-run Select and Generate; anything that differs was edited or drifted."""
    try:
        findings = load_findings(run["findings"])
        selected = select(findings, request, catalog)
        generated = generate(findings, selected["controls"], request)
    except (FindingsError, SelectError, GenerateError) as exc:
        out.block("reproducible", "run", f"Select or Generate fails on this run's inputs: {exc}")
        return
    expected = {"selection": selected["selection"], "registry": selected["registry"],
                "controls": selected["controls"], "generation": generated["report"],
                "policies": generated["policies"]}
    for name in ("selection", "registry", "generation"):
        if _plain(expected[name]) != run[name]:
            out.block("reproducible", f"{name}.json", "differs from what this request and findings produce")
    for group, folder in (("controls", "controls"), ("policies", "org-policies")):
        want, have = _plain(expected[group]), run[group]
        for name in sorted(set(want) | set(have)):
            if name not in have:
                out.block("reproducible", f"{folder}/{name}.json", "missing from the run")
            elif name not in want:
                out.block("reproducible", f"{folder}/{name}.json", "not produced by this request and findings")
            elif want[name] != have[name]:
                out.block("reproducible", f"{folder}/{name}.json",
                          "differs from what this request and findings produce")
    want, have = generated["artifacts"], run.get("artifacts") or {}
    for path in sorted(set(want) | set(have)):
        if path not in have:
            out.block("reproducible", path, "missing from the run")
        elif path not in want:
            out.block("reproducible", path, "not produced by this request and findings")
        elif want[path] != have[path]:
            out.block("reproducible", path, "differs from what this request and findings produce")


def check_policies(policies: dict, generation: dict, controls: dict, out: _Findings) -> None:
    """Checks on the documents to be released, independent of how they were made."""
    sids = {cid.replace("-", ""): cid for cid in controls}
    service = generation.get("service")
    allow_list = {"Sid": "AllowList", "Effect": "Allow", "Resource": "*",
                  "Action": [f"{p}:*" for p in generation.get("allow_list_prefixes", [])]}
    for name, doc in sorted(policies.items()):
        if policy_size(doc) > MAX_POLICY_CHARS:
            out.block("size", name, f"{policy_size(doc)} characters, over the {MAX_POLICY_CHARS} limit")
        if "${" in json.dumps(doc):
            out.block("parameters", name, "holds an unresolved ${parameter}")
        for i, stmt in enumerate(doc.get("Statement", [])):
            effect = stmt.get("Effect")
            if effect == "Allow":
                expected = (name == f"scp-{service}-allow" and stmt == allow_list) or \
                           (name.startswith("vpce-") and i == 0 and stmt == ENDPOINT_BASE_ALLOW)
                if not expected:
                    out.block("unexpected-allow", f"{name}/{stmt.get('Sid', i)}",
                              "grants something other than the service allow-list or the endpoint base allow")
            elif effect == "Deny":
                cid = sids.get(stmt.get("Sid"))
                if cid is None:
                    out.block("traceable", f"{name}/{stmt.get('Sid', i)}", "doesn't trace to a selected control")
                elif not Mode(controls[cid]["mode"]).enforcing:
                    out.block("traceable", f"{name}/{stmt['Sid']}",
                              f"deploys a deny for {cid}, whose mode {controls[cid]['mode']} deploys none")
            else:
                out.block("effect", f"{name}/{stmt.get('Sid', i)}", f"has Effect {effect!r}")


def _evidence_index(evidence: list[dict], proofs: list[dict], problems: list[str]) -> dict:
    """{(kind, binding hash): [item, ...]}: outside impact and calibration evidence, plus Verify's proofs."""
    index: dict = {}
    for item in proofs:
        index.setdefault(("proof", item["statement_sha256"]), []).append(item)
    for n, document in enumerate(evidence):
        for i, item in enumerate(document.get("items", [])):
            where = f"evidence file {n + 1}, item {i}"
            if not isinstance(item, dict) or item.get("kind") not in EVIDENCE_KINDS \
                    or item.get("result") not in RESULTS or not isinstance(item.get("source"), str):
                problems.append(f"{where} needs kind ({'/'.join(EXTERNAL_KINDS)}), "
                                f"result ({'/'.join(RESULTS)}) and source")
                continue
            if item["kind"] not in EXTERNAL_KINDS:
                problems.append(f"{where} is a proof: proofs come only from the reviewer's own run of Verify; "
                                "ignored")
                continue
            binding = item.get("evaluator_sha256") if item["kind"] == "calibration" else item.get("statement_sha256")
            index.setdefault((item["kind"], binding), []).append(item)
    return index


def check_verification(request: OnboardingRequest, run: dict, out: _Findings, problems: list[str]) -> list[dict]:
    """Run Verify; return its proofs. Failures block; accepted risks and an unsigned spec are doubts."""
    if run.get("profile") is None:
        problems.append("capability-profile.json is missing, so nothing is proved: run resolve into the run")
        return []
    try:
        findings = load_findings(run["findings"])
        result = verify(request, findings, run["controls"], run["policies"],
                        contract_actions(run["profile"], findings["service"]))
    except (FindingsError, VerifyError) as exc:
        problems.append(f"nothing is proved: {exc}")
        return []
    if run.get("verification") is not None and run["verification"] != result:
        out.block("reproducible", "verification.json", "differs from what Verify produces for this run")
    for failure in result["failures"]:
        out.block("verify", "run", failure)
    spec = result["spec"]
    if spec["status"] != "approved":
        out.doubt("security-spec", spec["service"], Risk.MEDIUM,
                  f"proofs are against the {spec['service']} security spec, which is {spec['status']}",
                  "the security spec says what each of these controls must deny", spec)
    for risk in result["accepted_risks"]:
        if risk["status"] == "approved":  # signed off in the spec, through its reviewed pull request
            continue
        out.doubt("accepted-risk", risk["id"], Risk.MEDIUM,
                  f"{risk['risk']} Reach: {risk['reach']} ({risk['status']})",
                  f"the gap is acceptable for {', '.join(risk['controls'])}, as far as it reaches", risk)
    return result["proofs"]


_STATEMENT_DOUBTS = {
    "proof": ("no proof that this statement denies exactly what its control's security property denies",
              "I have checked that this statement denies what the control requires, no more and no less"),
    "impact": ("no replay of recent activity showing which existing calls this statement would deny",
               "I have checked that this deny breaks no approved workload where it is attached"),
}


def check_evidence(request: OnboardingRequest, policies: dict, controls: dict, evidence: list[dict],
                   proofs: list[dict], out: _Findings, problems: list[str]) -> list[dict]:
    """Every deployed deny needs a proof, and an impact replay where it can break running workloads."""
    index = _evidence_index(evidence, proofs, problems)
    sids = {cid.replace("-", ""): cid for cid in controls}
    for name, stmt in deny_statements(policies):
        cid = sids.get(stmt.get("Sid"))
        if cid is None:
            continue  # already a blocker
        shared = bool(controls[cid].get("shared"))
        digest = sha256(stmt)
        # Organization-wide denies reach running workloads; so do a service's on a promotion.
        kinds = ["proof"] + (["impact"] if shared or request.run_mode != "new" else [])
        for kind in kinds:
            items = index.get((kind, digest), [])
            failed = [i for i in items if i["result"] == "fail"]
            if failed:
                out.block(f"evidence-{kind}", f"{name}/{stmt['Sid']}",
                          f"{failed[0]['source']}: {failed[0].get('detail') or 'failed'}")
            elif not items:
                detail, means = _STATEMENT_DOUBTS[kind]
                out.doubt(f"evidence-{kind}", f"{name}/{stmt['Sid']}", Risk.HIGH if shared else Risk.MEDIUM,
                          f"{cid}: {detail}", means, stmt)
    items = index.get(("calibration", EVALUATOR_SHA256), [])
    if any(i["result"] == "fail" for i in items):
        out.block("evidence-calibration", "evaluator", "the local evaluator disagrees with AWS")
    elif not items:
        out.doubt("calibration", "evaluator", Risk.MEDIUM,
                  "proofs hold in the local evaluator's model of IAM, which hasn't been replayed against the "
                  "IAM policy simulator and live calls", "I accept proofs that hold in the local evaluator's "
                  "model of IAM until it is calibrated against AWS", EVALUATOR_SHA256)
    # Evidence bound to a statement that no longer exists, or changed since, or to another
    # evaluator: say so, don't use it.
    current = {sha256(stmt) for _, stmt in deny_statements(policies)} | {EVALUATOR_SHA256}
    return [{"kind": kind, "source": i["source"], "sid": i.get("sid")}
            for (kind, binding), items in sorted(index.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))
            if binding not in current for i in items]


def check_selection(request: OnboardingRequest, run: dict, out: _Findings) -> None:
    """Doubts about what was selected and why, and about who the policies trust."""
    selection, controls, generation = run["selection"], run["controls"], run["generation"]
    for item in selection.get("checker_items", []):
        cid, text = item["control_id"], item["item"]
        if cid is None:  # a matrix change
            out.doubt("matrix-change", text.removeprefix("matrix change "), Risk.HIGH,
                      "the decision matrix differs from the ratified default, which moves modes for many controls",
                      "the matrix change is ratified", text)
        elif text.startswith("inferred severity"):
            record = controls[cid]
            out.doubt("inferred-severity", cid, Risk.MEDIUM,
                      f"{text} (rubric, not an AWS source) sets {cid}'s mode to {record['mode']}",
                      f"{record['severity']} is the right severity for {cid}",
                      {k: record.get(k) for k in ("severity", "severity_source", "class", "mode", "title")})
        else:
            record = controls[cid]
            out.doubt("inferred-mapping", cid, Risk.LOW,
                      f"{text}: every framework mapping is inferred, none verified",
                      f"{cid}'s framework mappings are good enough to release on",
                      {"mode": record["mode"], "framework_refs": record["framework_refs"]})
    if request.run_mode != "new":
        for entry in selection.get("retired", []):
            out.doubt("retired", entry["control_id"], Risk.MEDIUM,
                      f"{entry['control_id']} stops applying on this promotion ({entry['reason']}): "
                      "its deny is lifted", "lifting this control is intended at this tier",
                      {**entry, "tier": selection.get("maturity_tier")})
    for entry in selection.get("excluded_by_decision", []):
        out.doubt("excluded", entry["control_id"], Risk.MEDIUM,
                  f"{entry['control_id']} is left out by an analyst decision ({entry['reason']})",
                  "the decision is right and its consequence is understood", entry)
    for exc in request.exceptions:
        out.doubt("exception", f"{exc.control_id}/{exc.principal}", Risk.MEDIUM,
                  f"{exc.principal} is exempt from {exc.control_id} until {exc.expires.isoformat()} "
                  f"(owner {exc.owner}): {exc.rationale}", "the exception is justified and its owner is right",
                  {"principal": exc.principal, "control_id": exc.control_id, "owner": exc.owner,
                   "expires": exc.expires.isoformat(), "rationale": exc.rationale})
    if request.break_glass_principals:
        out.doubt("break-glass", "principals", Risk.MEDIUM,
                  "break-glass roles are exempt from every guardrail but the data perimeter; who can assume "
                  "them is set by trust policies this tool doesn't check (AR-04)",
                  "the break-glass roles' trust policies admit only the intended responders",
                  sorted(request.break_glass_principals))
    if request.trusted_resource_accounts:
        out.doubt("trusted-accounts", "resource-accounts", Risk.MEDIUM,
                  "data may leave the organization to these accounts through the data perimeter: "
                  + ", ".join(sorted(request.trusted_resource_accounts)),
                  "each account is a vendor or AWS-owned account the organization has approved",
                  sorted(request.trusted_resource_accounts))
    pending = []
    for cid, statuses in sorted(generation.get("controls", {}).items()):
        if any(s["status"] == "pending" for s in statuses.values()):
            pending.append(cid)
        # Config rules and detections only detect; Sentinel stops only what Terraform plans.
        guarded = any(statuses.get(t, {}).get("status") == "generated" for t in GUARDRAIL_TYPES)
        if Mode(controls[cid]["mode"]).enforcing and not guarded:
            plan_time = statuses.get("sentinel", {}).get("status") == "generated"
            out.doubt("unenforced", cid, Risk.MEDIUM,
                      f"{cid} is selected as {controls[cid]['mode']}, but "
                      + ("only a Sentinel policy enforces it, at plan time: resources made outside Terraform "
                         "aren't stopped" if plan_time else "this run deploys nothing that enforces it"),
                      f"releasing without a guardrail enforcing {cid} is acceptable for now",
                      {"mode": controls[cid]["mode"], "statuses": statuses})
    if pending:
        out.doubt("pending-artifacts", "detective", Risk.LOW,
                  f"{len(pending)} controls have artifacts not generated yet (Config, CloudTrail, Sentinel)",
                  "releasing the guardrails before their detective artifacts is acceptable",
                  {cid: generation["controls"][cid] for cid in pending})
    artifacts = generation.get("detective_artifacts") or {}
    if artifacts:
        out.doubt("unexercised-artifacts", "detective", Risk.LOW,
                  f"{len(artifacts)} Config rules, detections and Sentinel files are rendered but have not run "
                  "in AWS Config, EventBridge or Sentinel: a wrong field path or event field misses what it "
                  "should catch",
                  "releasing detective artifacts checked only by the local evaluator is acceptable",
                  artifacts)


def _consistency(request: OnboardingRequest, run: dict, out: _Findings) -> None:
    for name, schema in (("selection", "selection/v1"), ("generation", "generation/v1")):
        doc = run[name]
        if doc.get("schema") != schema:
            out.block("schema", f"{name}.json", f"schema must be {schema}")
        if doc.get("tool_version") != __version__:
            out.block("tool-version", f"{name}.json",
                      f"written by tool {doc.get('tool_version')}, reviewed by {__version__}: rerun the pipeline")
        if doc.get("maturity_tier") != request.maturity_tier.value or \
                doc.get("criticality") != request.criticality.value:
            out.block("consistent", f"{name}.json", "tier or criticality differs from the request")
    if set(run["controls"]) != set(run["selection"].get("controls", [])):
        out.block("consistent", "controls/", "control records differ from the controls selection.json lists")


# ---------------------------------------------------------------- acceptances


def _acceptances(acceptances: dict | None, maker: str, today: dt.date, problems: list[str]) -> dict[str, dict]:
    """{fingerprint: acceptance} for the valid ones; the rest go to `problems`."""
    valid: dict[str, dict] = {}
    for i, entry in enumerate((acceptances or {}).get("acceptances", [])):
        where = f"acceptance {i}"
        if not isinstance(entry, dict):
            problems.append(f"{where} must be an object")
            continue
        missing = [f for f in ("fingerprint", "accepted_by", "expires", "rationale")
                   if not isinstance(entry.get(f), str) or not entry[f].strip()]
        if missing:
            problems.append(f"{where} is missing {', '.join(missing)}")
            continue
        try:
            expires = dt.date.fromisoformat(entry["expires"])
        except ValueError:
            problems.append(f"{where}: expires must be an ISO date (YYYY-MM-DD)")
            continue
        if expires <= today:
            problems.append(f"{where} ({entry.get('doubt', entry['fingerprint'][:12])}) expired on {expires}")
            continue
        if entry["accepted_by"].strip().casefold() == maker.casefold():
            problems.append(f"{where}: the maker ({maker}) can't accept doubts about their own run")
            continue
        valid[entry["fingerprint"]] = {"accepted_by": entry["accepted_by"].strip(), "expires": entry["expires"],
                                       "rationale": entry["rationale"].strip()}
    return valid


# ---------------------------------------------------------------- review


def review(request: OnboardingRequest, run: dict, *, evidence: dict | list[dict] | None = None,
           acceptances: dict | None = None, catalog: dict | None = None,
           load_problems: tuple[str, ...] = (), today: dt.date | None = None) -> dict:
    """Return the review document for a run (see the module docstring).

    `evidence` is one or more evidence/v1 documents: impact replays and calibration.
    """
    today = today or dt.date.today()
    evidence = [evidence] if isinstance(evidence, dict) else list(evidence or [])
    out, notes = _Findings(), []
    for problem in load_problems:
        out.block("complete", "run", problem)
    complete = not load_problems
    if complete:
        _consistency(request, run, out)
        _reproduce(request, run, catalog if catalog is not None else load_index(), out)
    if complete and not out.blockers:
        check_policies(run["policies"], run["generation"], run["controls"], out)
        proofs = check_verification(request, run, out, notes)
        stale = check_evidence(request, run["policies"], run["controls"], evidence, proofs, out, notes)
        check_selection(request, run, out)
    else:
        stale = []  # nothing past a broken run is worth reviewing
    accepted = _acceptances(acceptances, request.maker, today, notes)

    ceiling = AUTO_ACCEPT_CEILING[request.criticality]
    for d in out.doubts:
        if d["fingerprint"] in accepted:
            d["status"], d["acceptance"] = "accepted", accepted[d["fingerprint"]]
        elif ceiling is not None and Risk(d["risk"]) <= ceiling:
            d["status"] = "auto-accepted"
        else:
            d["status"] = "needs acceptance"
    current = {d["fingerprint"] for d in out.doubts}
    open_doubts = [d for d in out.doubts if d["status"] == "needs acceptance"]
    decision = "blocked" if out.blockers else "hold" if open_doubts else "release"
    residual = max((Risk(d["risk"]) for d in open_doubts), default=None)
    policies = run.get("policies") or {}
    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": (run.get("generation") or {}).get("service"),
        "maturity_tier": request.maturity_tier.value,
        "criticality": request.criticality.value,
        "run_mode": request.run_mode,
        "reviewed_on": today.isoformat(),
        "decision": decision,
        "residual_risk": residual.value if residual else None,
        "auto_accept_ceiling": ceiling.value if ceiling else None,
        # A deployment must release exactly these documents.
        "policy_set_sha256": sha256(policies),
        "policies": {name: sha256(doc) for name, doc in sorted(policies.items())},
        # And exactly these detective artifacts (SHA-256 of each file's bytes).
        "artifacts": {path: text_sha256(text) for path, text in sorted((run.get("artifacts") or {}).items())},
        "blockers": out.blockers,
        "doubts": sorted(out.doubts, key=lambda d: (-Risk(d["risk"]).rank, d["id"])),
        "counts": {s: sum(d["status"] == s for d in out.doubts)
                   for s in ("needs acceptance", "accepted", "auto-accepted")},
        "unused_acceptances": sorted(set(accepted) - current),
        "stale_evidence": stale,
        "problems": notes,
        # Fill in and pass back with --acceptances; the maker can't sign.
        "acceptance_template": {"schema": ACCEPTANCES_SCHEMA, "acceptances": [
            {"doubt": d["id"], "risk": d["risk"], "accept_means": d["accept_means"],
             "fingerprint": d["fingerprint"], "accepted_by": "", "expires": "", "rationale": ""}
            for d in open_doubts]},
    }
