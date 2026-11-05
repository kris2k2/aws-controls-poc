"""Command line: `python -m onboard <command>`."""

from __future__ import annotations

import argparse
from argparse import Namespace
import datetime as dt
import json
import shutil
import sys
import urllib.parse
from pathlib import Path

from . import __version__
from .assess import AssessError, assess
from .catalog import CATALOG_URL, PINNED_INDEX, CatalogError, build_index, fetch_index, load_index
from .control_catalog import (REGION as CATALOG_REGION, ControlCatalog, http_transport, recording_transport,
                              snapshot_metadata, snapshot_transport)
from .controls import FindingsError, load_findings
from .deliver import DeliverError, check_delivery, deliver, manifest_sha256
from .generate import GenerateError, generate
from .report import ReportError, load as load_report, render as render_report
from .request import RequestError, parse_request
from .resolve import ResolveError, resolve
from .review import ACCEPTANCES_SCHEMA, EVIDENCE_SCHEMA, load_optional, load_run, review
from .verify import VerifyError, contract_actions, verify
from .select import SelectError, select
from .service_reference import INDEX_URL, ServiceReference, SourceError, check_url, http_fetch


def snapshot_fetcher(directory: Path):
    """Serve service reference URLs from a local snapshot, for offline, repeatable runs.

    The snapshot holds `index.json` and one `<prefix>.json` per service.
    """
    def fetch(url: str) -> bytes:
        check_url(url)
        if url == INDEX_URL:
            path = directory / "index.json"
        else:
            path = directory / Path(urllib.parse.urlsplit(url).path).name
        if not path.is_file():
            raise SourceError(f"{url} is not in the snapshot {directory} (looked for {path.name})")
        return path.read_bytes()
    return fetch


def _load_request(path: str):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RequestError([f"cannot read {path}: {exc}"]) from exc
    return parse_request(data)


def _write_json(path: Path, document) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_check_request(args) -> int:
    request = _load_request(args.request)
    print(f"OK: {request.service} at {request.maturity_tier.value}, "
          f"criticality {request.criticality.value}, run mode {request.run_mode}")
    return 0


def cmd_resolve(args) -> int:
    request = _load_request(args.request)
    fetch = snapshot_fetcher(Path(args.snapshot)) if args.snapshot else http_fetch
    profile = resolve(request.service, ServiceReference(fetch))
    out = Path(args.out) / "capability-profile.json"
    _write_json(out, profile)
    counts = ", ".join(f"{s['prefix']}: {s['summary']['actions']} actions" for s in profile["services"])
    print(f"Wrote {out} ({counts})")
    if profile["related_prefixes_to_confirm"]:
        print("Related prefixes to confirm: " + ", ".join(profile["related_prefixes_to_confirm"]))
    return 0


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FindingsError([f"cannot read {path}: {exc}"]) from exc


def cmd_assess(args) -> int:
    request = _load_request(args.request)
    run = Path(args.run)
    profile_path = run / "capability-profile.json"
    if not profile_path.exists():
        raise AssessError(f"{profile_path} is missing: run resolve into the run first")
    profile = _read_json(profile_path)
    if args.control_catalog_snapshot:
        directory = Path(args.control_catalog_snapshot)
        transport = snapshot_transport(directory)
        source = {"mode": "snapshot", "snapshot": directory.name, **snapshot_metadata(directory)}
    else:
        transport = http_transport()
        source = {"mode": "live", "region": CATALOG_REGION, "synthetic": False,
                  "retrieved": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if args.record_snapshot:
            transport = recording_transport(transport, Path(args.record_snapshot))
    overlay = _read_json(Path(args.overlay)) if args.overlay else None
    result = assess(request, profile, ControlCatalog(transport), load_index(Path(args.catalog)),
                    overlay=overlay, source=source)
    _write_json(run / "findings.json", result["findings"])
    _write_json(run / "assessment.json", result["assessment"])
    a = result["assessment"]
    counts = ", ".join(f"{k}: {v}" for k, v in a["counts"].items())
    skipped = len(a["sources"]["control_catalog"]["skipped"])
    print(f"Wrote {run / 'findings.json'} ({len(a['candidates'])} candidates; {counts}); "
          f"{skipped} Security Hub controls skipped, see {run / 'assessment.json'}")
    return 0


def cmd_select(args) -> int:
    request = _load_request(args.request)
    findings = load_findings(_read_json(Path(args.findings)))
    result = select(findings, request, load_index(Path(args.catalog)))
    run = Path(args.out)
    # A re-run must not leave control records from an earlier selection behind.
    for stale in (run / "controls").glob("*.json"):
        stale.unlink()
    _write_json(run / "findings.json", findings)
    for cid, record in result["controls"].items():
        _write_json(run / "controls" / f"{cid}.json", record)
    _write_json(run / "selection.json", result["selection"])
    _write_json(run / "registry.json", result["registry"])
    sel = result["selection"]
    print(f"Selected {len(sel['controls'])} controls at {sel['maturity_tier']} "
          f"({', '.join(f'{k}: {v}' for k, v in sorted(sel['counts']['mode'].items()))}); "
          f"{len(sel['checker_items'])} checker items")
    return 0


def cmd_generate(args) -> int:
    request = _load_request(args.request)
    run = Path(args.run)
    findings = load_findings(_read_json(run / "findings.json"))
    controls = {p.stem: _read_json(p) for p in sorted((run / "controls").glob("*.json"))}
    result = generate(findings, controls, request)
    for name, policy in result["policies"].items():
        _write_json(run / "org-policies" / f"{name}.json", policy)
    # Review compares this directory with what Generate produces, so stale files must go.
    if (run / "detective").is_dir():
        shutil.rmtree(run / "detective")
    for path, text in result["artifacts"].items():
        (run / path).parent.mkdir(parents=True, exist_ok=True)
        (run / path).write_text(text, encoding="utf-8")
    _write_json(run / "generation.json", result["report"])
    pending = sum(s["status"] == "pending" for c in result["report"]["controls"].values() for s in c.values())
    print(f"Wrote {len(result['policies'])} organization policies to {run / 'org-policies'} and "
          f"{len(result['artifacts'])} detective artifacts to {run / 'detective'}; {pending} artifacts pending")
    return 0


def cmd_verify(args) -> int:
    request = _load_request(args.request)
    run = Path(args.run)
    findings = load_findings(_read_json(run / "findings.json"))
    controls = {p.stem: _read_json(p) for p in sorted((run / "controls").glob("*.json"))}
    policies = {p.stem: _read_json(p) for p in sorted((run / "org-policies").glob("*.json"))}
    if not policies:
        raise VerifyError(f"{run / 'org-policies'} holds no policies: run generate first")
    profile_path = run / "capability-profile.json"
    if not profile_path.exists():
        raise VerifyError(f"{profile_path} is missing: run resolve into the run first")
    contract = contract_actions(_read_json(profile_path), findings["service"])
    result = verify(request, findings, controls, policies, contract)
    _write_json(run / "verification.json", result)
    passed = sum(p["result"] == "pass" for p in result["proofs"])
    mutants = sum(p["mutants"]["caught"] for p in result["proofs"])
    print(f"{result['result'].upper()}: {passed} of {len(result['proofs'])} statements proved against the "
          f"{result['service']} security spec ({result['spec']['status']}), {mutants} mutants caught, "
          f"{len(result['failures'])} failures; wrote {run / 'verification.json'}")
    for failure in result["failures"]:
        print(f"  failure: {failure}")
    for proof in result["proofs"]:
        if proof["result"] == "fail":
            print(f"  {proof['policy']}/{proof['sid']}: {proof['detail']}")
    return 0 if result["result"] == "pass" else 4


# Exit codes for `review`, so a pipeline can gate on them.
REVIEW_EXIT = {"release": 0, "hold": 3, "blocked": 4}


def _review(args) -> tuple[dict, list[Path]]:
    """Run Review for `args.run`, write review.json, and return the result and the evidence files used."""
    request = _load_request(args.request)
    run = Path(args.run)
    files, problems = load_run(run)
    paths = [Path(e) for e in args.evidence or []]
    if not paths and (run / "evidence.json").exists():
        paths = [run / "evidence.json"]
    evidence = [doc for doc in (load_optional(p, EVIDENCE_SCHEMA, problems) for p in paths) if doc is not None]
    acceptances = load_optional(Path(args.acceptances) if args.acceptances else None, ACCEPTANCES_SCHEMA, problems)
    result = review(request, files, evidence=evidence, acceptances=acceptances,
                    catalog=load_index(Path(args.catalog)), load_problems=tuple(problems))
    _write_json(run / "review.json", result)
    counts = result["counts"]
    print(f"{result['decision'].upper()}: {len(result['blockers'])} blockers, "
          f"{counts['needs acceptance']} doubts need a person, {counts['accepted']} accepted, "
          f"{counts['auto-accepted']} auto-accepted (ceiling {result['auto_accept_ceiling'] or 'none'}); "
          f"wrote {run / 'review.json'}")
    for blocker in result["blockers"]:
        print(f"  blocker {blocker['check']}: {blocker['subject']}: {blocker['detail']}")
    return result, paths


def cmd_review(args) -> int:
    result, _ = _review(args)
    return REVIEW_EXIT[result["decision"]]


def cmd_deliver(args) -> int:
    # Review again here: a review.json already in the run is never trusted (ADR-0008).
    result, evidence = _review(args)
    run = Path(args.run)
    if result["decision"] != "release":
        if result["decision"] == "hold":
            print(f"Not delivered: {result['counts']['needs acceptance']} doubts need a person. Fill in "
                  f"acceptance_template in {run / 'review.json'} (not as the maker) and pass it with --acceptances.")
        else:
            print("Not delivered: the run is blocked; fix it and run again.")
        return REVIEW_EXIT[result["decision"]]
    out = Path(args.delivery) if args.delivery else run / "delivery"
    # The bundle's report shows this review, not whatever review.json held before.
    report = render_report(load_report(run, review=result)).encode("utf-8")
    manifest = deliver(result, run, out, request_bytes=Path(args.request).read_bytes(),
                       acceptances_bytes=Path(args.acceptances).read_bytes() if args.acceptances else None,
                       evidence={p.name: p.read_bytes() for p in evidence}, report_bytes=report)
    print(f"DELIVERED: {len(manifest['policies'])} policies ({manifest['service']} at {manifest['maturity_tier']}, "
          f"policy set {manifest['policy_set_sha256'][:12]}) to {out}; manifest sha256 {manifest_sha256(out)}")
    return 0


def write_report(run: Path, out: Path | None = None) -> Path:
    out = out or run / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(load_report(run)), encoding="utf-8")
    return out


def cmd_report(args) -> int:
    out = write_report(Path(args.run), Path(args.out) if args.out else None)
    print(f"Wrote {out}")
    return 0


def cmd_check_delivery(args) -> int:
    bundle = Path(args.bundle)
    problems = check_delivery(bundle)
    for problem in problems:
        print(f"  {problem}")
    if problems:
        print(f"FAIL: {bundle} is not an intact released bundle")
        return 4
    print(f"OK: {bundle} is intact and released; manifest sha256 {manifest_sha256(bundle)}")
    return 0


class RunError(ValueError):
    pass


# Files and directories the pipeline writes into a run, so a re-run starts clean.
RUN_OUTPUTS = ("capability-profile.json", "findings.json", "assessment.json", "selection.json", "registry.json",
               "generation.json", "verification.json", "review.json", "run.json", "report.html")
RUN_OUTPUT_DIRS = ("controls", "org-policies", "detective", "delivery")


def _clean_run(run: Path) -> None:
    if not run.exists() or not any(run.iterdir()):
        return
    if not (run / "run.json").is_file():
        raise RunError(f"{run} holds files but no run.json: pass a new directory or one `onboard run` wrote")
    for name in RUN_OUTPUTS:
        (run / name).unlink(missing_ok=True)
    for name in RUN_OUTPUT_DIRS:
        if (run / name).is_dir():
            shutil.rmtree(run / name)


RUN_RESULT = {0: "delivered", 3: "hold", 4: "blocked"}


def cmd_run(args) -> int:
    """The whole cycle for one service: Resolve, Assess, Select, Generate, Verify, Review, Deliver."""
    _load_request(args.request)  # fail before touching the run directory
    run = Path(args.out)
    _clean_run(run)
    run.mkdir(parents=True, exist_ok=True)
    common = {"request": args.request, "catalog": args.catalog}
    stages = (
        ("resolve", cmd_resolve, Namespace(request=args.request, out=str(run), snapshot=args.snapshot)),
        ("assess", cmd_assess, Namespace(**common, run=str(run), overlay=args.overlay,
                                         control_catalog_snapshot=args.control_catalog_snapshot,
                                         record_snapshot=args.record_snapshot)),
        ("select", cmd_select, Namespace(**common, findings=str(run / "findings.json"), out=str(run))),
        ("generate", cmd_generate, Namespace(request=args.request, run=str(run))),
        ("verify", cmd_verify, Namespace(request=args.request, run=str(run))),
        ("review and deliver", cmd_deliver, Namespace(**common, run=str(run), evidence=args.evidence,
                                                      acceptances=args.acceptances, delivery=None)),
    )
    log = {"schema": "run/v1", "tool_version": __version__, "service": None, "stages": [], "result": None}

    def finish(result: str, code: int) -> int:
        log["result"] = result
        if result == "delivered":
            log["delivery"] = {"path": "delivery", "manifest_sha256": manifest_sha256(run / "delivery")}
        # The report shows whatever the run reached, held and blocked runs included.
        if (run / "generation.json").is_file():
            try:
                log["report"] = write_report(run).name
                print(f"== report: {run / 'report.html'}")
            except Exception as exc:  # the report never hides the run's own result or error
                log["report_error"] = str(exc).splitlines()[0][:300] if str(exc) else type(exc).__name__
        _write_json(run / "run.json", log)
        return code

    for name, func, stage_args in stages:
        print(f"== {name}")
        try:
            code = func(stage_args)
        except Exception as exc:
            log["stages"].append({"stage": name, "exit": 2, "error": str(exc).splitlines()[0][:300]})
            finish("failed", 2)
            raise
        log["stages"].append({"stage": name, "exit": code})
        if name == "assess":
            log["service"] = json.loads((run / "findings.json").read_text(encoding="utf-8"))["service"]
        if code != 0:
            return finish(RUN_RESULT.get(code, "failed") if name == "review and deliver" else "failed", code)
    return finish("delivered", 0)


def cmd_catalog(args) -> int:
    if args.source:
        # A local copy of the OSCAL catalog; record where it came from.
        raw = Path(args.source).read_bytes()
        index = build_index(raw, args.source_url or CATALOG_URL, args.retrieved)
    else:
        index = fetch_index()
    _write_json(Path(args.out), index)
    withdrawn = sum(1 for c in index["controls"].values() if c["withdrawn"])
    print(f"Wrote {args.out}: NIST SP 800-53 {index['version']} (last modified {index['last_modified']}), "
          f"{len(index['controls'])} controls and enhancements, {withdrawn} withdrawn")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="onboard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check-request", help="validate an onboarding request")
    p.add_argument("request", help="request JSON file")
    p.set_defaults(func=cmd_check_request)

    p = sub.add_parser("resolve", help="Resolve stage: write capability-profile.json")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--out", required=True, help="run output directory")
    p.add_argument("--snapshot", help="read the service reference from this directory instead of AWS")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("assess", help="Assess stage: write findings.json and assessment.json from the capability "
                                      "profile, the organization baseline and the AWS Control Catalog")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--run", required=True, help="run directory written by resolve")
    p.add_argument("--overlay", help="the analyst's candidates and dependencies (findings-overlay/v1)")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--control-catalog-snapshot",
                        help="replay the Control Catalog from this snapshot directory (offline; no credentials)")
    source.add_argument("--record-snapshot", help="also save the live Control Catalog responses to this directory")
    p.add_argument("--catalog", default=str(PINNED_INDEX), help="NIST SP 800-53 catalog index (default: the pinned one)")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("select", help="Select stage: write control records and selection.json")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--findings", required=True, help="findings.json from Assess (in the run directory)")
    p.add_argument("--out", required=True, help="run output directory")
    p.add_argument("--catalog", default=str(PINNED_INDEX), help="NIST SP 800-53 catalog index (default: the pinned one)")
    p.set_defaults(func=cmd_select)

    p = sub.add_parser("catalog", help="build the NIST SP 800-53 Rev 5 catalog index from NIST's OSCAL catalog")
    p.add_argument("--out", required=True, help="index file to write (the pinned one is catalogs/nist-sp-800-53-rev5.json)")
    p.add_argument("--source", help="a local copy of the OSCAL catalog JSON instead of fetching it")
    p.add_argument("--source-url", help="where the local copy was downloaded from (default: NIST's catalog URL)")
    p.add_argument("--retrieved", help="when the local copy was downloaded (ISO 8601)")
    p.set_defaults(func=cmd_catalog)

    p = sub.add_parser("generate", help="Generate stage: write organization policies and generation.json")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--run", required=True, help="run directory written by select")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("verify", help="Verify stage: prove each guardrail against its security property and "
                                      "write verification.json (exit 0 pass, 4 fail)")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--run", required=True, help="run directory written by resolve, select and generate")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("review", help="Review stage: decide whether the run may be released without a person "
                                      "(exit 0 release, 3 hold, 4 blocked)")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--run", required=True, help="run directory written by generate")
    p.add_argument("--evidence", action="append",
                   help="impact or calibration evidence (evidence/v1); repeatable "
                        "(default: evidence.json in the run, if present)")
    p.add_argument("--acceptances", help="human acceptances of earlier doubts (acceptances/v1)")
    p.add_argument("--catalog", default=str(PINNED_INDEX), help="NIST SP 800-53 catalog index (default: the pinned one)")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("deliver", help="Review the run again and, on release, seal it into a delivery bundle "
                                       "(exit 0 delivered, 3 hold, 4 blocked)")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--run", required=True, help="run directory written by verify")
    p.add_argument("--delivery", help="bundle directory to write (default: delivery/ in the run); must be new or empty")
    p.add_argument("--evidence", action="append", help="impact or calibration evidence (evidence/v1); repeatable")
    p.add_argument("--acceptances", help="human acceptances of earlier doubts (acceptances/v1)")
    p.add_argument("--catalog", default=str(PINNED_INDEX), help="NIST SP 800-53 catalog index (default: the pinned one)")
    p.set_defaults(func=cmd_deliver)

    p = sub.add_parser("check-delivery", help="check a delivery bundle is intact and released (exit 0 ok, 4 not)")
    p.add_argument("bundle", help="delivery bundle directory")
    p.set_defaults(func=cmd_check_delivery)

    p = sub.add_parser("report", help="Report: write report.html, a visual summary of the service, its threat "
                                      "vectors and implemented guardrails, from a run directory")
    p.add_argument("--run", required=True, help="run directory written by select and generate (and verify, review)")
    p.add_argument("--out", help="where to write the report (default: report.html in the run)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("run", help="the whole cycle for one service: resolve, assess, select, generate, verify, "
                                   "review and deliver (exit 0 delivered, 3 hold, 4 blocked or failed proof)")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--out", required=True, help="run directory: new, empty, or one `onboard run` wrote (re-run clean)")
    p.add_argument("--snapshot", help="read the service reference from this directory instead of AWS")
    p.add_argument("--overlay", help="the analyst's candidates and dependencies (findings-overlay/v1)")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--control-catalog-snapshot", help="replay the Control Catalog from this snapshot directory")
    source.add_argument("--record-snapshot", help="also save the live Control Catalog responses to this directory")
    p.add_argument("--evidence", action="append", help="impact or calibration evidence (evidence/v1); repeatable")
    p.add_argument("--acceptances", help="human acceptances of the doubts a previous run held on (acceptances/v1)")
    p.add_argument("--catalog", default=str(PINNED_INDEX), help="NIST SP 800-53 catalog index (default: the pinned one)")
    p.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (RequestError, ResolveError, SourceError, FindingsError, SelectError, GenerateError,
            CatalogError, VerifyError, AssessError, DeliverError, RunError, ReportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
