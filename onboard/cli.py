"""Command line: `python -m onboard <command>`."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

from .catalog import CATALOG_URL, PINNED_INDEX, CatalogError, build_index, fetch_index, load_index
from .controls import FindingsError, load_findings
from .generate import GenerateError, generate
from .request import RequestError, parse_request
from .resolve import ResolveError, resolve
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
    _write_json(run / "generation.json", result["report"])
    print(f"Wrote {len(result['policies'])} organization policies to {run / 'org-policies'}")
    return 0


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

    p = sub.add_parser("select", help="Select stage: write control records and selection.json")
    p.add_argument("request", help="request JSON file")
    p.add_argument("--findings", required=True, help="findings.json from Assess")
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

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (RequestError, ResolveError, SourceError, FindingsError, SelectError, GenerateError,
            CatalogError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
