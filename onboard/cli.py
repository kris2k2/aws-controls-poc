"""Command line: `python -m onboard <command>`."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

from .request import RequestError, parse_request
from .resolve import ResolveError, resolve
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

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (RequestError, ResolveError, SourceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
