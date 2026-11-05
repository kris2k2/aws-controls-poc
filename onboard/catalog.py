"""The NIST SP 800-53 Rev 5 catalog: the only source of 800-53 identifiers.

NIST publishes the catalog in OSCAL. `build_index` reduces it to what the tool
needs (each control's catalog id, label, title and whether it is withdrawn)
plus the catalog's version, last-modified date and the SHA-256 of the source
file, so a run can say exactly which catalog it checked against. The pinned
index lives in `catalogs/`. `check_refs` resolves every NIST reference on a
control against it: an identifier that isn't in the catalog, or is withdrawn,
or names another catalog version, is a problem, never a warning.
"""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import json
import re
import urllib.parse
from pathlib import Path

from .service_reference import SourceError, http_fetch

SCHEMA = "nist-800-53-index/v1"
FRAMEWORK = "NIST-SP-800-53"
CATALOG_URL = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
               "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
ALLOWED_HOST = "raw.githubusercontent.com"
ALLOWED_PATH = "/usnistgov/oscal-content/"
PINNED_INDEX = Path(__file__).resolve().parent.parent / "catalogs" / "nist-sp-800-53-rev5.json"
CATALOG_ID = re.compile(r"^[a-z]{2}-\d{1,2}(\.\d{1,2})?$")


class CatalogError(ValueError):
    pass


def check_catalog_url(url: str) -> str:
    """Only NIST's OSCAL content repository, over HTTPS (SSRF guard)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST or parts.port not in (None, 443) \
            or parts.username or parts.password or not parts.path.startswith(ALLOWED_PATH):
        raise SourceError(f"refusing to fetch {url!r}: not under https://{ALLOWED_HOST}{ALLOWED_PATH}")
    return url


fetch_catalog = functools.partial(http_fetch, check=check_catalog_url)


def _prop(control: dict, name: str, cls: str | None = None) -> str | None:
    for p in control.get("props") or []:
        if p.get("name") == name and p.get("class") == cls:
            return p.get("value")
    return None


def build_index(raw: bytes, source_url: str, retrieved: str) -> dict:
    """Reduce an OSCAL catalog document to the index the tool checks against."""
    try:
        catalog = json.loads(raw)["catalog"]
        metadata = catalog["metadata"]
        groups = catalog["groups"]
    except (ValueError, KeyError, TypeError) as exc:
        raise CatalogError("not an OSCAL catalog document") from exc
    if "800-53" not in str(metadata.get("title", "")):
        raise CatalogError(f"not the SP 800-53 catalog: {metadata.get('title')!r}")

    controls: dict[str, dict] = {}

    def walk(items):
        for c in items or []:
            cid = c.get("id")
            if not isinstance(cid, str) or not CATALOG_ID.match(cid):
                raise CatalogError(f"unexpected control id {cid!r}")
            controls[cid] = {"label": _prop(c, "label") or cid.upper(), "title": c.get("title", ""),
                             "withdrawn": _prop(c, "status") == "withdrawn"}
            walk(c.get("controls"))

    for group in groups:
        walk(group.get("controls"))
    if not controls:
        raise CatalogError("the catalog has no controls")
    return {
        "schema": SCHEMA,
        "framework": FRAMEWORK,
        "title": metadata["title"],
        "version": metadata["version"],
        "last_modified": metadata["last-modified"],
        "oscal_version": metadata.get("oscal-version"),
        "source_url": source_url,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved": retrieved,
        "controls": dict(sorted(controls.items())),
    }


def fetch_index(url: str = CATALOG_URL, fetch=fetch_catalog, clock=None) -> dict:
    now = (clock or (lambda: dt.datetime.now(dt.timezone.utc)))()
    return build_index(fetch(url), url, now.replace(microsecond=0).isoformat().replace("+00:00", "Z"))


def load_index(path: Path = PINNED_INDEX) -> dict:
    try:
        index = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CatalogError(f"cannot read the NIST catalog index {path}: {exc}") from exc
    if not isinstance(index, dict) or index.get("schema") != SCHEMA or not isinstance(index.get("controls"), dict) \
            or not isinstance(index.get("version"), str):
        raise CatalogError(f"{path} is not a {SCHEMA} document")
    return index


def summary(index: dict) -> dict:
    """What a run records about the catalog it checked against."""
    return {k: index[k] for k in ("framework", "version", "last_modified", "source_url", "source_sha256", "retrieved")}


def check_refs(control_id: str, refs: list[dict], index: dict) -> tuple[list[str], list[dict]]:
    """Resolve a control's NIST references; returns (problems, refs with catalog labels and titles)."""
    problems, resolved = [], []
    for ref in refs:
        if ref.get("framework") != FRAMEWORK:
            resolved.append(ref)
            continue
        cid, version = ref.get("id"), ref.get("catalog_version")
        entry = index["controls"].get(cid)
        if version != index["version"]:
            problems.append(f"{control_id}: {cid} names catalog version {version!r}, "
                            f"but the pinned catalog is {index['version']}")
        if entry is None:
            problems.append(f"{control_id}: {cid} is not in NIST SP 800-53 {index['version']}")
        elif entry["withdrawn"]:
            problems.append(f"{control_id}: {cid} ({entry['label']}) is withdrawn in NIST SP 800-53 {index['version']}")
        else:
            resolved.append({**ref, "label": entry["label"], "title": entry["title"]})
    return problems, resolved
