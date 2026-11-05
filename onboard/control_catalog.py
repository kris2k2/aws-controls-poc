"""Client for the AWS Control Catalog: AWS's own controls, severities and framework mappings.

Assess reads it to find the Security Hub controls that govern a service's
resources (ADR-0007). It is the tool's only signed source:

- Read-only. Only `ListControls` and `ListControlMappings` can be called; the
  IAM actions they need (`controlcatalog:ListControls`,
  `controlcatalog:ListControlMappings`) are List-level in the service reference.
- One host, in the home region: `controlcatalog.ca-central-1.amazonaws.com`.
  Redirects are refused, so a response can't move the request elsewhere.
- Credentials come from the standard AWS environment variables at call time.
  They are never written to a file, a snapshot, a log line or an error.
- Responses are data. Only the expected JSON fields are read (by Assess), and
  pagination stops on a repeated token or after `MAX_PAGES`.

The protocol (rest-json, SigV4 signing name `controlcatalog`, POST routes) is
from AWS's API reference and the botocore service model 2018-05-10.
Offline runs replay a snapshot directory (`snapshot_transport`); a live run can
record one (`recording_transport`).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from .service_reference import SourceError

REGION = "ca-central-1"
SIGNING_NAME = "controlcatalog"
HOST = f"controlcatalog.{REGION}.amazonaws.com"
ALLOWED_HOSTS = frozenset({HOST})
# Operation -> (route, largest page size the API accepts).
OPERATIONS = {
    "ListControls": ("/list-controls", 100),
    "ListControlMappings": ("/list-control-mappings", 1000),
}
MAX_PAGES = 100            # the whole Security Hub set is a few pages of 100
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 30
SNAPSHOT_SCHEMA = "control-catalog-snapshot/v1"

# (operation, query, body) -> response document
Transport = Callable[[str, dict, dict], dict]


@dataclass(frozen=True)
class Credentials:
    access_key: str
    secret_key: str = field(repr=False)
    token: str | None = field(default=None, repr=False)


def credentials_from_env(env: Mapping[str, str] = os.environ) -> Credentials:
    """Read credentials from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN."""
    access, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    if not access or not secret:
        raise SourceError("the Control Catalog needs AWS credentials: set AWS_ACCESS_KEY_ID and "
                          "AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials), "
                          "or pass --control-catalog-snapshot for an offline run")
    return Credentials(access, secret, env.get("AWS_SESSION_TOKEN") or None)


def check_url(url: str) -> str:
    """Refuse anything but HTTPS to the Control Catalog host in the home region (SSRF guard)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443) \
            or parts.username or parts.password:
        raise SourceError(f"refusing to call {url!r}: not an HTTPS URL on {', '.join(sorted(ALLOWED_HOSTS))}")
    return url


def body_bytes(body: dict) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="-_.~")


def canonical_query(query: Mapping[str, str]) -> str:
    return "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(query.items()))


def sign(method: str, host: str, path: str, query: Mapping[str, str], body: bytes,
         credentials: Credentials, now: dt.datetime,
         region: str = REGION, service: str = SIGNING_NAME) -> dict[str, str]:
    """Return the headers for an AWS Signature Version 4 request (Content-Type, X-Amz-*, Authorization)."""
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    headers = {"content-type": "application/json", "host": host, "x-amz-date": amz_date}
    if credentials.token:
        headers["x-amz-security-token"] = credentials.token
    signed = ";".join(sorted(headers))
    canonical = "\n".join([
        method, "/".join(_quote(s) for s in path.split("/")), canonical_query(query),
        "".join(f"{k}:{' '.join(headers[k].split())}\n" for k in sorted(headers)),
        signed, hashlib.sha256(body).hexdigest(),
    ])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + credentials.secret_key).encode()
    for part in (date, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {"Content-Type": headers["content-type"], "X-Amz-Date": amz_date,
           "Authorization": f"AWS4-HMAC-SHA256 Credential={credentials.access_key}/{scope}, "
                            f"SignedHeaders={signed}, Signature={signature}"}
    if credentials.token:
        out["X-Amz-Security-Token"] = credentials.token
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None  # urllib then raises HTTPError for the 3xx


def _error_detail(exc: urllib.error.HTTPError) -> str:
    """The AWS error type and message, never the request (which carries the signature)."""
    kind = exc.headers.get("x-amzn-ErrorType", "") if exc.headers else ""
    try:
        doc = json.loads(exc.read(64 * 1024) or b"{}")
        message = doc.get("message") or doc.get("Message") or ""
        kind = kind or doc.get("__type", "")
    except (OSError, ValueError, AttributeError):
        message = ""
    return f"HTTP {exc.code} {kind.split(':')[0]} {str(message)[:200]}".strip()


def http_transport(credentials: Credentials | None = None,
                   clock: Callable[[], dt.datetime] | None = None) -> Transport:
    """A signed HTTPS transport. Credentials are read from the environment on first use if not given."""
    opener = urllib.request.build_opener(_NoRedirect)
    clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
    held: list[Credentials] = [credentials] if credentials else []

    def call(operation: str, query: dict, body: dict) -> dict:
        if operation not in OPERATIONS:
            raise SourceError(f"refusing to call {operation}: only {', '.join(OPERATIONS)} are allowed")
        if not held:
            held.append(credentials_from_env())
        path = OPERATIONS[operation][0]
        url = check_url(f"https://{HOST}{path}" + (f"?{canonical_query(query)}" if query else ""))
        data = body_bytes(body)
        headers = sign("POST", HOST, path, query, data, held[0], clock())
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - URL checked above
                check_url(response.geturl())
                raw = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise SourceError(f"Control Catalog {operation} failed: {_error_detail(exc)}") from None
        except OSError as exc:
            raise SourceError(f"could not reach the Control Catalog ({operation}): {exc}") from None
        if len(raw) > MAX_BYTES:
            raise SourceError(f"Control Catalog {operation} returned more than {MAX_BYTES} bytes")
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise SourceError(f"Control Catalog {operation} returned invalid JSON: {exc}") from None
        if not isinstance(document, dict):
            raise SourceError(f"Control Catalog {operation} returned {type(document).__name__}, not an object")
        return document

    return call


# ---------------------------------------------------------------- snapshots


def request_key(operation: str, query: dict, body: dict) -> str:
    return json.dumps({"operation": operation, "query": query, "body": body}, sort_keys=True,
                      separators=(",", ":"))


def snapshot_transport(directory: Path) -> Transport:
    """Replay a recorded snapshot: `index.json` maps each exact request to a response file."""
    try:
        index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SourceError(f"cannot read the Control Catalog snapshot {directory}: {exc}") from None
    if not isinstance(index, dict) or index.get("schema") != SNAPSHOT_SCHEMA:
        raise SourceError(f"{directory / 'index.json'} is not a {SNAPSHOT_SCHEMA} document")
    responses = {}
    for entry in index.get("responses") or []:
        name = Path(entry.get("file", ""))
        if name.name != str(name) or not name.name.endswith(".json"):
            raise SourceError(f"snapshot response file {entry.get('file')!r} must be a plain .json file name")
        responses[request_key(entry["operation"], entry.get("query") or {}, entry.get("body") or {})] = name.name

    def call(operation: str, query: dict, body: dict) -> dict:
        name = responses.get(request_key(operation, query, body))
        if name is None:
            raise SourceError(f"the Control Catalog snapshot {directory} has no response for {operation} "
                              f"{json.dumps(body, sort_keys=True)} {json.dumps(query, sort_keys=True)}")
        try:
            return json.loads((directory / name).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SourceError(f"cannot read {directory / name}: {exc}") from None

    return call


def snapshot_metadata(directory: Path) -> dict:
    index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
    return {k: index.get(k) for k in ("retrieved", "region", "synthetic", "note")}


def recording_transport(inner: Transport, directory: Path, clock=None) -> Transport:
    """Pass calls to `inner` and save each request and response as a snapshot (no credentials)."""
    clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
    directory.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    def call(operation: str, query: dict, body: dict) -> dict:
        document = inner(operation, query, body)
        name = f"{len(entries) + 1:04d}-{operation}.json"
        (directory / name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        entries.append({"operation": operation, "query": query, "body": body, "file": name})
        (directory / "index.json").write_text(json.dumps({
            "schema": SNAPSHOT_SCHEMA, "region": REGION, "synthetic": False,
            "retrieved": clock().strftime("%Y-%m-%dT%H:%M:%SZ"), "responses": entries,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return document

    return call


# ---------------------------------------------------------------- client


class ControlCatalog:
    """The two read-only calls Assess makes, with pagination."""

    def __init__(self, transport: Transport):
        self._call = transport

    def _pages(self, operation: str, body: dict, key: str) -> list[dict]:
        size = OPERATIONS[operation][1]
        items, token, seen = [], None, set()
        for _ in range(MAX_PAGES):
            query = {"maxResults": str(size)}
            if token:
                query["nextToken"] = token
            page = self._call(operation, query, body)
            batch = page.get(key)
            if not isinstance(batch, list):
                raise SourceError(f"Control Catalog {operation} response has no {key} list")
            items += batch
            token = page.get("NextToken")
            if not token:
                return items
            if not isinstance(token, str) or token in seen:
                raise SourceError(f"Control Catalog {operation} returned a repeated or invalid NextToken")
            seen.add(token)
        raise SourceError(f"Control Catalog {operation} did not finish in {MAX_PAGES} pages")

    def list_controls(self, implementation_type: str) -> list[dict]:
        return self._pages("ListControls", {"Filter": {"Implementations": {"Types": [implementation_type]}}},
                           "Controls")

    def framework_mappings(self, control_arn: str) -> list[dict]:
        return self._pages("ListControlMappings",
                           {"Filter": {"ControlArns": [control_arn], "MappingTypes": ["FRAMEWORK"]}},
                           "ControlMappings")
