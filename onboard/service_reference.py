"""Client for the AWS service reference: actions, resources and condition keys.

The service reference is AWS's machine-readable IAM contract for each service
prefix. It is the authoritative source for Resolve. Fetched content is data:
only the expected JSON fields are read, and nothing in it is executed or
followed except service URLs on the allowlisted host.
"""

from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"
ALLOWED_HOSTS = frozenset({"servicereference.us-east-1.amazonaws.com"})
MAX_BYTES = 32 * 1024 * 1024  # the largest service files (ec2) are a few MB
TIMEOUT_SECONDS = 30


class SourceError(RuntimeError):
    """A source could not be fetched or did not have the expected shape."""


@dataclass(frozen=True)
class Fetched:
    url: str
    retrieved: str  # ISO 8601 UTC timestamp
    document: object


Fetcher = Callable[[str], bytes]


def check_url(url: str) -> str:
    """Refuse anything but HTTPS to the service reference host (SSRF guard)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443) \
            or parts.username or parts.password:
        raise SourceError(f"refusing to fetch {url!r}: not an HTTPS URL on {', '.join(sorted(ALLOWED_HOSTS))}")
    return url


def http_fetch(url: str) -> bytes:
    request = urllib.request.Request(check_url(url), headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - URL checked above
            # A redirect could leave the allowlisted host; check where we ended up.
            check_url(response.geturl())
            body = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise SourceError(f"could not fetch {url}: {exc}") from exc
    if len(body) > MAX_BYTES:
        raise SourceError(f"{url} is larger than {MAX_BYTES} bytes")
    return body


class ServiceReference:
    """Reads the index and per-service files through an injectable fetcher."""

    def __init__(self, fetch: Fetcher = http_fetch, clock: Callable[[], dt.datetime] | None = None):
        self._fetch = fetch
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._index: Fetched | None = None

    def _get(self, url: str) -> Fetched:
        check_url(url)
        retrieved = self._clock().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        try:
            document = json.loads(self._fetch(url))
        except ValueError as exc:
            raise SourceError(f"{url} did not return JSON") from exc
        return Fetched(url, retrieved, document)

    def index(self) -> Fetched:
        """The list of service prefixes, each with the URL of its file."""
        if self._index is None:
            fetched = self._get(INDEX_URL)
            entries = fetched.document
            if not isinstance(entries, list) or not all(
                    isinstance(e, dict) and isinstance(e.get("service"), str) and isinstance(e.get("url"), str)
                    for e in entries):
                raise SourceError("service reference index is not a list of {service, url} entries")
            self._index = fetched
        return self._index

    def prefixes(self) -> dict[str, dict]:
        return {e["service"]: e for e in self.index().document}

    def service(self, prefix: str) -> Fetched:
        entry = self.prefixes().get(prefix)
        if entry is None:
            raise SourceError(f"{prefix!r} is not a service prefix in the service reference")
        fetched = self._get(entry["url"])
        document = fetched.document
        if not isinstance(document, dict) or document.get("Name") != prefix \
                or not isinstance(document.get("Actions"), list):
            raise SourceError(f"service reference file for {prefix!r} has an unexpected shape")
        return fetched
