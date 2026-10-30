#!/usr/bin/env python3
"""Block personal data (PII) from entering a repository.

Modes:
  pii_scan.py FILE...              scan files (pre-commit passes staged files)
  pii_scan.py --git-range A..B     scan every line added by each commit in a range (CI)
  pii_scan.py --claude-hook        read a Claude Code PreToolUse payload on stdin and
                                   block Write/Edit calls that would add PII

Suppressing a confirmed false positive:
  - put `pii-scan: allow` on the same line,
  - list exact public values (one per line, `#` comments) in `.pii-allowlist`
    at the repo root, e.g. an organization's published contact number, or
  - list path globs (one per line, `#` comments) in `.piiignore` at the repo root.

Role addresses (info@, privacy@, support@, ...) are not personal data and pass.

Findings are printed masked so the scanner never re-leaks what it catches into
terminal scrollback or CI logs.

Exit codes: 0 clean, 1 findings, 2 findings in --claude-hook mode (blocks the call).
Standard library only, so it runs anywhere Python 3.9+ does.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

ALLOW_MARKER = "pii-scan: allow"
IGNORE_FILE = ".piiignore"
ALLOWLIST_FILE = ".pii-allowlist"
POLICY_DOC = "standards/privacy/pii.md"
MAX_FILE_BYTES = 5 * 1024 * 1024

# Reserved / documentation-only values that are safe to use in examples and tests.
SAFE_EMAIL_DOMAINS = (
    "example.com", "example.org", "example.net", "example",
    "test", "invalid", "localhost", "users.noreply.github.com", "noreply.github.com",
)
SAFE_EMAIL_LOCAL_PARTS = {"noreply", "no-reply", "donotreply", "do-not-reply", "git"}
# Shared role mailboxes an organization publishes; they identify a function, not a person.
ROLE_EMAIL_LOCAL_PARTS = {
    "info", "contact", "hello", "privacy", "dpo", "security", "support", "help", "sales",
    "billing", "accounts", "admin", "abuse", "postmaster", "hostmaster", "webmaster",
    "press", "media", "careers", "jobs", "legal", "office", "team", "service",
}
SAFE_PHONE_EXCHANGES = {"555"}  # NANP fictional exchange
KNOWN_EXAMPLE_SSNS = {"078051120", "123456789", "219099999"}
KNOWN_EXAMPLE_SINS = {"046454286", "123456782"}
# Published payment-processor test card numbers (Stripe, Braintree, Adyen, etc.).
TEST_CARD_NUMBERS = {
    "4111111111111111", "4242424242424242", "4000056655665556", "4012888888881881",
    "4222222222222", "5555555555554444", "5200828282828210", "5105105105105100",
    "2223003122003222", "378282246310005", "371449635398431", "6011111111111117",
    "6011000990139424", "3056930009020004", "36227206271667", "3566002020360505",
    "3530111333300000", "6200000000000005",
}
EXAMPLE_IBANS = {"GB82WEST12345698765432", "DE89370400440532013000"}

_NB = r"(?<![0-9A-Za-z_])"  # not preceded by a word character
_NA = r"(?![0-9A-Za-z_])"   # not followed by a word character


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    value: str
    commit: Optional[str] = None

    def render(self) -> str:
        where = f"{self.path}:{self.line}"
        if self.commit:
            where = f"{self.commit[:12]} {where}"
        return f"{where}: [{self.kind}] {mask(self.value)}"


def mask(value: str) -> str:
    """Hide all but enough characters to locate the value."""
    compact = re.sub(r"[\s-]", "", value)
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain[:1]}***"
    if len(compact) <= 6:
        return "*" * len(compact)
    return "*" * (len(compact) - 4) + compact[-4:]


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# --- detectors --------------------------------------------------------------
# Each detector returns the matched values in a line that are real findings.

EMAIL_RE = re.compile(_NB + r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}" + _NA)


def detect_email(line: str) -> list[str]:
    out = []
    for m in EMAIL_RE.finditer(line):
        local, _, domain = m.group(0).lower().partition("@")
        if local in SAFE_EMAIL_LOCAL_PARTS or local in ROLE_EMAIL_LOCAL_PARTS:
            continue
        if any(domain == d or domain.endswith("." + d) for d in SAFE_EMAIL_DOMAINS):
            continue
        out.append(m.group(0))
    return out


# North American numbers must be visibly formatted, which keeps IDs and
# timestamps from matching; other countries need an explicit +CC prefix.
NANP_RE = re.compile(
    _NB + r"(?:\+?1[\s.-]?)?(?:\(([2-9]\d{2})\)\s?|([2-9]\d{2})[\s.-])([2-9]\d{2})[\s.-](\d{4})" + _NA
)
NANP_E164_RE = re.compile(r"(?<![\w+])\+1([2-9]\d{2})([2-9]\d{2})(\d{4})" + _NA)
INTL_RE = re.compile(r"(?<![\w+])\+(?!1)[2-9]\d{0,2}(?:[\s.-]?\d){7,12}" + _NA)


def detect_phone(line: str) -> list[str]:
    out = []
    for m in NANP_RE.finditer(line):
        if m.group(3) not in SAFE_PHONE_EXCHANGES:
            out.append(m.group(0).strip())
    for m in NANP_E164_RE.finditer(line):
        if m.group(2) not in SAFE_PHONE_EXCHANGES:
            out.append(m.group(0))
    out.extend(m.group(0) for m in INTL_RE.finditer(line))
    return out


SSN_RE = re.compile(_NB + r"(\d{3})-(\d{2})-(\d{4})" + _NA)


def detect_us_ssn(line: str) -> list[str]:
    out = []
    for m in SSN_RE.finditer(line):
        area, group, serial = m.groups()
        if area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000":
            continue
        if area + group + serial in KNOWN_EXAMPLE_SSNS:
            continue
        out.append(m.group(0))
    return out


SIN_RE = re.compile(_NB + r"(\d{3})([ -])(\d{3})\2(\d{3})" + _NA)


def detect_ca_sin(line: str) -> list[str]:
    out = []
    for m in SIN_RE.finditer(line):
        digits = m.group(1) + m.group(3) + m.group(4)
        # 0 is never issued; 8 is used for business numbers, not people.
        if digits[0] in "08" or digits in KNOWN_EXAMPLE_SINS or not luhn_ok(digits):
            continue
        out.append(m.group(0))
    return out


CARD_RE = re.compile(_NB + r"\d(?:[ -]?\d){12,18}" + _NA)
CARD_PREFIX_RE = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|3(?:0[0-5]|[68])|6(?:011|5|2)|35)")


def detect_card(line: str) -> list[str]:
    out = []
    for m in CARD_RE.finditer(line):
        digits = _digits(m.group(0))
        if not 13 <= len(digits) <= 19 or not CARD_PREFIX_RE.match(digits):
            continue
        if digits in TEST_CARD_NUMBERS or len(set(digits)) == 1 or not luhn_ok(digits):
            continue
        out.append(m.group(0))
    return out


IBAN_RE = re.compile(_NB + r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?" + _NA)


def iban_ok(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def detect_iban(line: str) -> list[str]:
    out = []
    for m in IBAN_RE.finditer(line):
        compact = m.group(0).replace(" ", "")
        if 15 <= len(compact) <= 34 and compact not in EXAMPLE_IBANS and iban_ok(compact):
            out.append(m.group(0))
    return out


DETECTORS: dict[str, Callable[[str], list[str]]] = {
    "email": detect_email,
    "phone": detect_phone,
    "us-ssn": detect_us_ssn,
    "ca-sin": detect_ca_sin,
    "payment-card": detect_card,
    "iban": detect_iban,
}


def _normalize(value: str) -> str:
    return re.sub(r"[\s.()-]", "", value).lower()


def scan_text(text: str, path: str, commit: Optional[str] = None, first_line: int = 1,
              allow: frozenset = frozenset()) -> list[Finding]:
    findings = []
    for offset, line in enumerate(text.splitlines()):
        if ALLOW_MARKER in line:
            continue
        for kind, detect in DETECTORS.items():
            for value in detect(line):
                if _normalize(value) in allow:
                    continue
                findings.append(Finding(path, first_line + offset, kind, value, commit))
    return findings


# --- ignore handling --------------------------------------------------------

def load_allowlist(root: Path) -> frozenset:
    try:
        lines = (root / ALLOWLIST_FILE).read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(_normalize(ln.split("#", 1)[0]) for ln in lines if ln.split("#", 1)[0].strip())


def load_ignore(root: Path) -> list[str]:
    try:
        lines = (root / IGNORE_FILE).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def is_ignored(path: str, patterns: Iterable[str], root: Optional[Path] = None) -> bool:
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(root or Path.cwd())
        except ValueError:
            pass
    posix = p.as_posix()
    return any(fnmatch.fnmatch(posix, p) or fnmatch.fnmatch(Path(posix).name, p) for p in patterns)


# --- modes ------------------------------------------------------------------

def scan_files(paths: Iterable[str], ignore: list[str], allow: frozenset = frozenset()) -> list[Finding]:
    findings = []
    for p in paths:
        if is_ignored(p, ignore):
            continue
        path = Path(p)
        try:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        findings.extend(scan_text(data.decode("utf-8", errors="replace"), p, allow=allow))
    return findings


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def iter_added_lines(log_output: str) -> Iterator[tuple[str, str, int, str]]:
    """Yield (commit, path, line_no, text) for every added line in `git log -p -U0` output."""
    commit, path, line_no, in_header = "", None, 0, False
    for raw in log_output.splitlines():
        if raw.startswith("COMMIT:"):
            commit, in_header = raw[len("COMMIT:"):], False
        elif raw.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and raw.startswith("+++ "):
            target = raw[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif raw.startswith("@@"):
            m = HUNK_RE.match(raw)
            line_no, in_header = (int(m.group(1)) if m else 0), False
        elif not in_header and path and raw.startswith("+"):
            yield commit, path, line_no, raw[1:]
            line_no += 1


def scan_git_range(rev_range: str, ignore: list[str], allow: frozenset = frozenset()) -> list[Finding]:
    log = subprocess.run(
        ["git", "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=COMMIT:%H", rev_range],
        check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout
    findings = []
    for commit, path, line_no, text in iter_added_lines(log):
        if not is_ignored(path, ignore):
            findings.extend(scan_text(text, path, commit, line_no, allow))
    return findings


def hook_payload_text(payload: dict) -> tuple[str, str]:
    """Return (path, text-being-written) for file-writing tools; empty text otherwise."""
    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or "<unknown>"
    parts = [tool_input.get("content"), tool_input.get("new_string"), tool_input.get("new_source")]
    parts += [e.get("new_string") for e in tool_input.get("edits") or [] if isinstance(e, dict)]
    return path, "\n".join(p for p in parts if isinstance(p, str))


def run_claude_hook() -> int:
    # Hooks can fire from a subdirectory; resolve .piiignore from the project root.
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path.cwd())
    ignore = load_ignore(root)
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # not our payload; never wedge the agent on malformed input
    path, text = hook_payload_text(payload)
    if not text or is_ignored(path, ignore, root):
        return 0
    findings = scan_text(text, path, allow=load_allowlist(root))
    if not findings:
        return 0
    print("PII scan blocked this write. Replace these values with synthetic data "
          "(example.com addresses, 555 phone numbers, published test card numbers):", file=sys.stderr)
    for f in findings:
        print(f"  [{f.kind}] {mask(f.value)} (offset line {f.line})", file=sys.stderr)
    print(f"Policy: {POLICY_DOC}. If this is a confirmed false positive, add "
          f"'{ALLOW_MARKER}' on that line and say why in the PR.", file=sys.stderr)
    return 2


def report(findings: list[Finding]) -> int:
    if not findings:
        return 0
    for f in findings:
        print(f.render())
    print(f"\n{len(findings)} possible PII value(s) found. Replace them with synthetic data; "
          f"see {POLICY_DOC}.\nFalse positive? Add '{ALLOW_MARKER}' to the line or a glob to {IGNORE_FILE}.",
          file=sys.stderr)
    return 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--git-range", metavar="A..B", help="scan lines added by commits in this range")
    mode.add_argument("--claude-hook", action="store_true", help="act as a Claude Code PreToolUse hook")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)

    if args.claude_hook:
        return run_claude_hook()
    ignore, allow = load_ignore(Path.cwd()), load_allowlist(Path.cwd())
    if args.git_range:
        return report(scan_git_range(args.git_range, ignore, allow))
    return report(scan_files(args.files, ignore, allow))


if __name__ == "__main__":
    sys.exit(main())
