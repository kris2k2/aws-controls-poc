#!/usr/bin/env python3
"""Enforce the commit message policy.

Rejects commit messages that:
  - don't start with a Conventional Commits header ("type(scope)!: summary"),
    which release tooling reads to choose the next semantic version,
  - link to AI agent sessions or conversation transcripts (they can hold
    secrets, personal data, and internal context, and anyone with the link
    may be able to open them long after the commit lands), or
  - contain personal data (same detectors as tools/pii_scan.py).

Attribution trailers such as `Co-Authored-By:` are fine.

Modes:
  check_commit_msg.py MSG_FILE          commit-msg hook (pre-commit passes the file)
  check_commit_msg.py --git-range A..B  check every commit message in a range (CI)

Exit codes: 0 clean, 1 violations.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.dont_write_bytecode = True  # keep the managed .governance/tools/ free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pii_scan  # noqa: E402

POLICY_DOC = "standards/sdlc/workflow.md#commits"
SCISSORS = "# ------------------------ >8 ------------------------"

# Types and what they mean for the version: feat -> minor, fix/perf/sec -> patch,
# "!" or a BREAKING CHANGE footer -> major; the rest don't trigger a release.
COMMIT_TYPES = ("feat", "fix", "perf", "sec", "docs", "test", "refactor", "style",
                "build", "ci", "chore", "revert")
HEADER_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[\w./-]+)\))?(?P<breaking>!)?: \S.*$")
# Messages git or GitHub generate, and local fixups that are squashed before merge.
GENERATED_RE = re.compile(r'^(Merge (pull request|branch|remote-tracking branch) |Revert "|fixup! |squash! |amend! )')

SESSION_LINKS = [
    (re.compile(r"^[\w-]*-Session:\s*\S+", re.I | re.M), "agent session trailer"),
    (re.compile(r"claude\.ai/(?:code/session_|code/[\w-]+/session|chat/|share/)", re.I), "Claude session link"),
    (re.compile(r"(?:chatgpt\.com|chat\.openai\.com)/(?:c|share|g)/", re.I), "ChatGPT conversation link"),
    (re.compile(r"(?:gemini\.google\.com/(?:app|share)/|g\.co/gemini/share/)", re.I), "Gemini conversation link"),
    (re.compile(r"copilot\.microsoft\.com/(?:chats|shares)/", re.I), "Copilot conversation link"),
]


def clean_message(raw: str) -> str:
    """Drop the parts git strips before committing: comments and the verbose diff."""
    body = raw.split(SCISSORS, 1)[0]
    return "\n".join(ln for ln in body.splitlines() if not ln.startswith("#"))


def header_problem(message: str) -> Optional[str]:
    header = message.strip().splitlines()[0] if message.strip() else ""
    if GENERATED_RE.match(header):
        return None
    m = HEADER_RE.match(header)
    if not m:
        return f"header '{header[:60]}' isn't Conventional Commits (type(scope)!: summary)"
    if m.group("type") not in COMMIT_TYPES:
        return f"unknown commit type '{m.group('type')}' (use one of: {', '.join(COMMIT_TYPES)})"
    if len(header) > 100:
        return "header is longer than 100 characters"
    return None


def violations(message: str) -> list[str]:
    found = []
    if problem := header_problem(message):
        found.append(problem)
    for pattern, label in SESSION_LINKS:
        if pattern.search(message):
            found.append(label)
    for f in pii_scan.scan_text(message, "<commit message>"):
        found.append(f"{f.kind} {pii_scan.mask(f.value)}")
    return found


def check_range(rev_range: str) -> list[tuple[str, list[str]]]:
    out = subprocess.run(
        ["git", "log", "--format=%H%x00%B%x01", rev_range],
        check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).stdout
    results = []
    for record in out.split("\x01"):
        if "\x00" not in record:
            continue
        sha, message = record.strip("\n").split("\x00", 1)
        problems = violations(message)
        if problems:
            results.append((sha, problems))
    return results


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--git-range", metavar="A..B", help="check every commit message in this range")
    parser.add_argument("msg_file", nargs="?", help="commit message file (commit-msg hook)")
    args = parser.parse_args(argv)

    if args.git_range:
        bad = check_range(args.git_range)
    elif args.msg_file:
        problems = violations(clean_message(Path(args.msg_file).read_text(encoding="utf-8", errors="replace")))
        bad = [("this commit", problems)] if problems else []
    else:
        parser.error("pass a commit message file or --git-range")

    for sha, problems in bad:
        print(f"{sha[:12]}: {'; '.join(problems)}")
    if bad:
        print(f"\nCommit message policy violated; see {POLICY_DOC}. Remove agent session or "
              "conversation links and personal data, then reword the commit.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
