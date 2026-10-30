#!/usr/bin/env python3
"""Semantic versioning driven by Conventional Commits.

  release.py next                 print the next version, from commits since the last v* tag
  release.py prepare [--date D]   write VERSION and add that version's section to CHANGELOG.md
  release.py notes VERSION        print a version's CHANGELOG section (release notes)

Bump rules: a "!" header or a BREAKING CHANGE footer -> major; feat -> minor;
fix, perf, sec -> patch; other types don't cut a release on their own. While
the major version is 0 (initial development), a breaking change bumps the
minor version instead, as SemVer allows for 0.y.z.

Release flow: run `prepare` on a branch, review VERSION and CHANGELOG.md in a
PR, merge. The release workflow then tags vX.Y.Z and publishes the notes.
See standards/sdlc/versioning.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.dont_write_bytecode = True  # keep the managed .governance/tools/ free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_commit_msg import HEADER_RE  # noqa: E402

VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE: ", re.M)
SECTIONS = (("breaking", "Breaking changes"), ("feat", "Added"), ("sec", "Security"),
            ("fix", "Fixed"), ("perf", "Performance"))
UNRELEASED = "## [Unreleased]"


@dataclass(frozen=True)
class Commit:
    sha: str
    type: str
    scope: Optional[str]
    summary: str
    breaking: bool


def git(*args: str, cwd: Optional[Path] = None) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, cwd=cwd).stdout


def last_tag(cwd: Optional[Path] = None) -> Optional[str]:
    try:
        return git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", cwd=cwd).strip() or None
    except subprocess.CalledProcessError:
        return None


def commits_since(tag: Optional[str], cwd: Optional[Path] = None) -> list[Commit]:
    rev = f"{tag}..HEAD" if tag else "HEAD"
    out = git("log", "--no-merges", "--format=%H%x00%B%x01", rev, cwd=cwd)
    commits = []
    for record in out.split("\x01"):
        if "\x00" not in record:
            continue
        sha, message = record.strip("\n").split("\x00", 1)
        header = message.strip().splitlines()[0] if message.strip() else ""
        m = HEADER_RE.match(header)
        if not m:
            continue  # non-conventional (e.g. "Initial commit"): not a release signal
        summary = header.split(": ", 1)[1]
        commits.append(Commit(sha, m.group("type"), m.group("scope"), summary,
                              bool(m.group("breaking") or BREAKING_FOOTER.search(message))))
    return commits


def parse(version: str) -> tuple[int, int, int]:
    m = VERSION_RE.match(version.strip())
    if not m:
        raise ValueError(f"not a version: {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def bump(current: tuple[int, int, int], commits: list[Commit]) -> Optional[tuple[int, int, int]]:
    major, minor, patch = current
    if any(c.breaking for c in commits):
        return (major, minor + 1, 0) if major == 0 else (major + 1, 0, 0)
    if any(c.type == "feat" for c in commits):
        return (major, minor + 1, 0)
    if any(c.type in ("fix", "perf", "sec") for c in commits):
        return (major, minor, patch + 1)
    return None


def fmt(v: tuple[int, int, int]) -> str:
    return ".".join(map(str, v))


def next_version(cwd: Optional[Path] = None) -> tuple[Optional[str], list[Commit]]:
    tag = last_tag(cwd)
    commits = commits_since(tag, cwd)
    new = bump(parse(tag) if tag else (0, 0, 0), commits)
    return (fmt(new) if new else None), commits


def section(version: str, date: str, commits: list[Commit], carried: str) -> str:
    lines = [f"## [{version}] - {date}", ""]
    if carried.strip():
        lines += [carried.strip(), ""]
    for key, title in SECTIONS:
        picked = [c for c in commits if (c.breaking if key == "breaking" else (c.type == key and not c.breaking))]
        if picked:
            lines += [f"### {title}", ""]
            lines += [f"- {c.summary}" + (f" ({c.scope})" if c.scope else "") + f" ({c.sha[:7]})" for c in picked]
            lines.append("")
    return "\n".join(lines)


def prepare(root: Path, date: str) -> int:
    version, commits = next_version(root)
    if version is None:
        print("Nothing to release: no feat, fix, perf, sec or breaking commits since the last tag.")
        return 0
    changelog = root / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8") if changelog.exists() else (
        "# Changelog\n\nAll notable changes, newest first. Versions follow "
        "[Semantic Versioning](https://semver.org/).\n\n" + UNRELEASED + "\n")
    if f"## [{version}]" in text:
        print(f"CHANGELOG.md already has {version}", file=sys.stderr)
        return 1
    head, _, rest = text.partition(UNRELEASED)
    if not _:
        print(f"CHANGELOG.md has no '{UNRELEASED}' heading", file=sys.stderr)
        return 1
    nxt = rest.find("\n## [")
    carried, older = (rest[:nxt], rest[nxt + 1:]) if nxt >= 0 else (rest, "")
    new_text = (head + UNRELEASED + "\n\n" + section(version, date, commits, carried)
                + ("\n" + older if older else ""))
    changelog.write_text(new_text.rstrip("\n") + "\n", encoding="utf-8")
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
    print(version)
    return 0


def notes(root: Path, version: str) -> int:
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.S | re.M)
    if not m:
        print(f"no CHANGELOG section for {version}", file=sys.stderr)
        return 1
    print(m.group(1).strip())
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("next")
    p = sub.add_parser("prepare")
    p.add_argument("--date", default=dt.date.today().isoformat())
    n = sub.add_parser("notes")
    n.add_argument("version")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root)

    if args.cmd == "next":
        version, _ = next_version(root)
        print(version or "none")
        return 0
    if args.cmd == "prepare":
        return prepare(root, args.date)
    return notes(root, args.version)


if __name__ == "__main__":
    sys.exit(main())
