#!/usr/bin/env python3
"""Install, update and verify the governance baseline in a project.

A project carries the baseline in .governance/: a read-only copy of one
released version of the governance repository. .governance/MANIFEST.json
records the version and a hash of every file. Projects never edit it; they
update it with `sync`, which a weekly workflow proposes as a pull request.

  governance.py init  [--source DIR | --ref TAG|latest] [--project NAME] [--owner LOGIN] [--target DIR]
  governance.py sync  [--source DIR | --ref TAG|latest] [--allow-major] [--notes-file FILE] [--target DIR]
  governance.py check [--target DIR] [--no-upstream]
  governance.py ci    [--skip STEP]...      run every governance check (CI entry point)
  governance.py version                    print the installed version

--source is a local checkout of the governance repository. --ref fetches a
release tag from $GOVERNANCE_REPO (default below) with git, authenticating
with $GOVERNANCE_TOKEN when it's set (needed while the repository is private).
"latest" is the newest release in the installed major version (any version
for init); sync crosses a major version only with --allow-major.

Standard library only. See standards/sdlc/governance-adoption.md.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_REPO = "https://github.com/kris2k2/agents"
DIR = ".governance"
MANIFEST = "MANIFEST.json"
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

# What a project receives in .governance/ (paths in the governance repository).
MANAGED = (
    "AGENTS.md", "VERSION", "CHANGELOG.md",
    "standards/*/*.md",
    "templates/*.md",
    "templates/aws/github-ci-bootstrap.yaml",
    "templates/aws/cdk/project-guardrails.ts",
    "templates/project/*",
    "tools/pii_scan.py", "tools/check_commit_msg.py", "tools/check_runtimes.py",
    "tools/release.py", "tools/governance.py", "tools/requirements.txt",
)
# Starter files: templates/project/<name> -> path in the project. Created by
# init when missing; afterwards they belong to the project, and sync updates
# one only while the project hasn't changed it.
SCAFFOLD = {
    "AGENTS.md": "AGENTS.md",
    "CLAUDE.md": "CLAUDE.md",
    "governance.yml": ".github/workflows/governance.yml",
    "governance-sync.yml": ".github/workflows/governance-sync.yml",
    "pre-commit-config.yaml": ".pre-commit-config.yaml",
    "claude-settings.json": ".claude/settings.json",
    "pull_request_template.md": ".github/pull_request_template.md",
    "CODEOWNERS": ".github/CODEOWNERS",
    "dependabot.yml": ".github/dependabot.yml",
}
GITIGNORE_TEMPLATE = "gitignore"

# gitleaks, pinned by version and checksum (supply-chain standard).
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_SHA256 = {
    "x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
}


class GovernanceError(Exception):
    pass


# --- helpers ------------------------------------------------------------------

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str, cwd: Optional[Path] = None, auth: bool = False) -> str:
    cmd = ["git"]
    token = os.environ.get("GOVERNANCE_TOKEN")
    if auth and token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraHeader=AUTHORIZATION: basic {basic}"]
    result = subprocess.run([*cmd, *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise GovernanceError(f"git {args[0]} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def parse_tag(tag: str) -> Optional[tuple[int, int, int]]:
    m = TAG_RE.match(tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def release_tags(repo: str) -> list[str]:
    out = git("ls-remote", "--tags", "--refs", repo, auth=True)
    tags = [line.split("refs/tags/", 1)[1] for line in out.splitlines() if "refs/tags/" in line]
    return sorted((t for t in tags if parse_tag(t)), key=parse_tag)


def pick_latest(tags: list[str], major: Optional[int]) -> Optional[str]:
    eligible = [t for t in tags if major is None or parse_tag(t)[0] == major]
    return eligible[-1] if eligible else None


def managed_files(source: Path) -> list[str]:
    files = set()
    for pattern in MANAGED:
        for p in source.glob(pattern):
            if p.is_file():
                files.add(p.relative_to(source).as_posix())
    missing = [p for p in MANAGED if not any(fnmatch.fnmatch(f, p) for f in files)]
    if missing:
        raise GovernanceError(f"source is missing {', '.join(missing)}; is it a governance checkout?")
    return sorted(files)


class Source:
    """A governance release to install from: a local checkout or a fetched tag."""

    def __init__(self, path: Path, version: str, origin: str, commit: Optional[str], tmp=None):
        self.path, self.version, self.origin, self.commit, self._tmp = path, version, origin, commit, tmp

    @classmethod
    def local(cls, path: Path) -> "Source":
        version = (path / "VERSION").read_text(encoding="utf-8").strip()
        commit = None
        try:
            commit = git("rev-parse", "HEAD", cwd=path).strip()
            tagged = git("tag", "--points-at", "HEAD", cwd=path).split()
            if f"v{version}" not in tagged:
                version = f"{version}+dev.{commit[:7]}"
        except GovernanceError:
            version = f"{version}+local"
        return cls(path, version, "local", commit)

    @classmethod
    def fetch(cls, repo: str, ref: str, current_major: Optional[int]) -> "Source":
        if ref == "latest":
            tags = release_tags(repo)
            ref = pick_latest(tags, current_major)
            if ref is None:
                raise GovernanceError(f"no release tags in {repo}"
                                      + (f" for major version {current_major}" if current_major is not None else ""))
        tmp = tempfile.TemporaryDirectory(prefix="governance-")
        dest = Path(tmp.name) / "src"
        git("clone", "--quiet", "--depth", "1", "--branch", ref, repo, str(dest), auth=True)
        commit = git("rev-parse", "HEAD", cwd=dest).strip()
        version = (dest / "VERSION").read_text(encoding="utf-8").strip()
        if f"v{version}" != ref:
            raise GovernanceError(f"tag {ref} has VERSION {version}; refusing a mislabeled release")
        return cls(dest, version, repo, commit, tmp)


def open_source(args, current_major: Optional[int] = None) -> Source:
    if args.source:
        return Source.local(Path(args.source).resolve())
    return Source.fetch(os.environ.get("GOVERNANCE_REPO", DEFAULT_REPO), args.ref or "latest", current_major)


def read_manifest(target: Path) -> dict:
    path = target / DIR / MANIFEST
    if not path.exists():
        raise GovernanceError(f"{DIR}/{MANIFEST} not found; run `governance.py init` first")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(manifest.get("files"), list):
        manifest["files"] = {f["path"]: f["sha256"] for f in manifest["files"]}
    return manifest


def write_manifest(gdir: Path, manifest: dict) -> None:
    # Files are stored as {"path", "sha256"} objects, not {path: hash}: a hash
    # next to a name like "secrets.md" looks like an API key to secret scanners.
    stored = {**manifest, "files": [{"path": p, "sha256": h} for p, h in sorted(manifest["files"].items())]}
    (gdir / MANIFEST).write_text(json.dumps(stored, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render(template: str, manifest: dict) -> str:
    return template.replace("{{PROJECT}}", manifest["project"]).replace("{{OWNER}}", manifest["owner"])


def install(source: Source, target: Path, project: str, owner: str) -> dict:
    """Replace target/.governance with the source's managed files."""
    gdir = target / DIR
    if gdir.exists():
        shutil.rmtree(gdir)
    files = {}
    for rel in managed_files(source.path):
        dest = gdir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source.path / rel, dest)
        if rel.startswith("tools/") and rel.endswith(".py"):
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        files[rel] = sha256(dest)
    manifest = {
        "schema": 1, "version": source.version, "source": source.origin, "commit": source.commit,
        "project": project, "owner": owner, "files": files,
    }
    write_manifest(gdir, manifest)
    return manifest


def scaffold_templates(gdir: Path, manifest: dict) -> dict[str, str]:
    tdir = gdir / "templates" / "project"
    return {dest: render((tdir / name).read_text(encoding="utf-8"), manifest)
            for name, dest in SCAFFOLD.items() if (tdir / name).exists()}


def merge_gitignore(target: Path, gdir: Path) -> list[str]:
    template = gdir / "templates" / "project" / GITIGNORE_TEMPLATE
    if not template.exists():
        return []
    path = target / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    wanted = [ln for ln in template.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    missing = [ln for ln in wanted if ln not in existing]
    if missing:
        block = ["", "# Governance baseline (.governance/templates/project/gitignore)", *missing]
        path.write_text("\n".join(existing + block).lstrip("\n") + "\n", encoding="utf-8")
    return missing


def default_owner(target: Path) -> str:
    try:
        url = git("remote", "get-url", "origin", cwd=target).strip()
    except GovernanceError:
        return "OWNER"
    m = re.search(r"github\.com[:/]+([^/]+)/", url)
    return m.group(1) if m else "OWNER"


# --- commands --------------------------------------------------------------------

def cmd_init(args) -> int:
    target = Path(args.target).resolve()
    if (target / DIR).exists():
        raise GovernanceError(f"{DIR}/ already exists; use `governance.py sync` to update it")
    source = open_source(args)
    project = args.project or re.sub(r"[^a-z0-9-]+", "-", target.name.lower()).strip("-")
    manifest = install(source, target, project, args.owner or default_owner(target))
    created, kept = [], []
    for dest, content in scaffold_templates(target / DIR, manifest).items():
        path = target / dest
        if path.exists():
            kept.append(dest)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(dest)
    ignored = merge_gitignore(target, target / DIR)
    print(f"Installed governance {manifest['version']} into {DIR}/ for project '{project}'.")
    for dest in created:
        print(f"  created {dest}")
    for dest in kept:
        print(f"  kept existing {dest}: merge in {DIR}/templates/project/ by hand")
    if ignored:
        print(f"  added {len(ignored)} line(s) to .gitignore")
    print("""
Next steps:
  1. Review and commit everything on a branch; open a PR.
  2. pip install pre-commit && pre-commit install
  3. GitHub settings: protect main (PRs, code-owner review, the governance check);
     enable secret scanning + push protection; allow GitHub Actions to create
     pull requests (for governance-sync).
  4. While the governance repository is private, add a read-only token for it as
     the GOVERNANCE_READ_TOKEN secret (used by governance-sync and upstream checks).""")
    return 0


def changelog_between(changelog: Path, old: str, new: str) -> str:
    """CHANGELOG sections newer than `old`, up to and including `new`."""
    if not changelog.exists():
        return ""
    key = lambda v: parse_tag("v" + v.split("+")[0]) or (0, 0, 0)  # noqa: E731
    sections = re.split(r"(?m)^(?=## \[)", changelog.read_text(encoding="utf-8"))
    out = []
    for sec in sections:
        m = re.match(r"## \[(\d+\.\d+\.\d+)\]", sec)
        if m and key(old) < key(m.group(1)) <= key(new):
            out.append(sec.strip())
    return "\n\n".join(out)


def cmd_sync(args) -> int:
    target = Path(args.target).resolve()
    old = read_manifest(target)
    old_major = parse_tag("v" + old["version"].split("+")[0])
    source = open_source(args, None if args.allow_major or not old_major else old_major[0])
    new_major = parse_tag("v" + source.version.split("+")[0])
    if old_major and new_major and new_major[0] > old_major[0] and not args.allow_major:
        raise GovernanceError(f"{source.version} is a new major version (installed: {old['version']}); "
                              "review its breaking changes, then rerun with --allow-major")
    old_scaffold = scaffold_templates(target / DIR, old)
    manifest = install(source, target, old["project"], old["owner"])
    new_scaffold = scaffold_templates(target / DIR, manifest)

    report = []
    for dest, new_content in new_scaffold.items():
        path = target / dest
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == new_content:
            continue
        if current is None or current == old_scaffold.get(dest):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(new_content, encoding="utf-8")
            report.append(f"- updated `{dest}` (it matched the previous template)")
        elif old_scaffold.get(dest) != new_content:
            report.append(f"- **review** `{dest}`: the template changed, but this file has local edits; "
                          f"compare with `{DIR}/templates/project/`")
    for line in merge_gitignore(target, target / DIR):
        report.append(f"- added `{line}` to `.gitignore`")

    if old["version"] == manifest["version"] and old["files"] == manifest["files"] and not report:
        print(f"Up to date: governance {manifest['version']}")
        return 0
    notes = [f"Governance baseline {old['version']} -> {manifest['version']}.", ""]
    if report:
        notes += ["Starter files:", *report, ""]
    delta = changelog_between(target / DIR / "CHANGELOG.md", old["version"], manifest["version"])
    if delta:
        notes += ["Changes:", "", delta]
    text = "\n".join(notes).rstrip() + "\n"
    if args.notes_file:
        Path(args.notes_file).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


def verify(target: Path, upstream: bool) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors, warnings = [], []
    manifest = read_manifest(target)
    gdir = target / DIR
    present = {p.relative_to(gdir).as_posix() for p in gdir.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts} - {MANIFEST}  # bytecode caches are generated
    listed = set(manifest["files"])
    for rel in sorted(listed - present):
        errors.append(f"{DIR}/{rel} is missing")
    for rel in sorted(present - listed):
        errors.append(f"{DIR}/{rel} isn't part of the baseline; don't add files to {DIR}/")
    for rel in sorted(listed & present):
        if sha256(gdir / rel) != manifest["files"][rel]:
            errors.append(f"{DIR}/{rel} was edited; {DIR}/ is managed, use `governance.py sync`")
    version_file = gdir / "VERSION"
    if version_file.exists() and version_file.read_text(encoding="utf-8").strip() != manifest["version"].split("+")[0]:
        errors.append(f"{DIR}/VERSION doesn't match the manifest")

    if upstream:
        repo = os.environ.get("GOVERNANCE_REPO", DEFAULT_REPO)
        if "+" in manifest["version"]:
            warnings.append(f"{manifest['version']} is a development build; can't verify it against a release")
        else:
            try:
                src = Source.fetch(repo, f"v{manifest['version']}", None)
                expected = {rel: sha256(src.path / rel) for rel in managed_files(src.path)}
                if expected != manifest["files"]:
                    errors.append(f"{DIR}/ doesn't match release v{manifest['version']} of {repo}")
            except GovernanceError as exc:
                warnings.append(f"couldn't verify against {repo}: {exc}")

    checks = {
        "AGENTS.md": ".governance/AGENTS.md",
        "CLAUDE.md": "@.governance/AGENTS.md",
        ".claude/settings.json": ".governance/tools/pii_scan.py",
    }
    for rel, needle in checks.items():
        path = target / rel
        if not path.exists() or needle not in path.read_text(encoding="utf-8"):
            warnings.append(f"{rel} should reference `{needle}` (see {DIR}/templates/project/)")
    workflows = target / ".github" / "workflows"
    if not any("governance.py ci" in p.read_text(encoding="utf-8")
               for p in (workflows.glob("*.y*ml") if workflows.is_dir() else [])):
        warnings.append("no workflow runs `governance.py ci`; add .github/workflows/governance.yml")
    return errors, warnings


def cmd_check(args) -> int:
    errors, warnings = verify(Path(args.target).resolve(), upstream=not args.no_upstream)
    for w in warnings:
        print(f"WARNING: {w}")
    for e in errors:
        print(f"ERROR: {e}")
    if not errors:
        print(f"OK: {DIR}/ matches its manifest" + (f" ({len(warnings)} warning(s))" if warnings else ""))
    return 1 if errors else 0


def gitleaks_binary(workdir: Path) -> Path:
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if platform.system() != "Linux" or arch is None:
        raise GovernanceError("pinned gitleaks download supports Linux x64/arm64 only; "
                              "run gitleaks through pre-commit on this machine")
    name = f"gitleaks_{GITLEAKS_VERSION}_linux_{arch}.tar.gz"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{name}"
    archive = workdir / name
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URL
        archive.write_bytes(resp.read())
    if sha256(archive) != GITLEAKS_SHA256[arch]:
        raise GovernanceError(f"{name} checksum mismatch; refusing to run it")
    with tarfile.open(archive) as tar:
        member = tar.getmember("gitleaks")
        if not member.isfile():
            raise GovernanceError("unexpected gitleaks archive layout")
        tar.extract(member, workdir, filter="data") if hasattr(tarfile, "data_filter") else tar.extract(member, workdir)
    binary = workdir / "gitleaks"
    binary.chmod(0o755)
    return binary


def cmd_ci(args) -> int:
    tools = Path(__file__).resolve().parent
    root = Path(git("rev-parse", "--show-toplevel").strip())
    py = sys.executable
    base, head, title = (os.environ.get(k, "").strip() for k in ("BASE_SHA", "HEAD_SHA", "PR_TITLE"))
    skip = set(args.skip or [])
    results: list[tuple[str, bool]] = []

    def step(name: str, cmd: list[str]) -> None:
        if name in skip:
            print(f"::group::{name} (skipped)\n::endgroup::")
            return
        print(f"::group::{name}", flush=True)
        ok = subprocess.run(cmd, cwd=root).returncode == 0
        print("::endgroup::", flush=True)
        results.append((name, ok))

    if base and head:
        step("pii-scan (commits in this PR)", [py, str(tools / "pii_scan.py"), "--git-range", f"{base}..{head}"])
        step("commit messages (this PR)", [py, str(tools / "check_commit_msg.py"), "--git-range", f"{base}..{head}"])
    if title and "pr-title" not in skip:
        sys.dont_write_bytecode = True  # keep .governance/tools/ free of __pycache__
        sys.path.insert(0, str(tools))
        from check_commit_msg import header_problem  # noqa: E402
        problem = header_problem(title)
        print(f"PR title: {'ERROR: ' + problem if problem else 'OK'} (squash merges use it as the commit message)")
        results.append(("pr-title", problem is None))
    tracked = git("ls-files", "-z", cwd=root).split("\0")
    step("pii-scan (all tracked files)", [py, str(tools / "pii_scan.py"), *[f for f in tracked if f]])
    step("runtime versions", [py, str(tools / "check_runtimes.py"), "--online", "--root", str(root)])
    if (root / DIR / MANIFEST).exists():
        step("governance check", [py, str(tools / "governance.py"), "check", "--target", str(root)])
    if "gitleaks" not in skip:
        print("::group::gitleaks (full history)", flush=True)
        try:
            with tempfile.TemporaryDirectory() as d:
                binary = gitleaks_binary(Path(d))
                ok = subprocess.run([str(binary), "git", "--redact", "--exit-code", "1", str(root)]).returncode == 0
        except (GovernanceError, OSError) as exc:  # a scan that can't run fails closed
            print(f"ERROR: gitleaks didn't run: {exc}")
            ok = False
        print("::endgroup::", flush=True)
        results.append(("gitleaks", ok))

    print("\nGovernance checks:")
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(ok for _, ok in results) else 1


def cmd_version(args) -> int:
    print(read_manifest(Path(args.target).resolve())["version"])
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def with_source(p):
        g = p.add_mutually_exclusive_group()
        g.add_argument("--source", help="local checkout of the governance repository")
        g.add_argument("--ref", help="release tag to fetch, or 'latest' (default)")

    p = sub.add_parser("init", help="install the baseline and starter files")
    with_source(p)
    p.add_argument("--project", help="project slug (default: directory name)")
    p.add_argument("--owner", help="GitHub login for CODEOWNERS (default: from the origin remote)")
    p.add_argument("--target", default=".")
    p = sub.add_parser("sync", help="update .governance/ to another release")
    with_source(p)
    p.add_argument("--allow-major", action="store_true", help="allow moving to a new major version")
    p.add_argument("--notes-file", help="write the PR description here")
    p.add_argument("--target", default=".")
    p = sub.add_parser("check", help="verify .governance/ is unmodified")
    p.add_argument("--target", default=".")
    p.add_argument("--no-upstream", action="store_true", help="don't compare with the published release")
    p = sub.add_parser("ci", help="run every governance check")
    p.add_argument("--skip", action="append",
                   help="skip a step: gitleaks, pr-title, or a step name as printed")
    p = sub.add_parser("version", help="print the installed version")
    p.add_argument("--target", default=".")
    args = parser.parse_args(argv)

    try:
        return {"init": cmd_init, "sync": cmd_sync, "check": cmd_check, "ci": cmd_ci,
                "version": cmd_version}[args.cmd](args)
    except GovernanceError as exc:
        print(f"governance: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
