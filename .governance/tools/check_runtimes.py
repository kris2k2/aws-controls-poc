#!/usr/bin/env python3
"""Keep CI on current, supported runtimes, not versions remembered from training data.

Versions are never hardcoded here. Online checks read live data:
  - endoflife.date: Node.js and Python release support phases
  - actions/runner-images README: GitHub-hosted runner labels and their status
  - each action's tags and action.yml: latest release and the runtime it runs on

Offline checks (always run):
  - every `uses:` action is pinned to a full commit SHA with a `# vX.Y.Z` comment
  - every job sets `timeout-minutes`

Online checks (--online):
  - runs-on labels: deprecated or unlisted -> error; preview/beta -> warning
  - Node.js / Python in setup-* inputs and .nvmrc / .node-version / .python-version:
    end of life -> error; security-only/maintenance, or non-LTS Node -> warning
  - actions: running on an end-of-life Node runtime -> error; behind the latest major -> warning

Usage:
  check_runtimes.py [--online] [--strict] [--root DIR]
  check_runtimes.py --report            what is current right now (run before writing CI)
  check_runtimes.py --pin OWNER/REPO    latest release of an action, pinned by SHA

Exit codes: 0 clean (warnings allowed unless --strict), 1 errors.
See standards/sdlc/runtime-versions.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

POLICY_DOC = "standards/sdlc/runtime-versions.md"
EOL_API = "https://endoflife.date/api/v1/products/{product}/"
RUNNER_README = "https://raw.githubusercontent.com/actions/runner-images/main/README.md"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
VERSION_FILES = {".nvmrc": "nodejs", ".node-version": "nodejs", ".python-version": "python"}
SETUP_INPUTS = {"node-version": "nodejs", "python-version": "python"}
DYNAMIC_SPECS = re.compile(r"^(lts/.*|latest|current|node|stable|\*|3\.x|\d+\.x\.x)$", re.I)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)['\"]?\s*(?:#\s*(\S+))?")
SEMVER_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


@dataclass
class Issue:
    level: str  # "error" | "warning"
    where: str
    message: str
    line: Optional[int] = None

    def render(self) -> str:
        loc = f"{self.where}:{self.line}" if self.line else self.where
        return f"{loc}: {self.level.upper()}: {self.message}"

    def annotation(self) -> str:
        loc = f"file={self.where}" + (f",line={self.line}" if self.line else "")
        return f"::{self.level} {loc}::{self.message}"


# --- live data ----------------------------------------------------------------

class Live:
    """Fetches live data. Tests substitute a subclass with canned answers."""

    def _get(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "governance-check-runtimes"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https hosts
            return resp.read().decode("utf-8")

    def releases(self, product: str) -> list[dict]:
        return json.loads(self._get(EOL_API.format(product=product)))["result"]["releases"]

    def runner_labels(self) -> dict[str, str]:
        """Map each runner label to "ga", "preview" or "deprecated"."""
        labels, in_table = {}, False
        for line in self._get(RUNNER_README).splitlines():
            if line.startswith("| Image"):
                in_table = True
                continue
            if in_table and not line.startswith("|"):
                break
            cells = [c.strip() for c in line.strip("|").split("|")]
            if not in_table or len(cells) < 3 or set(cells[0]) <= {"-", " "}:
                continue
            image = cells[0].lower()
            status = "deprecated" if "deprecated" in image else "preview" if ("preview" in image or "beta" in image) else "ga"
            for label in re.findall(r"`([^`]+)`", cells[2]):
                labels[label] = status
        return labels

    def action_runtime(self, repo: str, path: str, ref: str) -> Optional[str]:
        for name in ("action.yml", "action.yaml"):
            try:
                meta = yaml.safe_load(self._get(RAW.format(repo=repo, ref=ref, path=f"{path}{name}")))
            except Exception:  # noqa: BLE001 - try the other file name
                continue
            return str((meta or {}).get("runs", {}).get("using", "")) or None
        return None

    def tags(self, repo: str) -> dict[str, str]:
        """Release tags -> commit SHA (peeled for annotated tags)."""
        out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}"],
                             check=True, capture_output=True, text=True, timeout=60).stdout
        tags: dict[str, str] = {}
        for line in out.splitlines():
            sha, ref = line.split("\t")
            name = ref.removeprefix("refs/tags/")
            if name.endswith("^{}"):
                tags[name[:-3]] = sha  # peeled commit wins over the tag object
            else:
                tags.setdefault(name, sha)
        return tags


def latest_release(tags: dict[str, str]) -> Optional[tuple[str, str]]:
    versions = [(tuple(map(int, m.groups())), name) for name in tags if (m := SEMVER_TAG.match(name))]
    if not versions:
        return None
    _, name = max(versions)
    return name, tags[name]


# --- version policy -------------------------------------------------------------

def cycle_of(product: str, spec: str) -> Optional[str]:
    spec = spec.strip().lstrip("v")
    if product == "nodejs":
        m = re.search(r"(\d+)", spec)
        return m.group(1) if m else None
    m = re.search(r"(\d+)\.(\d+)", spec)
    return f"{m.group(1)}.{m.group(2)}" if m else None


def recommended(product: str, releases: list[dict]) -> str:
    active = [r for r in releases if not r.get("isEol") and not r.get("isEoas")]
    if product == "nodejs":
        lts = [r for r in active if r.get("isLts")] or [r for r in releases if r.get("isLts") and not r.get("isEol")]
        return f"Node.js {lts[0]['name']} (LTS)" if lts else "a current Node.js LTS"
    names = [r["name"] for r in active[:2]]
    return "Python " + " or ".join(names) if names else "a supported Python"


def assess(product: str, spec: str, releases: list[dict]) -> Optional[tuple[str, str]]:
    """Return (level, message) for a version spec, or None if it's current."""
    if DYNAMIC_SPECS.match(spec.strip()):
        return None
    cycle = cycle_of(product, spec)
    label = "Node.js" if product == "nodejs" else "Python"
    if cycle is None:
        return ("warning", f"can't read a {label} version from '{spec}'")
    release = next((r for r in releases if r["name"] == cycle), None)
    rec = recommended(product, releases)
    if release is None:
        newest = releases[0]["name"] if releases else "?"
        key = (lambda v: tuple(map(int, v.split("."))))
        if releases and key(cycle) > key(newest):
            return ("error", f"{label} {cycle} isn't released yet; use {rec}")
        return ("warning", f"{label} {cycle} isn't listed on endoflife.date; use {rec}")
    if release.get("isEol"):
        return ("error", f"{label} {cycle} reached end of life on {release.get('eolFrom')}; use {rec}")
    if product == "nodejs" and not release.get("isLts"):
        when = f" (LTS from {release['ltsFrom']})" if release.get("ltsFrom") else ""
        return ("warning", f"Node.js {cycle} is not an LTS release yet{when}; use {rec}")
    if release.get("isEoas"):
        return ("warning", f"{label} {cycle} gets security fixes only since {release.get('eoasFrom')}; "
                           f"move to {rec}")
    return None


# --- repository scanning ----------------------------------------------------------

def workflow_files(root: Path) -> list[Path]:
    wf = root / ".github" / "workflows"
    return sorted([*wf.glob("*.yml"), *wf.glob("*.yaml")]) if wf.is_dir() else []


def version_files(root: Path) -> list[Path]:
    found = []
    for name in VERSION_FILES:
        found += [p for p in root.rglob(name) if "node_modules" not in p.parts and ".git" not in p.parts]
    return sorted(found)


def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def scan_uses(root: Path, path: Path) -> list[tuple[int, str, Optional[str]]]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = USES_RE.match(line)
        if m:
            out.append((n, m.group(1), m.group(2)))
    return out


def offline_checks(root: Path) -> list[Issue]:
    issues = []
    for wf in workflow_files(root):
        where = rel(root, wf)
        for n, uses, comment in scan_uses(root, wf):
            if uses.startswith(("./", "docker://")):
                continue
            ref = uses.rpartition("@")[2]
            if not SHA_RE.match(ref):
                issues.append(Issue("error", where, f"pin {uses} to a full commit SHA with a version comment "
                                                    f"(run: check_runtimes.py --pin {uses.split('@')[0]})", n))
            elif not (comment and re.match(r"^v?\d+(\.\d+)*$", comment)):
                issues.append(Issue("error", where, f"add a '# vX.Y.Z' comment to {uses}", n))
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for name, job in (doc.get("jobs") or {}).items():
            if isinstance(job, dict) and "uses" not in job and "timeout-minutes" not in job:
                issues.append(Issue("error", where, f"job '{name}' has no timeout-minutes (the default is 360)"))
    return issues


def _matrix_values(job: dict, expr: str) -> list[str]:
    m = re.fullmatch(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}", expr.strip())
    if not m:
        return []
    values = ((job.get("strategy") or {}).get("matrix") or {}).get(m.group(1))
    return [str(v) for v in values] if isinstance(values, list) else []


def runtime_specs(root: Path) -> list[tuple[str, str, str]]:
    """(where, product, spec) for every Node.js/Python version the repo selects."""
    specs = []
    for wf in workflow_files(root):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for job in (doc.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                for key, product in SETUP_INPUTS.items():
                    value = ((step or {}).get("with") or {}).get(key)
                    if value is None:
                        continue
                    for spec in (_matrix_values(job, str(value)) if "${{" in str(value) else
                                 str(value).split()):
                        specs.append((rel(root, wf), product, spec))
    for vf in version_files(root):
        spec = vf.read_text(encoding="utf-8").strip().splitlines()
        if spec:
            specs.append((rel(root, vf), VERSION_FILES[vf.name], spec[0]))
    return specs


def runs_on_labels(root: Path) -> list[tuple[str, str]]:
    out = []
    for wf in workflow_files(root):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for job in (doc.get("jobs") or {}).values():
            runs_on = (job or {}).get("runs-on") if isinstance(job, dict) else None
            labels = runs_on.get("labels", []) if isinstance(runs_on, dict) else runs_on
            labels = [labels] if isinstance(labels, str) else (labels or [])
            if "self-hosted" in labels:
                continue
            out += [(rel(root, wf), str(lb)) for lb in labels if "${{" not in str(lb)]
    return out


def online_checks(root: Path, live: Live) -> list[Issue]:
    issues: list[Issue] = []
    data: dict[str, list[dict]] = {}
    for product in ("nodejs", "python"):
        try:
            data[product] = live.releases(product)
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            issues.append(Issue("warning", "endoflife.date", f"couldn't fetch {product} releases: {exc}"))

    for where, product, spec in runtime_specs(root):
        if product in data and (verdict := assess(product, spec, data[product])):
            issues.append(Issue(verdict[0], where, verdict[1]))

    try:
        labels = live.runner_labels()
    except Exception as exc:  # noqa: BLE001
        labels = None
        issues.append(Issue("warning", "runner-images", f"couldn't fetch runner labels: {exc}"))
    if labels:
        for where, label in sorted(set(runs_on_labels(root))):
            status = labels.get(label)
            if status == "deprecated":
                issues.append(Issue("error", where, f"runner '{label}' is deprecated by GitHub; move to a current label"))
            elif status == "preview":
                issues.append(Issue("warning", where, f"runner '{label}' is in preview/beta"))
            elif status is None:
                issues.append(Issue("warning", where, f"runner '{label}' isn't a GitHub-hosted image label "
                                                      "(larger or self-hosted runners aren't checked)"))

    seen: dict[str, Optional[str]] = {}
    tag_cache: dict[str, Optional[tuple[str, str]]] = {}
    for wf in workflow_files(root):
        where = rel(root, wf)
        for n, uses, comment in scan_uses(root, wf):
            if uses.startswith(("./", "docker://")) or "@" not in uses:
                continue
            target, _, ref = uses.rpartition("@")
            parts = target.split("/")
            repo, sub = "/".join(parts[:2]), "/".join(parts[2:])
            if "/.github/workflows/" not in f"/{sub}" and uses not in seen:
                try:
                    seen[uses] = live.action_runtime(repo, f"{sub}/" if sub else "", ref)
                except Exception as exc:  # noqa: BLE001
                    seen[uses] = None
                    issues.append(Issue("warning", where, f"couldn't read {uses} metadata: {exc}", n))
            using = seen.get(uses)
            if using and (m := re.fullmatch(r"node(\d+)", using)) and "nodejs" in data:
                node = next((r for r in data["nodejs"] if r["name"] == m.group(1)), None)
                if node is None or node.get("isEol"):
                    issues.append(Issue("error", where, f"{target} runs on {using}, which has reached end of "
                                                        "life; GitHub runners no longer support it", n))
            if repo not in tag_cache:
                try:
                    tag_cache[repo] = latest_release(live.tags(repo))
                except Exception as exc:  # noqa: BLE001
                    tag_cache[repo] = None
                    issues.append(Issue("warning", where, f"couldn't list tags for {repo}: {exc}", n))
            latest = tag_cache[repo]
            current = comment or ref
            cm, lm = re.match(r"v?(\d+)", current or ""), latest and SEMVER_TAG.match(latest[0])
            if cm and lm and int(cm.group(1)) < int(lm.group(1)):
                issues.append(Issue("warning", where, f"{target} {current} is behind the latest major "
                                                      f"{latest[0]}: {target}@{latest[1]}  # {latest[0]}", n))
    return issues


# --- modes -------------------------------------------------------------------------

def report(live: Live) -> None:
    for product, label in (("nodejs", "Node.js"), ("python", "Python")):
        rels = live.releases(product)
        print(f"{label}: recommended {recommended(product, rels)}")
        for r in rels:
            if r.get("isEol"):
                continue
            phase = "security fixes only" if r.get("isEoas") else "active support"
            lts = " LTS" if r.get("isLts") else (f" (LTS from {r['ltsFrom']})" if r.get("ltsFrom") else "")
            print(f"  {r['name']}{lts}: {phase}; latest {(r.get('latest') or {}).get('name')}; "
                  f"end of life {r.get('eolFrom')}")
    labels = live.runner_labels()
    for status in ("ga", "preview", "deprecated"):
        names = sorted(k for k, v in labels.items() if v == status)
        print(f"Runner labels ({status}): {', '.join(names)}")


def pin(live: Live, repo: str) -> int:
    latest = latest_release(live.tags(repo))
    if not latest:
        print(f"{repo}: no release tags found", file=sys.stderr)
        return 1
    tag, sha = latest
    owner_repo = "/".join(repo.split("/")[:2])
    using = live.action_runtime(owner_repo, "/".join(repo.split("/")[2:]) + "/" if repo.count("/") > 1 else "", sha)
    print(f"uses: {repo}@{sha}  # {tag}" + (f"   (runs on {using})" if using else ""))
    return 0


def main(argv: Optional[list[str]] = None, live: Optional[Live] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=".", help="repository root to check")
    parser.add_argument("--online", action="store_true", help="also check against live support data")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--report", action="store_true", help="print current supported versions and runners")
    parser.add_argument("--pin", metavar="OWNER/REPO", help="print the latest release pinned by SHA")
    args = parser.parse_args(argv)
    live = live or Live()

    if args.report:
        report(live)
        return 0
    if args.pin:
        return pin(live, args.pin)

    root = Path(args.root).resolve()
    issues = offline_checks(root) + (online_checks(root, live) if args.online else [])
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for issue in issues:
        print(issue.annotation() if in_actions else issue.render())
    errors = [i for i in issues if i.level == "error" or args.strict]
    if issues:
        print(f"\n{len(errors)} error(s), {len(issues) - len(errors)} warning(s). See {POLICY_DOC}.",
              file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
