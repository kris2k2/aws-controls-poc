"""Deliver: seal a released run into a bundle a deployment pipeline can check (ADR-0008).

Deliver writes files only; it deploys nothing. It takes a Review result that
was computed for this call (the caller re-runs Review, which re-runs Select,
Generate and Verify; a `review.json` already in the run is never trusted) and
writes `delivery/` only when that result is `release`:

- `policies/<name>.json`: the released documents, byte for byte as they were
  hashed for the review;
- `detective/...`: the released Config rules, EventBridge detections and
  Sentinel policies (ADR-0009), byte for byte as the review hashed them;
- `report.html`: the visual summary of this review's run (ADR-0010);
- the evidence behind the decision: `review.json`, `verification.json`,
  `selection.json`, `findings.json`, `assessment.json` (if Assess ran),
  `capability-profile.json`, the request, and the acceptances and evidence
  files the review used;
- `manifest.json`: what the bundle is (service, tier, criticality, decision,
  the reviewed policy-set hash) and the SHA-256 of every other file.

`check_delivery` re-checks a bundle: every file listed with its hash and
nothing else, the policies hashed as the review hashed them, and a release
decision. The manifest makes a bundle tamper-evident, not authentic: anyone
who can rewrite it can rewrite the hashes too. Where the bundle is kept, and
who may write there, is what makes it trustworthy.

The bundle is written to a sibling `.partial` directory and renamed into
place, so a failed delivery leaves nothing that looks complete.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from . import __version__
from .verify import sha256 as canonical_sha256

SCHEMA = "delivery-manifest/v1"
MANIFEST = "manifest.json"
# Run files copied into the bundle when present; the first four are required.
REQUIRED = ("selection.json", "findings.json", "verification.json", "capability-profile.json", "composition.json")
OPTIONAL = ("assessment.json", "generation.json", "registry.json")
NOT_IN_BUNDLE = (
    "the Config rules, CloudTrail detections and Sentinel policies generation.json lists as pending "
    "(no structured definition yet), and permissions boundaries",
)


class DeliverError(ValueError):
    pass


def _file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deliver(review: dict, run: Path, out: Path, *, request_bytes: bytes,
            acceptances_bytes: bytes | None = None, evidence: dict[str, bytes] | None = None,
            report_bytes: bytes | None = None) -> dict:
    """Write the bundle for a released run to `out` and return its manifest."""
    if review.get("decision") != "release":
        raise DeliverError(f"the review decided {review.get('decision')!r}: only a release is delivered")
    if out.exists() and any(out.iterdir()):
        raise DeliverError(f"{out} already holds files: deliver into a new directory")

    # Read each policy once; what is hashed is what is written.
    policies: dict[str, bytes] = {}
    for path in sorted((run / "org-policies").glob("*.json")):
        policies[path.stem] = path.read_bytes()
    documents = {name: json.loads(raw) for name, raw in policies.items()}
    hashes = {name: canonical_sha256(doc) for name, doc in documents.items()}
    if hashes != review.get("policies") or canonical_sha256(documents) != review.get("policy_set_sha256"):
        raise DeliverError("the policies in the run aren't the ones the review released; review the run again")

    artifacts = {p.relative_to(run).as_posix(): p.read_bytes()
                 for p in sorted((run / "detective").rglob("*")) if p.is_file()}
    artifact_hashes = {path: _file_sha256(raw) for path, raw in artifacts.items()}
    if artifact_hashes != (review.get("artifacts") or {}):
        raise DeliverError("the detective artifacts in the run aren't the ones the review released; "
                           "review the run again")

    files: dict[str, bytes] = {f"policies/{name}.json": raw for name, raw in policies.items()}
    files.update(artifacts)
    for name in REQUIRED + OPTIONAL:
        path = run / name
        if path.is_file():
            files[name] = path.read_bytes()
        elif name in REQUIRED:
            raise DeliverError(f"{path} is missing: a delivery carries the evidence behind its release")
    if json.loads(files["verification.json"]).get("result") != "pass":
        raise DeliverError("verification.json doesn't record a pass")
    files["review.json"] = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode()
    files["request.json"] = request_bytes
    if acceptances_bytes is not None:
        files["acceptances.json"] = acceptances_bytes
    if report_bytes is not None:
        files["report.html"] = report_bytes
    for i, (name, raw) in enumerate(sorted((evidence or {}).items()), 1):
        files[f"evidence/{i:02d}-{Path(name).name}"] = raw

    manifest = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": review.get("service"),
        "maturity_tier": review.get("maturity_tier"),
        "criticality": review.get("criticality"),
        "run_mode": review.get("run_mode"),
        "reviewed_on": review.get("reviewed_on"),
        "decision": review["decision"],
        "residual_risk": review.get("residual_risk"),
        "policy_set_sha256": review["policy_set_sha256"],
        "policies": {name: {"file": f"policies/{name}.json", "sha256": hashes[name]} for name in sorted(hashes)},
        "artifacts": artifact_hashes,
        "files": {path: _file_sha256(raw) for path, raw in sorted(files.items())},
        "composition_sha256": review.get("composition_sha256"),
        "deploys": "nothing: a deployment pipeline checks this bundle (onboard check-delivery), then applies "
                   "composition.json: its attachments and detachments, in the order it lists them",
        "not_in_bundle": list(NOT_IN_BUNDLE),
    }

    partial = out.with_name(out.name + ".partial")
    if partial.exists():
        shutil.rmtree(partial)
    try:
        for path, raw in files.items():
            target = partial / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (partial / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if out.exists():
            out.rmdir()  # empty, checked above
        partial.rename(out)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    return manifest


def manifest_sha256(bundle: Path) -> str:
    return _file_sha256((bundle / MANIFEST).read_bytes())


def check_delivery(bundle: Path) -> list[str]:
    """Problems with a delivery bundle; an empty list means it is intact and released."""
    try:
        manifest = json.loads((bundle / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"cannot read {bundle / MANIFEST}: {exc}"]
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        return [f"{MANIFEST} is not a {SCHEMA} document"]
    problems = []
    if manifest.get("decision") != "release":
        problems.append(f"the manifest records {manifest.get('decision')!r}, not a release")
    listed = manifest.get("files") or {}
    present = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()} - {MANIFEST}
    for path in sorted(present - set(listed)):
        problems.append(f"{path} is in the bundle but not in the manifest")
    for path, digest in sorted(listed.items()):
        target = bundle / path
        if Path(path).is_absolute() or ".." in Path(path).parts:
            problems.append(f"{path} is not a path inside the bundle")
        elif not target.is_file():
            problems.append(f"{path} is listed but missing")
        elif _file_sha256(target.read_bytes()) != digest:
            problems.append(f"{path} doesn't match its hash: it changed after delivery")
    if problems:
        return problems
    entries = manifest.get("policies") or {}
    policy_files = {p for p in listed if p.startswith("policies/")}
    if {e.get("file") for e in entries.values()} != policy_files:
        return problems + ["the manifest's policies aren't exactly the files under policies/"]
    documents = {}
    for name, entry in sorted(entries.items()):
        document = json.loads((bundle / entry["file"]).read_bytes())
        documents[name] = document
        if canonical_sha256(document) != entry.get("sha256"):
            problems.append(f"policy {name} doesn't match the hash the review released")
    if canonical_sha256(documents) != manifest.get("policy_set_sha256"):
        problems.append("the policies don't make up the released policy set")
    review = json.loads((bundle / "review.json").read_bytes()) if "review.json" in listed else {}
    if review.get("decision") != "release" or review.get("policy_set_sha256") != manifest.get("policy_set_sha256"):
        problems.append("review.json in the bundle doesn't release this policy set")
    artifacts = manifest.get("artifacts") or {}
    if set(artifacts) != {p for p in listed if p.startswith("detective/")} \
            or any(listed[p] != digest for p, digest in artifacts.items()):
        problems.append("the manifest's artifacts aren't exactly the files under detective/")
    if (review.get("artifacts") or {}) != artifacts:
        problems.append("review.json in the bundle doesn't release these detective artifacts")
    return problems
