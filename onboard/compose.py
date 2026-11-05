"""Compose: place a run's policies in the organization, check its budgets, and diff it (ADR-0011).

Compose reads what Generate wrote and the organization as the request
describes it (`org_state`), and writes `composition.json`. It deploys nothing
and calls nothing: it is a pure function of the request and the generated
files, so Review reproduces it.

`org_state` (all synthetic in the tests):

    {"organization_id": "o-...",
     "ous": [{"path": "Workloads"}, {"path": "Workloads/Analytics"}],   # parents before children
     "accounts": [{"id": "111122223333", "ou": "Sandbox/Preview"}],
     "policies": [{"name": "FullAWSAccess", "type": "scp", "targets": ["Root", ...],
                   "sha256": "..." | "document": {...}}],
     "vpc_endpoints": {"athena": ["vpce-..."]}}

A target is `Root`, an OU path or a 12-digit account ID.

Placement:

- The organization's guardrails (`*-org-guardrails`) go on the root: they hold
  for every account.
- The service's targets are its preview accounts at Private Preview, and the
  OUs in `target_scope` after that.
- Allow-list organizations (no `FullAWSAccess` on the root): an SCP allows an
  action only if every level from the root to the account allows it, the
  account included, so the service's allow-list goes on every node from the
  root down to each target and on every OU and account under it; the service
  is reachable only there. An account added under a target later needs the
  allow-list too, which the next run's diff shows. Its guardrails go on the targets,
  which covers everywhere it is reachable.
- Deny-list organizations (`FullAWSAccess` on the root): the service is
  reachable everywhere, so its guardrails go on the root and its allow-list
  isn't attached.
- Endpoint policies go on every VPC endpoint in `org_state`.

Budgets: for every node a policy is attached to, the attachments already there
(other services' included, and RCPFullAWSAccess, which is on every node) plus
this run's, minus the ones it replaces, must fit the per-target quota (10 SCPs,
5 RCPs); every policy must fit its size limit (10,240 characters for an SCP,
5,120 for an RCP), counted without whitespace, so deploy them minified. Anything over
is `over-budget`: a person merges or moves policies; Compose never drops a
guardrail to fit.

The diff lists attachments in the order to apply them, after creating and
updating policies and before deleting any: guardrails attached, then allows
attached, then allows detached, then guardrails detached. The service is
never allowed anywhere without its guardrails in between.

The diff covers the policies this run manages (the organization's guardrails
and `<type>-<service>-*`): create, update, unchanged or delete, and every
attachment to add or remove. Policies it doesn't manage are only counted.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import __version__
from .generate import policy_size
from .model import Tier
from .request import OnboardingRequest

SCHEMA = "composition/v1"
ROOT = "Root"
# AWS Organizations quotas, checked 2026-11-05 (ADR-0011): policies attached directly to a
# root, OU or account (inherited ones don't count), size in characters, OU nesting.
MAX_ATTACHED = {"scp": 10, "rcp": 5}
MAX_SIZE = {"scp": 10240, "rcp": 5120}
MAX_OU_DEPTH = 5
FULL_ACCESS = {"scp": "FullAWSAccess", "rcp": "RCPFullAWSAccess"}
# AWS attaches RCPFullAWSAccess to every root, OU and account; it can't be detached and
# counts toward the RCP quota, whether or not org_state lists it.
ORG_TYPES = ("scp", "rcp")
_ACCOUNT = re.compile(r"^\d{12}$")
_OU_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*(/[A-Za-z0-9][A-Za-z0-9 ._-]*)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ComposeError(ValueError):
    pass


def _sha256(document) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Organization:
    """The OU tree, accounts and attached policies from `org_state`, validated."""

    def __init__(self, org_state: dict):
        problems = []
        self.ous: set[str] = set()
        for i, ou in enumerate(org_state.get("ous") or []):
            path = ou.get("path") if isinstance(ou, dict) else None
            if not isinstance(path, str) or not _OU_PATH.match(path) or path == ROOT:
                problems.append(f"org_state.ous[{i}].path must be an OU path like Workloads/Analytics")
                continue
            parent = path.rpartition("/")[0]
            if parent and parent not in self.ous:
                problems.append(f"org_state.ous[{i}]: {path}'s parent {parent} must be listed before it")
            if path.count("/") + 1 > MAX_OU_DEPTH:
                problems.append(f"org_state.ous[{i}]: {path} is nested deeper than {MAX_OU_DEPTH} levels")
            self.ous.add(path)
        self.accounts: dict[str, str] = {}
        for i, account in enumerate(org_state.get("accounts") or []):
            aid, ou = (account.get("id"), account.get("ou", ROOT)) if isinstance(account, dict) else (None, None)
            if not isinstance(aid, str) or not _ACCOUNT.match(aid):
                problems.append(f"org_state.accounts[{i}].id must be a 12-digit account ID")
            elif ou != ROOT and ou not in self.ous:
                problems.append(f"org_state.accounts[{i}]: OU {ou!r} isn't in org_state.ous")
            else:
                self.accounts[aid] = ou
        self.policies: dict[str, dict] = {}
        for i, policy in enumerate(org_state.get("policies") or []):
            where = f"org_state.policies[{i}]"
            if not isinstance(policy, dict) or not isinstance(policy.get("name"), str) or not policy["name"]:
                problems.append(f"{where}.name is required")
                continue
            if policy.get("type") not in ORG_TYPES:
                problems.append(f"{where}.type must be scp or rcp")
                continue
            targets = policy.get("targets")
            if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
                problems.append(f"{where}.targets must be a list of Root, OU paths or account IDs")
                continue
            for t in targets:
                if not self.known(t):
                    problems.append(f"{where}: target {t!r} isn't the root, a listed OU or a listed account")
            digest = policy.get("sha256")
            if "document" in policy:
                digest = _sha256(policy["document"])
            elif not (isinstance(digest, str) and _SHA256.match(digest)) and policy["name"] not in FULL_ACCESS.values():
                problems.append(f"{where} needs its document or sha256, so a change shows in the diff")
            if policy["name"] in self.policies:
                problems.append(f"{where}: {policy['name']} is listed twice")
            self.policies[policy["name"]] = {"type": policy["type"], "targets": list(targets), "sha256": digest}
        if problems:
            raise ComposeError("org_state doesn't describe the organization:\n  - " + "\n  - ".join(problems))

    def known(self, target: str) -> bool:
        return target == ROOT or target in self.ous or target in self.accounts

    def path_to(self, target: str) -> list[str]:
        """Root, then each OU down to the target (inclusive)."""
        ou = self.accounts.get(target, target)
        nodes = [ROOT]
        if ou != ROOT:
            parts = ou.split("/")
            nodes += ["/".join(parts[:i + 1]) for i in range(len(parts))]
        if target in self.accounts:
            nodes.append(target)
        return nodes

    def below(self, target: str) -> list[str]:
        """Every OU and account under an OU target (or the whole organization under the root), parents first."""
        if target in self.accounts:
            return []
        inside = (lambda path: True) if target == ROOT else (lambda path: path.startswith(target + "/"))
        ous = sorted((o for o in self.ous if inside(o)), key=lambda o: (o.count("/"), o))
        accounts = sorted(a for a, ou in self.accounts.items() if ou == target or (ou != ROOT and inside(ou))
                          or (target == ROOT and ou == ROOT))
        return ous + accounts

    def attached(self, target: str, ptype: str) -> list[str]:
        return sorted(n for n, p in self.policies.items() if p["type"] == ptype and target in p["targets"])


def _kind(name: str) -> str:
    return name.split("-", 1)[0]


def manages(name: str, service: str) -> bool:
    return name in {f"{t}-org-guardrails" for t in ORG_TYPES} or any(
        name.startswith(f"{t}-{service}-") for t in ORG_TYPES)


def service_targets(request: OnboardingRequest, org: Organization) -> list[str]:
    if request.maturity_tier is Tier.PRIVATE_PREVIEW:
        targets = list(request.preview_accounts)
        missing = [a for a in targets if a not in org.accounts]
        if missing:
            raise ComposeError(f"preview accounts {', '.join(missing)} aren't in org_state.accounts, so Compose "
                               "can't tell which OUs their allow-list must pass through")
    else:
        targets = list(request.target_scope)
        missing = [t for t in targets if not org.known(t)]
        if missing:
            raise ComposeError(f"target_scope {', '.join(missing)} isn't the root, a listed OU or a listed account")
    return sorted(dict.fromkeys(targets))


def compose(request: OnboardingRequest, generation: dict, policies: dict[str, dict]) -> dict:
    """Return composition/v1 for the generated policies (see the module docstring)."""
    org = Organization(request.org_state)
    service = generation["service"]
    targets = service_targets(request, org)
    deny_list = FULL_ACCESS["scp"] in org.attached(ROOT, "scp")
    strategy = "deny-list" if deny_list else "allow-list"

    placements: dict[str, dict] = {}
    for name in sorted(policies):
        kind = _kind(name)
        if kind == "vpce":
            continue
        if name.endswith("-org-guardrails"):
            where, why = [ROOT], "the organization's guardrails hold for every account"
        elif name == f"scp-{service}-allow":
            if deny_list:
                placements[name] = {"type": kind, "targets": [], "why": "FullAWSAccess on the root already allows "
                                    "the service everywhere, so the allow-list isn't attached"}
                continue
            # Root first, then down to each target and everything under it: an account needs the
            # allow on itself too, not only on its OU.
            where = list(dict.fromkeys(n for t in targets for n in org.path_to(t) + org.below(t)))
            why = ("an SCP allow must be present at every level from the root to the account, the account "
                   "included, so it goes on each target and every OU and account under it")
        elif deny_list:
            where, why = [ROOT], "FullAWSAccess makes the service reachable everywhere, so its denies go on the root"
        else:
            where, why = list(targets), "the service is reachable only where its allow-list reaches"
        placements[name] = {"type": kind, "targets": where, "why": why}

    endpoints = {name: list(generation.get("vpc_endpoints", [])) for name in sorted(policies) if _kind(name) == "vpce"}

    # Budgets: every node this run attaches to, with what is already there.
    budgets, problems = [], []
    for name, doc in sorted(policies.items()):
        if _kind(name) in ORG_TYPES and policy_size(doc) > MAX_SIZE[_kind(name)]:
            problems.append(f"{name} is {policy_size(doc)} characters, over the {MAX_SIZE[_kind(name)]} limit")
    nodes = sorted({(t, p["type"]) for p in placements.values() for t in p["targets"]},
                   key=lambda tp: (tp[0] != ROOT, tp[0], tp[1]))
    for target, ptype in nodes:
        mine = {n for n, p in placements.items() if p["type"] == ptype and target in p["targets"]}
        existing = set(org.attached(target, ptype))
        # Attachments of policies this run manages are replaced by this run's placement.
        kept = {n for n in existing if not manages(n, service)}
        if ptype == "rcp":
            kept.add(FULL_ACCESS["rcp"])
        after = sorted(kept | mine)
        over = len(after) > MAX_ATTACHED[ptype]
        budgets.append({"target": target, "type": ptype, "attached": len(after), "limit": MAX_ATTACHED[ptype],
                        "policies": after, "over": over})
        if over:
            problems.append(f"{target} would have {len(after)} {ptype.upper()}s attached, over the quota of "
                            f"{MAX_ATTACHED[ptype]}: {', '.join(after)}")

    # Diff against the organization, for the policies this run manages.
    diff_policies, diff_attachments = [], []
    managed = sorted({n for n in org.policies if manages(n, service)} | set(placements))
    for name in managed:
        before = org.policies.get(name)
        doc = policies.get(name)
        new_sha = _sha256(doc) if doc is not None else None
        if before is None:
            change = "create"
        elif doc is None:
            change = "delete"
        else:
            change = "unchanged" if before["sha256"] == new_sha else "update"
        diff_policies.append({"name": name, "change": change, **({"sha256": new_sha} if new_sha else {})})
        old_targets = set(before["targets"]) if before else set()
        new_targets = set(placements.get(name, {}).get("targets", []))
        for t in sorted(new_targets - old_targets):
            diff_attachments.append({"policy": name, "target": t, "change": "attach"})
        for t in sorted(old_targets - new_targets):
            diff_attachments.append({"policy": name, "target": t, "change": "detach"})
    # Apply order: denies go on before allows, and allows come off before denies, so there is never a
    # moment where the service is allowed somewhere without its guardrails.
    def phase(a: dict) -> int:
        allow = a["policy"].endswith("-allow")
        return {("attach", False): 0, ("attach", True): 1, ("detach", True): 2, ("detach", False): 3}[(a["change"], allow)]
    diff_attachments.sort(key=lambda a: (phase(a), a["policy"], a["target"]))
    for i, a in enumerate(diff_attachments, 1):
        a["step"] = i
    # Detaching the service's allow-list takes the service away from those nodes (allow-list organizations).
    removed = sorted(a["target"] for a in diff_attachments
                     if a["policy"] == f"scp-{service}-allow" and a["change"] == "detach")

    # Where the detective artifacts go: shared ones everywhere, the service's at its targets.
    artifacts = {}
    shared = {cid for cid, s in generation.get("controls", {}).items() if cid.startswith("ORG-")}
    for path in sorted(generation.get("detective_artifacts", {})):
        name = path.rsplit("/", 1)[-1]
        cid = name.split(".")[0].upper()
        scope = [ROOT] if cid in shared else (list(targets) if not deny_list else [ROOT])
        if path.startswith("detective/eventbridge/"):
            artifacts[path] = {"scope": scope, "regions": "every enabled Region",
                               "why": "denied and out-of-Region calls are logged where they happen"}
        elif path.startswith("detective/config-rules/"):
            artifacts[path] = {"scope": scope, "regions": list(request.allowed_regions),
                               "why": "resources exist only in the allowed Regions (ORG-C-01)"}
        else:
            artifacts[path] = {"scope": "the organization's Terraform policy sets", "regions": None,
                               "why": "Sentinel runs in Terraform, outside AWS Organizations"}

    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "maturity_tier": request.maturity_tier.value,
        "strategy": strategy,
        "targets": [{"target": t, "kind": "account" if t in org.accounts else "root" if t == ROOT else "ou"}
                    for t in targets],
        "placements": placements,
        "endpoints": endpoints,
        "budgets": budgets,
        "diff": {"policies": diff_policies, "attachments": diff_attachments},
        "removes_service_from": removed,
        "artifacts": artifacts,
        "result": "over-budget" if problems else "fits",
        "problems": problems,
    }
