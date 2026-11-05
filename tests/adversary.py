"""The attacker model and the bounded checks behind the adversarial guardrail tests.

The journey tests show each guardrail works for the requests its author thought
of. This module checks it against the requests an attacker can make instead:

- A security property (`Property`) states, independently of the generated JSON,
  which requests a control must deny. The properties live in
  `tests/athena_security_spec.py`, the file the security team reviews.
- The attacker model (`Space`) lists what a request can vary: the action, the
  resource, the principal (role name, path and account, inside or outside the
  organization, a standalone account in no organization, anonymous, or an AWS
  service), the region, the VPC endpoint (the organization's own, one the
  attacker created, or none), whether an AWS service makes the call, the
  organization and account owning the resource, and request tags. Each dimension takes every value the
  request names, plus values it names nowhere.
- `counterexamples` checks one generated statement against its property over
  every combination of the dimensions either of them reads. A statement can
  only read the action, the resource and the condition keys it names (that is
  how the evaluator works), and a property can only read the dimensions it
  declares (`View` enforces it). Actions and resources are grouped into
  classes that every pattern on both sides treats alike, and one member of
  each class is checked. So the check is exhaustive over the model, not a
  sample: a statement passes only if it denies exactly what its property
  denies, no more (collateral damage) and no less (a bypass).
- Whole-policy decisions are deny-overrides over statements plus the
  allow-lists (the SCP allow-list and the endpoint policy's base allow), so
  per-statement equivalence plus allow-list equivalence gives equivalence of
  the whole decision, under the same scoping: SCPs bind organization
  principals, RCPs organization resources, endpoint policies every request
  through the organization's endpoints.
- `mutants` breaks a statement the ways a generator bug would; the tests
  require every mutant to produce a counterexample, which shows the check
  has teeth.

Everything here is relative to the local evaluator's reading of IAM. Until
that evaluator is calibrated against AWS (the policy simulator and live calls
in a sandbox account), a pass means "holds in our model of AWS".
"""

from __future__ import annotations

import copy
import fnmatch
import functools
import itertools
import re
from dataclasses import dataclass, field
from typing import Callable

from onboard.evaluator import Decision, Request, evaluate, statement_applies

# Values the request names nowhere. Synthetic, from the AWS documentation ranges.
ORG_ACCOUNT_ON_NO_LIST = "777788889999"   # in the organization, on no list in the request
EXTERNAL_ACCOUNT = "999988887777"         # outside the organization
STANDALONE_ACCOUNT = "210987654321"       # outside any organization: no aws:PrincipalOrgID or aws:ResourceOrgID
OTHER_ORG = "o-otherorgid"
ATTACKER_VPCE = "vpce-0attacker000000000"
REGIONS_NAMED_NOWHERE = ("us-east-1", "us-west-2")
TAG_VALUE = "cc-0001"

# Actions outside the service contract that the attacker model always tries:
# dependencies, the services the existing allow-list opens, global services
# and one service nothing allows.
EXTRA_ACTIONS = (
    "s3:GetObject", "s3:PutObject", "s3:ListAllMyBuckets", "kms:Decrypt", "kms:ScheduleKeyDeletion",
    "glue:GetTable", "glue:CreateConnection", "iam:ListRoles", "iam:CreateUser", "sts:AssumeRole",
    "sts:GetCallerIdentity", "organizations:DescribeOrganization", "organizations:LeaveOrganization",
    "cloudtrail:LookupEvents", "config:DescribeConfigurationRecorders", "route53:ListHostedZones",
    "cloudfront:ListDistributions", "support:DescribeCases", "ec2:RunInstances",
)

CONSTRAINS_PRINCIPALS = "organization principals"  # enforceable with an SCP
CONSTRAINS_RESOURCES = "organization resources"    # enforceable with an RCP
CONSTRAINS_ENDPOINTS = "requests through organization endpoints"  # enforceable with an endpoint policy
POLICY_TYPE = {CONSTRAINS_PRINCIPALS: "scp", CONSTRAINS_RESOURCES: "rcp", CONSTRAINS_ENDPOINTS: "vpce"}

# Which dimension sets each request-context key (lower case). A statement that
# reads a key missing here fails the check: extend the model first.
KEY_DIMENSION = {
    "aws:principalarn": "principal",
    "aws:principalaccount": "principal",
    "aws:principalorgid": "principal",
    "aws:principalisawsservice": "principal",
    "aws:requestedregion": "region",
    "aws:sourcevpce": "vpce",
    "aws:viaawsservice": "via",
    "aws:resourceorgid": "resource_org",
    "aws:resourceaccount": "resource_account",
    "aws:requesttag/cost-center": "tag",
}
DIMENSIONS = ("principal", "region", "vpce", "via", "resource_org", "resource_account", "tag")


@functools.lru_cache(maxsize=4096)
def _compiled(pattern: str, ignore_case: bool) -> re.Pattern:
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE if ignore_case else 0)


def matches(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """Glob match (* and ?), implemented apart from the evaluator's on purpose."""
    return _compiled(pattern, ignore_case).match(value) is not None


def _list(value) -> list:
    return value if isinstance(value, list) else [value]


@dataclass(frozen=True)
class Principal:
    label: str
    arn: str | None
    account: str | None
    org_id: str | None
    service: bool = False

    @property
    def in_org(self) -> bool:
        return not self.service and self.org_id is not None and self.org_id != OTHER_ORG


def role(account: str, name: str, org_id: str | None) -> Principal:
    where = "org" if org_id and org_id != OTHER_ORG else "external"
    return Principal(f"{name}@{account} ({where})", f"arn:aws:iam::{account}:role/{name}", account, org_id)


AWS_SERVICE = Principal("AWS service principal", None, None, None, service=True)
ANONYMOUS = Principal("anonymous (unsigned request)", None, None, None)


def sample(pattern: str) -> list[str]:
    """Concrete values a wildcard pattern matches: plainly, and through a role path."""
    if "*" not in pattern:
        return [pattern]
    return [pattern.replace("*", "x"), pattern.replace("*", "/x", 1).replace("*", "x")]


@dataclass(frozen=True)
class Facts:
    """What the request says, read straight from it rather than from the generator."""

    service: str
    org_id: str
    allowed_regions: tuple[str, ...]
    preview_accounts: tuple[str, ...]
    vpce_ids: tuple[str, ...]
    endpoints: tuple[str, ...]          # every VPC endpoint the organization runs, any service
    trusted_resource_accounts: tuple[str, ...]
    break_glass: tuple[str, ...]
    exception_principals: tuple[str, ...]
    allow_prefixes: tuple[str, ...]

    @property
    def protected_roles(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.break_glass) | set(self.exception_principals)))

    @classmethod
    def of(cls, request, findings: dict) -> "Facts":
        org = request.org_state
        service = findings["service"]
        return cls(
            service=service,
            org_id=org.get("organization_id", ""),
            allowed_regions=tuple(request.allowed_regions),
            preview_accounts=tuple(request.preview_accounts),
            vpce_ids=tuple((org.get("vpc_endpoints") or {}).get(service, [])),
            endpoints=tuple(sorted({e for ids in (org.get("vpc_endpoints") or {}).values() for e in ids})),
            trusted_resource_accounts=tuple(request.trusted_resource_accounts),
            break_glass=tuple(request.break_glass_principals),
            exception_principals=tuple(e.principal for e in request.exceptions),
            allow_prefixes=tuple([service] + sorted({d["prefix"] for d in findings.get("dependencies", [])})),
        )


def _account(arn: str) -> str:
    return arn.split(":")[4]


def _role_name(arn: str) -> str:
    return arn.split(":", 5)[5].removeprefix("role/")


class Space:
    """The attacker model for one request: the values each dimension takes."""

    def __init__(self, facts: Facts, contract_actions: list[str], extra_actions=(), extra_principals=()):
        self.facts = facts
        org = facts.org_id
        named = [_role_name(p) for p in facts.protected_roles]
        names = sorted({"analyst"} | {n for p in named for n in sample(p)} | {"BreakGlass-x"})
        org_accounts = sorted(set(facts.preview_accounts) | {_account(p) for p in facts.protected_roles}
                              | {ORG_ACCOUNT_ON_NO_LIST})
        principals = [role(a, n, org) for a in org_accounts for n in names]
        principals += [role(EXTERNAL_ACCOUNT, n, OTHER_ORG) for n in names]
        principals += [role(STANDALONE_ACCOUNT, "analyst", None), ANONYMOUS, AWS_SERVICE, *extra_principals]
        self.values = {
            "principal": principals,
            "region": list(facts.allowed_regions) + [r for r in REGIONS_NAMED_NOWHERE if r not in facts.allowed_regions],
            "vpce": list(facts.endpoints) + [ATTACKER_VPCE, None],
            "via": [False, True],
            "resource_org": [org, OTHER_ORG, None],
            "resource_account": sorted(set(facts.trusted_resource_accounts) | {org_accounts[0], EXTERNAL_ACCOUNT,
                                                                                STANDALONE_ACCOUNT}) + [None],
            "tag": [TAG_VALUE, None],
        }
        actions = list(contract_actions) + list(EXTRA_ACTIONS) + list(extra_actions)
        self.actions = sorted(set(actions))
        role_resources = {f"arn:aws:iam::{a}:role/{n}" for a in org_accounts + [EXTERNAL_ACCOUNT] for n in names}
        for pattern in facts.protected_roles:
            role_resources.update(sample(pattern))
        self.resources = sorted(role_resources) + [
            f"arn:aws:athena:{facts.allowed_regions[0]}:{org_accounts[0]}:workgroup/primary",
            "arn:aws:s3:::example-bucket/key"]

    def with_literals(self, patterns) -> list[str]:
        """The action universe plus every literal action a pattern names."""
        literal = {p for p in patterns if "*" not in p and "?" not in p}
        return sorted(set(self.actions) | literal)


@functools.lru_cache(maxsize=1024)
def _classes(universe: tuple[str, ...], patterns: tuple[str, ...], ignore_case: bool) -> list[str]:
    """One representative per class of values that every pattern treats alike."""
    compiled = [_compiled(p, ignore_case) for p in dict.fromkeys(patterns)]
    reps = {}
    for value in universe:
        reps.setdefault(tuple(c.match(value) is not None for c in compiled), value)
    return list(reps.values())


class View:
    """What a property sees of a request: only the dimensions it declares."""

    def __init__(self, point: dict, reads: tuple[str, ...]):
        self._point, self._reads = point, set(reads) | {"principal", "action", "resource"}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._reads:
            raise AssertionError(f"the property reads {name!r} without declaring it in reads")
        return self._point[name]


Patterns = tuple[str, ...] | Callable[[Facts], tuple[str, ...]]


@dataclass(frozen=True)
class Property:
    """What one control must deny, stated independently of the generated policy."""

    control: str
    title: str
    constrains: str                       # CONSTRAINS_PRINCIPALS or CONSTRAINS_RESOURCES
    actions: Patterns = ()
    not_actions: Patterns = ()
    resources: Patterns = ("*",)
    reads: tuple[str, ...] = ()           # dimensions deny_when reads besides principal
    deny_when: Callable = field(default=lambda r, f: True)
    break_glass_exempt: bool = True       # False: break-glass is held to this control too

    def patterns(self, facts: Facts) -> tuple[list[str], list[str], list[str]]:
        get = lambda v: list(v(facts) if callable(v) else v)  # noqa: E731
        return get(self.actions), get(self.not_actions), get(self.resources)


def trusted(principal: Principal, facts: Facts, exceptions: tuple[str, ...], break_glass: bool = True) -> bool:
    """Exempt by design: an organization principal that is break-glass or holds an approved exception."""
    if not principal.in_org or principal.arn is None:
        return False
    return any(matches(p, principal.arn) for p in (facts.break_glass if break_glass else ()) + exceptions)


def _in_scope(patterns: tuple[list, list, list], action: str, resource: str) -> bool:
    actions, not_actions, resources = patterns
    if actions and not any(matches(p, action, ignore_case=True) for p in actions):
        return False
    if not_actions and any(matches(p, action, ignore_case=True) for p in not_actions):
        return False
    return any(matches(p, resource) for p in resources)


def in_domain(prop: Property, point: dict, facts: Facts) -> bool:
    """Whether the kind of policy that enforces the property sees the request at all."""
    if prop.constrains == CONSTRAINS_PRINCIPALS:
        return point["principal"].in_org
    if prop.constrains == CONSTRAINS_RESOURCES:
        return point.get("resource_org") == facts.org_id
    return point.get("vpce") in facts.endpoints and not point["principal"].service


def property_denies(prop: Property, point: dict, facts: Facts, exceptions: tuple[str, ...]) -> bool:
    if not in_domain(prop, point, facts):
        return False
    if not _in_scope(prop.patterns(facts), point["action"], point["resource"]):
        return False
    if trusted(point["principal"], facts, exceptions, prop.break_glass_exempt):
        return False
    return bool(prop.deny_when(View(point, prop.reads), facts))


def to_request(point: dict, facts: Facts) -> Request:
    """Build the evaluator's request context from a point in the space."""
    p: Principal = point["principal"]
    ctx = {"aws:ViaAWSService": "true" if point.get("via") else "false",
           "aws:PrincipalIsAWSService": "true" if p.service else "false"}
    if p.org_id:
        ctx["aws:PrincipalOrgID"] = p.org_id
    optional = {"aws:SourceVpce": point.get("vpce"), "aws:ResourceOrgID": point.get("resource_org"),
                "aws:ResourceAccount": point.get("resource_account"),
                "aws:RequestTag/cost-center": point.get("tag")}
    ctx.update({k: v for k, v in optional.items() if v is not None})
    return Request(action=point["action"], principal_arn=p.arn, principal_account=p.account,
                   region=point.get("region") or facts.allowed_regions[0], resource=point["resource"],
                   context=ctx, resource_in_org=point.get("resource_org") == facts.org_id)


def default_point(facts: Facts, **overrides) -> dict:
    """An ordinary request: an analyst in the first preview (or organization) account, done right."""
    account = (facts.preview_accounts or (ORG_ACCOUNT_ON_NO_LIST,))[0]
    point = {"principal": role(account, "analyst", facts.org_id), "action": f"{facts.service}:GetWorkGroup",
             "resource": f"arn:aws:athena:{facts.allowed_regions[0]}:{account}:workgroup/primary",
             "region": facts.allowed_regions[0], "vpce": (facts.vpce_ids or (None,))[0], "via": False,
             "resource_org": facts.org_id, "resource_account": account, "tag": None}
    point.update(overrides)
    return point


def statement_dimensions(stmt: dict | None) -> set[str]:
    if stmt is None:
        return set()
    dims = set()
    for keys in stmt.get("Condition", {}).values():
        for key in keys:
            dim = KEY_DIMENSION.get(key.lower())
            if dim is None:
                raise AssertionError(f"{stmt.get('Sid')} reads {key}, which the attacker model doesn't vary")
            dims.add(dim)
    return dims


def counterexamples(stmt: dict | None, prop: Property, space: Space, exceptions: tuple[str, ...] = (),
                    limit: int = 5) -> list[dict]:
    """Points where the statement and the property disagree, over the whole model.

    `stmt` is None when no statement was generated for an active property.
    """
    facts = space.facts
    scope = prop.patterns(facts)
    p_actions, p_not, p_resources = scope
    s_actions = _list(stmt.get("Action", [])) + _list(stmt.get("NotAction", [])) if stmt else []
    s_resources = _list(stmt.get("Resource", "*")) if stmt else []
    action_patterns = tuple(s_actions + p_actions + p_not)
    actions = _classes(tuple(space.with_literals(action_patterns)), action_patterns, ignore_case=True)
    resource_patterns = tuple(s_resources + p_resources)
    universe = sorted(set(space.resources) | {r for p in resource_patterns if p != "*" for r in sample(p)})
    resources = _classes(tuple(universe), resource_patterns, ignore_case=False)
    # Neither side can deny outside its actions and resources, so pairs that
    # neither matches can't disagree: skip them.
    unconditional = {k: v for k, v in stmt.items() if k != "Condition"} if stmt else None
    neutral = default_point(facts)

    dims = {"principal"} | statement_dimensions(stmt) | set(prop.reads)
    if prop.constrains == CONSTRAINS_ENDPOINTS:
        dims.add("vpce")
    values = {d: space.values[d] for d in sorted(dims & set(DIMENSIONS))}
    if prop.constrains == CONSTRAINS_PRINCIPALS:  # SCPs govern organization principals only
        values["principal"] = [p for p in values["principal"] if p.in_org]
    elif prop.constrains == CONSTRAINS_RESOURCES:  # RCPs govern organization resources only
        values["resource_org"] = [facts.org_id]
    else:  # endpoint policies govern every caller that comes through the organization's endpoints
        values["vpce"] = list(facts.endpoints)
        values["principal"] = [p for p in values["principal"] if not p.service]
    found = []
    names = list(values)
    pairs = [(a, r) for a in actions for r in resources
             if _in_scope(scope, a, r) or (unconditional and statement_applies(
                 unconditional, to_request({**neutral, "action": a, "resource": r}, facts)))]
    for (action, resource), *combo in itertools.product(pairs, *values.values()):
        point = {"action": action, "resource": resource, **dict(zip(names, combo))}
        request = to_request(point, facts)
        got = statement_applies(stmt, request) if stmt else False
        want = property_denies(prop, point, facts, exceptions)
        if got != want:
            found.append({"point": describe(point), "statement_denies": got, "property_denies": want})
            if len(found) >= limit:
                break
    return found


def allow_list_counterexamples(allow_stmt: dict, space: Space, limit: int = 5) -> list[str]:
    """Actions the generated allow-list treats differently from the service plus its dependencies."""
    allowed = {p.lower() for p in space.facts.allow_prefixes}
    universe = space.with_literals(_list(allow_stmt.get("Action", [])))
    found = []
    for action in universe:
        point = default_point(space.facts, action=action)
        got = statement_applies(allow_stmt, to_request(point, space.facts))
        if got != (action.split(":")[0].lower() in allowed):
            found.append(action)
            if len(found) >= limit:
                break
    return found


def describe(point: dict) -> dict:
    out = dict(point)
    out["principal"] = point["principal"].label
    return out


def decide(point: dict, facts: Facts, scp_levels: list, rcp_levels: list, endpoint_policies=()) -> Decision:
    """The whole decision for one request: SCPs bind organization principals, RCPs organization resources,
    endpoint policies whoever comes through one of the organization's endpoints."""
    principal: Principal = point["principal"]
    through_endpoint = point.get("vpce") in facts.endpoints
    return evaluate(to_request(point, facts), scp_levels if principal.in_org else [], rcp_levels,
                    endpoint_policies if through_endpoint else ())


def endpoint_allow_counterexamples(allow_stmt: dict, space: Space, limit: int = 5) -> list[str]:
    """Actions the endpoint policy's base allow doesn't allow. It must allow everything and leave the denying
    to the guardrails, or it breaks traffic nobody decided to break."""
    found = []
    for principal in [p for p in space.values["principal"] if not p.service]:
        for action in space.actions:
            point = default_point(space.facts, principal=principal, action=action,
                                  vpce=(space.facts.endpoints or (None,))[0])
            if not statement_applies(allow_stmt, to_request(point, space.facts)):
                found.append(f"{principal.label} {action}")
                if len(found) >= limit:
                    return found
    return found


# --- Mutation operators ---------------------------------------------------------------
_NEGATE = {"StringNotEquals": "StringEquals", "StringNotLike": "StringLike", "ArnNotLike": "ArnLike"}
_NEGATE.update({v: k for k, v in list(_NEGATE.items())})
_FLIP = {"true": "false", "false": "true"}


def _negated(op: str) -> bool:
    return op.removesuffix("IfExists") in ("StringNotEquals", "StringNotLike", "ArnNotLike")


def _narrow(pattern: str) -> str:
    return pattern[:-1] + "Get*" if pattern.endswith("*") else pattern


def mutants(stmt: dict):
    """Yield (description, mutated statement or None) for the bugs a generator could make.

    Removing IfExists from a negated operator is left out: for a missing key,
    StringNotEquals and StringNotEqualsIfExists both match, so the mutant
    would be equivalent to the original and could never be caught. Other
    equivalent mutants depend on the control; the tests list them with reasons.
    """
    yield "drop the statement", None
    for key in ("Action", "NotAction", "Resource"):
        if key not in stmt:
            continue
        entries = _list(stmt[key])
        for i, entry in enumerate(entries):
            if len(entries) > 1:
                m = copy.deepcopy(stmt)
                m[key] = entries[:i] + entries[i + 1:]
                yield f"drop {entry} from {key}", m
            if key != "Resource" and entry.endswith("*"):
                m = copy.deepcopy(stmt)
                m[key] = entries[:i] + [_narrow(entry)] + entries[i + 1:]
                yield f"narrow {entry} to {_narrow(entry)} in {key}", m
            if key != "Resource" and "*" not in entry:
                m = copy.deepcopy(stmt)
                m[key] = entries[:i] + [entry.split(":")[0] + ":*"] + entries[i + 1:]
                yield f"widen {entry} to its whole service in {key}", m
        if key == "Resource" and entries != ["*"]:
            m = copy.deepcopy(stmt)
            m[key] = "*"
            yield "widen Resource to *", m
    if "Action" in stmt or "NotAction" in stmt:
        m = copy.deepcopy(stmt)
        key, other = ("Action", "NotAction") if "Action" in stmt else ("NotAction", "Action")
        m[other] = m.pop(key)
        yield f"swap {key} for {other}", m
    for op, keys in stmt.get("Condition", {}).items():
        for cond_key, value in keys.items():
            m = copy.deepcopy(stmt)
            del m["Condition"][op][cond_key]
            if not m["Condition"][op]:
                del m["Condition"][op]
            if not m["Condition"]:
                del m["Condition"]
            yield f"drop {op} {cond_key}", m

            base = op.removesuffix("IfExists")
            if base in _NEGATE:
                yield f"negate {op} {cond_key}", _replace_op(stmt, op, cond_key, op.replace(base, _NEGATE[base]))
            if base in ("Bool", "Null"):
                m = copy.deepcopy(stmt)
                m["Condition"][op][cond_key] = [_FLIP.get(str(v).lower(), v) for v in _list(value)]
                yield f"flip {op} {cond_key}", m
            if not _negated(op) and base != "Null":  # IAM has no NullIfExists
                toggled = base if op.endswith("IfExists") else op + "IfExists"
                yield f"change {op} to {toggled} on {cond_key}", _replace_op(stmt, op, cond_key, toggled)

            values = _list(value)
            for i, v in enumerate(values):
                if len(values) > 1:
                    m = copy.deepcopy(stmt)
                    rest = values[:i] + values[i + 1:]
                    m["Condition"][op][cond_key] = rest if len(rest) > 1 else rest[0]
                    yield f"drop {v} from {op} {cond_key}", m
                if cond_key.lower() == "aws:principalarn" and v.startswith("arn:aws:iam::"):
                    widened = v.replace(_account(v), "*", 1)
                    if widened != v:
                        m = copy.deepcopy(stmt)
                        m["Condition"][op][cond_key] = values[:i] + [widened] + values[i + 1:]
                        yield f"widen the account in {v} to *", m


def _replace_op(stmt: dict, op: str, key: str, new_op: str) -> dict:
    m = copy.deepcopy(stmt)
    value = m["Condition"][op].pop(key)
    if not m["Condition"][op]:
        del m["Condition"][op]
    m["Condition"].setdefault(new_op, {})[key] = value
    return m


def endpoint_allow_mutants(allow_stmt: dict):
    yield "narrow the base allow to s3:*", {**allow_stmt, "Action": "s3:*"}
    yield "limit the base allow to organization principals", {
        **allow_stmt, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}}


def allow_list_mutants(allow_stmt: dict):
    entries = _list(allow_stmt["Action"])
    for i, entry in enumerate(entries):
        m = copy.deepcopy(allow_stmt)
        m["Action"] = entries[:i] + entries[i + 1:] or ["none:none"]
        yield f"drop {entry} from the allow-list", m
    m = copy.deepcopy(allow_stmt)
    m["Action"] = entries + ["*"]
    yield "add * to the allow-list", m
