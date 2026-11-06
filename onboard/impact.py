"""Impact: replay recent CloudTrail activity through every deny a run would deploy (ADR-0012).

Review asks, for every organization-wide deny (and every deny on a promotion),
whether it breaks a workload that runs today. Without evidence that is a High
or Medium doubt for a person. This stage answers it from the organization's
own CloudTrail records: each successful call in the export is turned into an
evaluator request and run through each deny statement, where Compose attaches
it. The result is `impact.json`, evidence/v1 items bound to each statement's
hash, which Review reads like any other impact evidence:

- `pass`: no call in the window would have been denied, and every call in
  the deny's scope could be evaluated;
- `fail`: some calls would have been denied (listed). Review blocks: the run
  must change (an exception, a narrower deny) before it releases;
- no item: calls in scope lacked a field the deny's conditions read
  (`undetermined`), so the question stays with a person.

Only what CloudTrail records is known. Organization membership comes from
`org_state` (an account it lists is in the organization), the resource owner from `resources` or else
`recipientAccountId`, an assumed role's ARN from its session issuer, the endpoint from `vpcEndpointId`, a service
call from `invokedBy`, request tags from `requestParameters.tags`. A key the
deny reads that none of these give makes the call undetermined for that deny.
IAM action names are taken as `<eventSource prefix>:<eventName>`; where an API
name differs from its action name, a call can be missed (finding F3).

The window must cover at least `MIN_WINDOW_DAYS`; Review ignores shorter replays.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

from . import __version__
from .compose import ROOT, Organization
from .evaluator import Request, statement_applies
from .verify import deny_statements, sha256

SCHEMA = "evidence/v1"
REPORT_SCHEMA = "impact/v1"
MIN_WINDOW_DAYS = 30
MAX_EXAMPLES = 5
# The organization ID of an account org_state doesn't list: not ours, whichever it is. If org_state
# leaves an account out, its calls look external, which can only make a replay fail, never pass.
OUTSIDE = "outside-this-organization"
_SERVICE_HOST = re.compile(r"^([a-z0-9-]+)\.amazonaws\.com$")


class ImpactError(ValueError):
    pass


def load_records(raw: bytes) -> list[dict]:
    """CloudTrail records from a log file ({"Records": [...]}) or a JSON list of records."""
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise ImpactError(f"not JSON: {exc}") from exc
    records = doc.get("Records") if isinstance(doc, dict) else doc
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise ImpactError("expected a CloudTrail log ({\"Records\": [...]}) or a list of records")
    return records


def _time(record: dict) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(record.get("eventTime", "")).replace("Z", "+00:00"))
    except ValueError:
        return None


def _keys_read(stmt: dict) -> set[str]:
    return {key.lower() for keys in stmt.get("Condition", {}).values() for key in keys}


def to_request(record: dict, org: Organization, org_id: str) -> tuple[Request, set[str]] | None:
    """The evaluator request for a successful call, and the context keys CloudTrail gave; None if not a call."""
    m = _SERVICE_HOST.match(str(record.get("eventSource", "")))
    name = record.get("eventName")
    if not m or not isinstance(name, str) or record.get("errorCode"):
        return None
    identity = record.get("userIdentity") or {}
    account = identity.get("accountId") or record.get("recipientAccountId")
    service_principal = identity.get("type") == "AWSService"
    arn = None
    if identity.get("type") == "AssumedRole":
        arn = ((identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
    elif identity.get("type") in ("IAMUser", "Root"):
        arn = identity.get("arn")
    context = {"aws:PrincipalIsAWSService": "true" if service_principal else "false",
               "aws:RequestedRegion": record.get("awsRegion"),
               "aws:ViaAWSService": "true" if str(record.get("invokedBy", "")).endswith(".amazonaws.com") else "false"}
    if account:
        context["aws:PrincipalAccount"] = account
        # org_state lists the organization's accounts: any other account is outside it.
        context["aws:PrincipalOrgID"] = org_id if account in org.accounts else OUTSIDE
    if record.get("vpcEndpointId"):
        context["aws:SourceVpce"] = record["vpcEndpointId"]
    resources = record.get("resources") or []
    resource = next((r.get("ARN") for r in resources if isinstance(r, dict) and r.get("ARN")), "*")
    owner = next((r.get("accountId") for r in resources if isinstance(r, dict) and r.get("accountId")), None)
    # recipientAccountId is the account that received the call: the resource owner on cross-account access.
    owner = owner or record.get("recipientAccountId")
    if owner:
        context["aws:ResourceAccount"] = owner
        context["aws:ResourceOrgID"] = org_id if owner in org.accounts else OUTSIDE
    tags = (record.get("requestParameters") or {}).get("tags")
    if isinstance(tags, dict):
        tags = [{"key": k, "value": v} for k, v in tags.items()]
    if isinstance(tags, list):
        for tag in tags:
            key = (tag or {}).get("key") or (tag or {}).get("Key")
            if key:
                context[f"aws:RequestTag/{key}"] = (tag.get("value") or tag.get("Value") or "")
    known = {k.lower() for k, v in context.items() if v is not None}
    # CloudTrail records these whenever they exist, so their absence is an answer too.
    known.add("aws:sourcevpce")
    if isinstance(record.get("requestParameters"), dict):
        known.add("aws:requesttag/*")
    request = Request(action=f"{m.group(1)}:{name}", principal_arn=arn, principal_account=account,
                      region=record.get("awsRegion") or "", resource=resource, context=context,
                      resource_in_org=owner in org.accounts if owner else True)
    return request, known


def _who(record: dict, req: Request) -> str:
    """A role's ARN, never a person's: an IAM user's ARN carries their name (personal data)."""
    kind = (record.get("userIdentity") or {}).get("type")
    if kind == "AssumedRole" and req.principal_arn:
        return req.principal_arn
    return f"{kind or 'a principal'} in {req.principal_account or 'an unknown account'}"


def _scope(name: str, composition: dict, org: Organization) -> set[str] | None:
    """Accounts whose calls a policy binds: None for every account."""
    placement = composition.get("placements", {}).get(name)
    if placement is None:
        return None  # endpoint policies: every caller through the endpoints
    targets = placement.get("targets", [])
    if ROOT in targets:
        return None
    accounts = set()
    for target in targets:
        accounts |= {target} if target in org.accounts else {a for a in org.below(target) if a in org.accounts}
    return accounts


def replay(policies: dict, composition: dict, org_state: dict, records: list[dict], *, source: str) -> dict:
    """Return {"evidence": evidence/v1, "report": impact/v1}."""
    org = Organization(org_state)
    org_id = org_state.get("organization_id", "")
    times = [t for t in (_time(r) for r in records) if t]
    if not times:
        raise ImpactError("no record has an eventTime")
    start, end = min(times), max(times)
    days = (end - start).total_seconds() / 86400
    calls = [(r, c) for r in records if (c := to_request(r, org, org_id))]
    endpoints = {e for ids in composition.get("endpoints", {}).values() for e in ids}
    items, statements = [], []
    for name, stmt in deny_statements(policies):
        scope = _scope(name, composition, org)
        reads = _keys_read(stmt)
        in_scope = denied = undetermined = 0
        examples = []
        for record, (req, known) in calls:
            if name.startswith("vpce-"):
                if req.context.get("aws:SourceVpce") not in endpoints:
                    continue
            elif name.startswith("rcp-"):
                if not req.resource_in_org:
                    continue
            elif scope is not None and req.principal_account not in scope:
                continue
            # A call the deny's actions don't cover can't be affected by it.
            if not statement_applies({k: v for k, v in stmt.items() if k in ("Action", "NotAction")}, req):
                continue
            in_scope += 1
            missing = sorted(k for k in reads if k not in known and not k.startswith("aws:principalarn")
                             and not (k.startswith("aws:requesttag/") and "aws:requesttag/*" in known))
            if stmt.get("Resource", "*") not in ("*", ["*"]) and req.resource == "*":
                missing.append("resource ARN")
            if missing:
                undetermined += 1
                continue
            if statement_applies(stmt, req):
                denied += 1
                if len(examples) < MAX_EXAMPLES:
                    examples.append({"eventTime": record.get("eventTime"), "action": req.action,
                                     "account": req.principal_account, "principal": _who(record, req)})
        entry = {"policy": name, "sid": stmt.get("Sid"), "statement_sha256": sha256(stmt), "in_scope": in_scope,
                 "denied": denied, "undetermined": undetermined, "examples": examples}
        statements.append(entry)
        if denied:
            result, detail = "fail", f"would deny {denied} of {in_scope} recent calls, e.g. " + ", ".join(
                f"{e['action']} by {e['principal'] or e['account']}" for e in examples)
        elif undetermined:
            continue  # can't tell: no evidence, the doubt stays with a person
        else:
            result, detail = "pass", f"denies none of {in_scope} calls in scope over {days:.0f} days"
        items.append({"kind": "impact", "policy": name, "sid": stmt.get("Sid"), "statement_sha256": entry["statement_sha256"],
                      "result": result, "source": source, "detail": detail,
                      "window": {"start": start.isoformat(), "end": end.isoformat(), "days": round(days, 2)},
                      "calls": {"in_scope": in_scope, "denied": denied}})
    report = {"schema": REPORT_SCHEMA, "tool_version": __version__, "source": source,
              "window": {"start": start.isoformat(), "end": end.isoformat(), "days": round(days, 2)},
              "records": len(records), "calls": len(calls), "statements": statements,
              "enough_history": days >= MIN_WINDOW_DAYS}
    return {"evidence": {"schema": SCHEMA, "items": items}, "report": report}


def source_of(paths_and_bytes: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256(b"".join(hashlib.sha256(raw).digest() for _, raw in paths_and_bytes)).hexdigest()
    return f"onboard impact {__version__}: CloudTrail replay sha256:{digest}"
