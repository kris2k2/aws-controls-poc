"""Resolve: turn one service into a capability profile.

This slice covers prefix resolution and the API contract (actions tiered by
risk, resource types, condition keys, SDK operations) from the service
reference. The rest of Resolve (resource-type crosswalk, dependencies,
regional availability, capability flags, prerequisites) is listed in the
profile under `not_yet_assessed`, so nothing is silently missing.
"""

from __future__ import annotations

import re

from . import __version__
from .service_reference import ServiceReference, SourceError

SCHEMA = "capability-profile/v1"

# Services whose actions span several IAM prefixes, or live under another
# service's prefix. Only prefixes present in the service reference are kept.
SPANS: dict[str, tuple[str, ...]] = {
    "s3": ("s3", "s3express", "s3-object-lambda", "s3tables"),
    "ebs": ("ec2", "ebs"),
    "vpc": ("ec2",),
}

# Highest risk first; an action takes the first tier whose annotation it has.
RISK_TIERS = ("permission-management", "write", "tagging", "read", "list")

NOT_YET_ASSESSED = (
    "resource-type crosswalk (IAM, CloudFormation, Config, Terraform)",
    "dependencies (KMS, iam:PassRole, service-linked roles, CloudWatch Logs, VPC endpoints)",
    "regional availability in ca-central-1 and eu-west-1",
    "capability flags (resource policies, RCP, VPC endpoints, customer-managed keys, "
    "CloudTrail data events, Config recording, sharing paths)",
    "prerequisites",
)


class ResolveError(ValueError):
    pass


def normalize(service: str) -> str:
    """'Amazon Bedrock' -> 'bedrock'; 'AWS Lambda' -> 'lambda'; 'S3' -> 's3'."""
    name = service.strip().casefold()
    name = re.sub(r"^(amazon|aws)\s+", "", name)
    return re.sub(r"[\s_]+", "-", name)


def resolve_prefixes(service: str, known: set[str]) -> tuple[list[str], list[str]]:
    """Return (prefixes, related) for a service name.

    `prefixes` are the IAM prefixes the service spans. `related` are other
    prefixes that share its name (for example bedrock-agentcore for bedrock):
    they are proposed for the analyst to confirm, never included silently.
    """
    base = normalize(service)
    if base in SPANS:
        prefixes = [p for p in SPANS[base] if p in known]
    elif base in known:
        prefixes = [base]
    else:
        raise ResolveError(f"could not resolve {service!r} to an IAM service prefix; "
                           "pass the prefix itself (for example 'bedrock')")
    if not prefixes:
        raise ResolveError(f"none of the prefixes for {service!r} are in the service reference")
    related = sorted(p for p in known if p.startswith(base + "-") and p not in prefixes)
    return sorted(prefixes), related


def risk_tier(action: dict) -> str:
    props = (action.get("Annotations") or {}).get("Properties") or {}
    if props.get("IsPermissionManagement"):
        return "permission-management"
    if props.get("IsTaggingOnly"):
        return "tagging"
    if props.get("IsWrite"):
        return "write"
    if props.get("IsList"):
        return "list"
    return "read"


def _names(items) -> list[str]:
    return sorted({i["Name"] for i in items or [] if isinstance(i, dict) and isinstance(i.get("Name"), str)})


def profile_prefix(document: dict) -> dict:
    prefix = document["Name"]
    actions = []
    for a in document.get("Actions") or []:
        if not isinstance(a, dict) or not isinstance(a.get("Name"), str):
            raise SourceError(f"{prefix}: an action has no name")
        props = (a.get("Annotations") or {}).get("Properties") or {}
        actions.append({
            "action": f"{prefix}:{a['Name']}",
            "risk_tier": risk_tier(a),
            "data_plane": bool(props.get("IsDataPlane")),
            "resource_types": _names(a.get("Resources")),
            "condition_keys": sorted(set(a.get("ActionConditionKeys") or [])),
        })
    actions.sort(key=lambda a: a["action"])

    resources = sorted(
        ({"resource_type": r["Name"], "arn_formats": sorted(r.get("ARNFormats") or [])}
         for r in document.get("Resources") or [] if isinstance(r, dict) and isinstance(r.get("Name"), str)),
        key=lambda r: r["resource_type"])
    keys = sorted(
        ({"condition_key": k["Name"], "types": sorted(k.get("Types") or [])}
         for k in document.get("ConditionKeys") or [] if isinstance(k, dict) and isinstance(k.get("Name"), str)),
        key=lambda k: k["condition_key"])
    operations = sorted(
        ({"operation": o["Name"],
          "authorized_actions": sorted(f"{x['Service']}:{x['Name']}" for x in o.get("AuthorizedActions") or []
                                       if isinstance(x, dict) and "Service" in x and "Name" in x),
          "boto3": sorted(f"{s['Name']}.{s['Method']}" for s in o.get("SDK") or []
                          if isinstance(s, dict) and s.get("Package") == "Boto3" and "Name" in s and "Method" in s)}
         for o in document.get("Operations") or [] if isinstance(o, dict) and isinstance(o.get("Name"), str)),
        key=lambda o: o["operation"])

    by_tier = {t: 0 for t in RISK_TIERS}
    for a in actions:
        by_tier[a["risk_tier"]] += 1
    return {
        "prefix": prefix,
        "actions": actions,
        "resource_types": resources,
        "condition_keys": keys,
        "operations": operations,
        "summary": {"actions": len(actions), "actions_by_risk_tier": by_tier,
                    "resource_types": len(resources), "condition_keys": len(keys)},
    }


def resolve(service: str, reference: ServiceReference) -> dict:
    """Build the capability profile for `service` from the service reference."""
    index = reference.index()
    entries = reference.prefixes()
    prefixes, related = resolve_prefixes(service, set(entries))
    profiles, sources = [], [{"source": "aws-service-reference-index", "url": index.url,
                              "retrieved": index.retrieved}]
    for prefix in prefixes:
        fetched = reference.service(prefix)
        profiles.append(profile_prefix(fetched.document))
        sources.append({"source": "aws-service-reference", "prefix": prefix, "url": fetched.url,
                        "version": fetched.document.get("Version"),
                        "modified": entries[prefix].get("modified"), "retrieved": fetched.retrieved})
    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "service": service,
        "prefixes": prefixes,
        "related_prefixes_to_confirm": related,
        "services": profiles,
        "sources": sources,
        "not_yet_assessed": list(NOT_YET_ASSESSED),
    }
