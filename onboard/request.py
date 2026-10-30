"""The onboarding request: parsing, defaults and validation.

A run starts from one request; the same request must always produce the same
control set given the same pinned source versions, so validation is strict and
every default is explicit here rather than implied downstream.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

from .model import Criticality, Tier

RUN_MODES = ("new", "diff", "offboard")
DEFAULT_REGULATORY_PROFILE = "ca-frfi-global"
DEFAULT_FRAMEWORK_PROFILE = "baseline"
# The profile's region policy: ca-central-1 and eu-west-1 open org-wide;
# us-east-1 only through exceptions discovered in Resolve.
DEFAULT_ALLOWED_REGIONS = ("ca-central-1", "eu-west-1")
# The lowest criticality each data classification implies. A classification
# raises the declared (or default) criticality, never lowers it. Internal
# Restricted is the classification behind the Moderate default (decided
# 2026-10-30). Labels above it are deliberately absent until their criticality
# is decided, so a request using one fails instead of being guessed.
CLASSIFICATION_CRITICALITY = {
    "Public": Criticality.LOW,
    "Internal": Criticality.LOW,
    "Internal Restricted": Criticality.MODERATE,
}

_ACCOUNT_ID = re.compile(r"^\d{12}$")
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_KNOWN_FIELDS = {
    "service", "maturity_tier", "preview_accounts", "target_scope", "org_state",
    "control_registry", "maker", "checker", "criticality", "data_classification",
    "regulatory_profile", "jurisdictions", "allowed_regions", "framework_profile",
    "capabilities_excluded", "exceptions", "break_glass_principals", "source_pins",
    "run_mode", "non_production_attested", "decisions",
}
_EXCEPTION_FIELDS = ("principal", "control_id", "owner", "expires", "rationale")


class RequestError(ValueError):
    """The request is invalid; the message lists every problem found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid onboarding request:\n  - " + "\n  - ".join(problems))


@dataclass(frozen=True)
class OnboardingException:
    principal: str
    control_id: str
    owner: str
    expires: dt.date
    rationale: str


@dataclass(frozen=True)
class OnboardingRequest:
    service: str
    maturity_tier: Tier
    maker: str
    checker: str
    org_state: dict
    run_mode: str = "new"
    preview_accounts: tuple[str, ...] = ()
    non_production_attested: bool = False
    target_scope: tuple[str, ...] = ()
    control_registry: dict | None = None
    criticality: Criticality = Criticality.MODERATE
    data_classification: str | None = None
    # Where the criticality came from: "declared", "default", or "raised by data classification".
    criticality_source: str = "default"
    regulatory_profile: str = DEFAULT_REGULATORY_PROFILE
    jurisdictions: tuple[str, ...] = ()
    allowed_regions: tuple[str, ...] = DEFAULT_ALLOWED_REGIONS
    framework_profile: str = DEFAULT_FRAMEWORK_PROFILE
    capabilities_excluded: tuple[str, ...] = ()
    exceptions: tuple[OnboardingException, ...] = ()
    break_glass_principals: tuple[str, ...] = ()
    source_pins: dict = field(default_factory=dict)
    # Analyst decisions the spec leaves open per service, e.g. {"network_perimeter": "vpc-endpoint"}.
    decisions: dict = field(default_factory=dict)


def _strings(value: Any, name: str, problems: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        problems.append(f"{name} must be a list of non-empty strings")
        return ()
    return tuple(value)


def _enum(cls, value: Any, name: str, problems: list[str], default=None):
    if value is None:
        if default is None:
            problems.append(f"{name} is required")
        return default
    try:
        return cls(value)
    except ValueError:
        problems.append(f"{name} must be one of: {', '.join(m.value for m in cls)}")
        return default


def parse_request(data: Any, today: dt.date | None = None) -> OnboardingRequest:
    """Validate a decoded request document and apply the documented defaults."""
    today = today or dt.date.today()
    if not isinstance(data, dict):
        raise RequestError(["request must be a JSON object"])
    problems: list[str] = []

    unknown = sorted(set(data) - _KNOWN_FIELDS)
    if unknown:
        problems.append(f"unknown fields: {', '.join(unknown)}")

    service = data.get("service")
    if not isinstance(service, str) or not _SERVICE.match(service):
        problems.append("service is required: an IAM prefix, service name or boto3 client name")

    tier = _enum(Tier, data.get("maturity_tier"), "maturity_tier", problems)
    criticality = _enum(Criticality, data.get("criticality"), "criticality", problems,
                        default=Criticality.MODERATE)
    criticality_source = "declared" if data.get("criticality") is not None else "default"
    classification = data.get("data_classification")
    if isinstance(classification, str) and classification.strip():
        implied = CLASSIFICATION_CRITICALITY.get(classification)
        if implied is None:
            problems.append(f"data_classification {classification!r} has no criticality mapping; "
                            f"known: {', '.join(CLASSIFICATION_CRITICALITY)}")
        elif criticality is not None and implied > criticality:
            criticality, criticality_source = implied, "raised by data classification"

    run_mode = data.get("run_mode", "new")
    if run_mode not in RUN_MODES:
        problems.append(f"run_mode must be one of: {', '.join(RUN_MODES)}")

    maker, checker = data.get("maker"), data.get("checker")
    for name, value in (("maker", maker), ("checker", checker)):
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{name} is required")
    if isinstance(maker, str) and isinstance(checker, str) and maker.strip() \
            and maker.strip().casefold() == checker.strip().casefold():
        problems.append("maker and checker must be two different people")

    org_state = data.get("org_state")
    if not isinstance(org_state, dict):
        problems.append("org_state is required: the OU tree and every attached organization policy")

    registry = data.get("control_registry")
    if registry is not None and not isinstance(registry, dict):
        problems.append("control_registry must be an object")
    if run_mode in ("diff", "offboard") and registry is None:
        problems.append(f"control_registry is required for a {run_mode} run")

    preview_accounts = _strings(data.get("preview_accounts"), "preview_accounts", problems)
    bad = [a for a in preview_accounts if not _ACCOUNT_ID.match(a)]
    if bad:
        problems.append(f"preview_accounts must be 12-digit AWS account IDs: {', '.join(bad)}")
    attested = data.get("non_production_attested", False)
    if not isinstance(attested, bool):
        problems.append("non_production_attested must be true or false")
        attested = False
    if tier is Tier.PRIVATE_PREVIEW:
        if not preview_accounts:
            problems.append("preview_accounts is required at Private Preview")
        if not attested:
            problems.append("non_production_attested must be true at Private Preview: "
                            "the maker attests each preview account holds no production data")

    target_scope = _strings(data.get("target_scope"), "target_scope", problems)
    if tier is not None and tier >= Tier.CONTAINED and not target_scope:
        problems.append(f"target_scope is required at {tier.value}")

    regions = _strings(data.get("allowed_regions"), "allowed_regions", problems) or DEFAULT_ALLOWED_REGIONS
    bad = [r for r in regions if not _REGION.match(r)]
    if bad:
        problems.append(f"allowed_regions has invalid region names: {', '.join(bad)}")

    exceptions = []
    raw_exceptions = data.get("exceptions") or []
    if not isinstance(raw_exceptions, list):
        problems.append("exceptions must be a list")
        raw_exceptions = []
    for i, exc in enumerate(raw_exceptions):
        where = f"exceptions[{i}]"
        if not isinstance(exc, dict):
            problems.append(f"{where} must be an object")
            continue
        missing = [f for f in _EXCEPTION_FIELDS if not isinstance(exc.get(f), str) or not exc[f].strip()]
        if missing:
            problems.append(f"{where} is missing {', '.join(missing)}")
            continue
        try:
            expires = dt.date.fromisoformat(exc["expires"])
        except ValueError:
            problems.append(f"{where}.expires must be an ISO date (YYYY-MM-DD)")
            continue
        if expires <= today:
            problems.append(f"{where} expired on {expires.isoformat()}")
            continue
        exceptions.append(OnboardingException(exc["principal"], exc["control_id"], exc["owner"],
                                              expires, exc["rationale"]))

    for name in ("regulatory_profile", "framework_profile", "data_classification"):
        value = data.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            problems.append(f"{name} must be a non-empty string")
    source_pins = data.get("source_pins") or {}
    if not isinstance(source_pins, dict):
        problems.append("source_pins must be an object")
        source_pins = {}

    decisions = data.get("decisions") or {}
    if not isinstance(decisions, dict) or not all(isinstance(k, str) and isinstance(v, str) and v
                                                   for k, v in decisions.items()):
        problems.append("decisions must map decision names to non-empty strings")
        decisions = {}

    jurisdictions = _strings(data.get("jurisdictions"), "jurisdictions", problems)
    excluded = _strings(data.get("capabilities_excluded"), "capabilities_excluded", problems)
    break_glass = _strings(data.get("break_glass_principals"), "break_glass_principals", problems)

    if problems:
        raise RequestError(problems)
    return OnboardingRequest(
        service=service, maturity_tier=tier, maker=maker.strip(), checker=checker.strip(),
        org_state=org_state, run_mode=run_mode, preview_accounts=preview_accounts,
        non_production_attested=attested, target_scope=target_scope, control_registry=registry,
        criticality=criticality, data_classification=data.get("data_classification"),
        criticality_source=criticality_source,
        regulatory_profile=data.get("regulatory_profile") or DEFAULT_REGULATORY_PROFILE,
        jurisdictions=jurisdictions, allowed_regions=regions,
        framework_profile=data.get("framework_profile") or DEFAULT_FRAMEWORK_PROFILE,
        capabilities_excluded=excluded, exceptions=tuple(exceptions),
        break_glass_principals=break_glass, source_pins=source_pins, decisions=decisions,
    )
