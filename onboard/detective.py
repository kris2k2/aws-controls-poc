"""Detective and plan-time artifacts: Config rules, CloudTrail detections, Sentinel policies (ADR-0009).

A control's `implementations.config`, `.cloudtrail` and `.sentinel` say what
the artifact must catch. When one also carries a structured definition,
Generate renders it here; without one it stays `pending`, never guessed.

- **config**: exactly one of `managed` (an AWS managed rule by identifier),
  `guard` (a custom policy rule: checks on the configuration item, rendered as
  CloudFormation Guard) or `security_hub_control` (enable the Security Hub
  control, whose AWS-managed Config rule does the evaluation). Rendered as
  `AWS::Config::ConfigRule` properties.
- **cloudtrail**: `match`, an EventBridge pattern for the `detail` of
  "AWS API Call via CloudTrail" events, with `${parameters}` from the request.
  Rendered as `AWS::Events::Rule` properties in the state that also matches
  read-only management events.
- **sentinel**: `plan`, the Terraform resource types and either `forbid` or
  checks on each planned resource's `after` values. Rendered as a `tfplan/v2`
  policy; its enforcement level comes from the control's mode.

Config and CloudTrail artifacts are rendered in every mode: they detect, they
don't block. Their routing (record, notify, page) follows the mode and
severity they carry. Nothing here is run through AWS Config, EventBridge or
Sentinel; `evaluate` and `matches` give the local meaning the tests check.
"""

from __future__ import annotations

import copy
import json
import re

from .model import Mode

CONFIG_SCHEMA = "config-rule/v1"
DETECTION_SCHEMA = "detection/v1"
CONFIG_SOURCES = ("managed", "guard", "security_hub_control")
CHECK_OPS = ("exists", "equals", "in", "not_in", "not_empty", "has_tag")
GUARD_OPS = ("exists", "equals", "in", "not_empty", "has_tag")  # not_in has no plain Guard form here
PATTERN_OPERATORS = ("prefix", "anything-but", "exists", "wildcard")
SENTINEL_LEVELS = {
    Mode.ENFORCE: "hard-mandatory",
    Mode.ENFORCE_WITH_OVERRIDE: "soft-mandatory",  # overridable by a named person (finding F11)
    Mode.ADVISE: "advisory",
    Mode.REPORT: "advisory",
}
GUARD_RUNTIME = "guard-2.x.x"
CLOUDTRAIL_DETAIL_TYPE = "AWS API Call via CloudTrail"
# Without this state an EventBridge rule doesn't see read-only (Get, List, Describe) calls.
RULE_STATE = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
CHANGE_TRIGGERS = ("ConfigurationItemChangeNotification", "OversizedConfigurationItemChangeNotification")
NOTES = [
    "EventBridge rules match events only in their own Region: deploy each detection in every enabled Region "
    "(IAM and other global services log in us-east-1).",
    "Config rules evaluate one account and Region: deploy each in every account and Region in scope.",
    "Nothing here has been run through AWS Config, EventBridge or Sentinel; the Guard paths, Terraform "
    "attributes and event fields are the analyst's, checked only by the local evaluator.",
]

_MANAGED_ID = re.compile(r"^[A-Z0-9_]{3,128}$")
_RESOURCE_TYPE = re.compile(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$")
_SECURITY_HUB_ID = re.compile(r"^[A-Za-z0-9]+\.\d{1,3}$")
_TF_TYPE = re.compile(r"^[a-z][a-z0-9_]*$")
_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FIELD = re.compile(r"^[A-Za-z0-9_.\-]+$")
_PARAMETER = re.compile(r"^\$\{([a-z_]+)\}$")


class DetectiveError(ValueError):
    pass


# ---------------------------------------------------------------- definitions


def defined(platform: str, impl: dict) -> bool:
    """Whether a planned implementation carries a structured definition to render."""
    keys = {"config": CONFIG_SOURCES, "cloudtrail": ("match",), "sentinel": ("plan",)}.get(platform, ())
    return any(k in impl for k in keys)


def _scalar(value) -> bool:
    return isinstance(value, (str, int, bool)) and not (isinstance(value, str) and not value)


def _check_checks(checks, where: str, ops: tuple[str, ...], problems: list[str]) -> None:
    if not isinstance(checks, list) or not checks:
        problems.append(f"{where}.checks must be a non-empty list")
        return
    for i, check in enumerate(checks):
        at = f"{where}.checks[{i}]"
        if not isinstance(check, dict):
            problems.append(f"{at} must be an object")
            continue
        path = check.get("path")
        if (not isinstance(path, list) or not path
                or not all((isinstance(s, str) and _SEGMENT.match(s)) or (type(s) is int and s >= 0) for s in path)
                or not isinstance(path[0], str)):
            problems.append(f"{at}.path must be a list of field names (and list indexes), starting with a name")
        op = [k for k in check if k != "path"]
        if len(op) != 1 or op[0] not in ops:
            problems.append(f"{at} needs exactly one of {', '.join(ops)}")
            continue
        value = check[op[0]]
        if op[0] in ("exists", "not_empty") and value is not True:
            problems.append(f"{at}.{op[0]} must be true")
        elif op[0] == "equals" and not _scalar(value):
            problems.append(f"{at}.equals must be a string, number or boolean")
        elif op[0] in ("in", "not_in") and (not isinstance(value, list) or not value
                                            or not all(_scalar(v) for v in value)):
            problems.append(f"{at}.{op[0]} must be a non-empty list of strings, numbers or booleans")
        elif op[0] == "has_tag" and not (isinstance(value, str) and value):
            problems.append(f"{at}.has_tag must be a tag key")


def _check_pattern(pattern, where: str, problems: list[str]) -> None:
    """An EventBridge pattern: objects of fields, each a list of values or filters."""
    if not isinstance(pattern, dict) or not pattern:
        problems.append(f"{where} must be a non-empty object")
        return
    for key, value in pattern.items():
        at = f"{where}.{key}"
        if key == "$or":
            if not isinstance(value, list) or len(value) < 2:
                problems.append(f"{at} must list at least two patterns")
            else:
                for i, branch in enumerate(value):
                    _check_pattern(branch, f"{at}[{i}]", problems)
        elif not _FIELD.match(key):
            problems.append(f"{at} is not a field name")
        elif isinstance(value, dict):
            _check_pattern(value, at, problems)
        elif not isinstance(value, list) or not value:
            problems.append(f"{at} must be an object or a non-empty list")
        else:
            for item in value:
                if isinstance(item, dict):
                    ops = list(item)
                    if len(ops) != 1 or ops[0] not in PATTERN_OPERATORS:
                        problems.append(f"{at} filters need exactly one of {', '.join(PATTERN_OPERATORS)}")
                    elif ops[0] == "exists" and not isinstance(item["exists"], bool):
                        problems.append(f"{at}.exists must be true or false")
                elif not _scalar(item):
                    problems.append(f"{at} values must be strings, numbers, booleans or filters")


def check_definition(platform: str, impl: dict, where: str, problems: list[str]) -> None:
    """Validate the structured definition on a planned config, cloudtrail or sentinel implementation."""
    if platform == "config":
        sources = [k for k in CONFIG_SOURCES if k in impl]
        if len(sources) > 1:
            problems.append(f"{where} needs at most one of {', '.join(CONFIG_SOURCES)}")
        if "managed" in impl:
            m = impl["managed"]
            if not isinstance(m, dict) or not isinstance(m.get("identifier"), str) \
                    or not _MANAGED_ID.match(m["identifier"]):
                problems.append(f"{where}.managed.identifier must be an AWS managed rule identifier "
                                "(like ATHENA_WORKGROUP_ENCRYPTED_AT_REST)")
            elif not isinstance(m.get("resource_types", []), list) \
                    or not all(isinstance(t, str) and _RESOURCE_TYPE.match(t) for t in m.get("resource_types", [])):
                problems.append(f"{where}.managed.resource_types must be AWS::Service::Resource types")
            elif not isinstance(m.get("parameters", {}), dict) \
                    or not all(isinstance(v, str) for v in m.get("parameters", {}).values()):
                problems.append(f"{where}.managed.parameters must map names to strings")
        if "guard" in impl:
            g = impl["guard"]
            if not isinstance(g, dict) or not isinstance(g.get("resource_type"), str) \
                    or not _RESOURCE_TYPE.match(g["resource_type"]):
                problems.append(f"{where}.guard.resource_type must be an AWS::Service::Resource type")
            else:
                _check_checks(g.get("checks"), f"{where}.guard", GUARD_OPS, problems)
        if "security_hub_control" in impl and not (isinstance(impl["security_hub_control"], str)
                                                   and _SECURITY_HUB_ID.match(impl["security_hub_control"])):
            problems.append(f"{where}.security_hub_control must be a Security Hub ID like Athena.4")
    elif platform == "cloudtrail":
        if "match" in impl:
            _check_pattern(impl["match"], f"{where}.match", problems)
            if isinstance(impl["match"], dict) and "eventSource" not in impl["match"] \
                    and not all(isinstance(b, dict) and "eventSource" in b for b in impl["match"].get("$or", [None])):
                problems.append(f"{where}.match must filter on eventSource (in every $or branch)")
        for key in ("requires", "optional_parameters"):
            if key in impl and (not isinstance(impl[key], list) or not all(isinstance(r, str) for r in impl[key])):
                problems.append(f"{where}.{key} must be a list of strings")
    elif platform == "sentinel":
        if "level" in impl:
            problems.append(f"{where}.level is derived from the control's mode; remove it")
        if "plan" in impl:
            p = impl["plan"]
            types = p.get("resource_types") if isinstance(p, dict) else None
            if not isinstance(types, list) or not types or not all(isinstance(t, str) and _TF_TYPE.match(t)
                                                                    for t in types):
                problems.append(f"{where}.plan.resource_types must be a non-empty list of Terraform types")
            elif ("forbid" in p) == ("checks" in p):
                problems.append(f"{where}.plan needs exactly one of forbid or checks")
            elif "forbid" in p and p["forbid"] is not True:
                problems.append(f"{where}.plan.forbid must be true")
            elif "checks" in p:
                _check_checks(p["checks"], f"{where}.plan", CHECK_OPS, problems)


# ---------------------------------------------------------------- local meaning


def _lookup(document, path: list):
    for segment in path:
        if isinstance(segment, int):
            if not isinstance(document, list) or segment >= len(document):
                return None
        elif not isinstance(document, dict) or segment not in document:
            return None
        document = document[segment]
    return document


def _check_holds(check: dict, document, engine: str) -> bool:
    value = _lookup(document, check["path"])
    if "exists" in check:
        return value is not None
    if "equals" in check:
        return value == check["equals"] and type(value) is type(check["equals"])
    if "in" in check:
        return value is not None and value in check["in"]
    if "not_in" in check:
        return value not in check["not_in"]  # absent passes: the default isn't on the list
    if "not_empty" in check:
        return value is not None and value not in ("", [], {})
    key = check["has_tag"]
    if engine == "config":  # CloudFormation tags: [{"Key": ..., "Value": ...}]
        return isinstance(value, list) and any(isinstance(t, dict) and t.get("Key") == key for t in value)
    return isinstance(value, dict) and key in value  # Terraform tags: a map


def evaluate(checks: list[dict], document: dict, engine: str) -> bool:
    """Whether a resource passes every check: a configuration item's `configuration`
    (engine "config") or a planned resource's `after` values (engine "sentinel")."""
    return all(_check_holds(c, document, engine) for c in checks)


def _filter_matches(item, value) -> bool:
    if not isinstance(item, dict):
        return value == item and type(value) is type(item)
    (op, arg), = item.items()
    if op == "prefix":
        return isinstance(value, str) and value.startswith(arg)
    if op == "wildcard":
        pattern = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", arg))
        return isinstance(value, str) and re.fullmatch(pattern, value, re.DOTALL) is not None
    if op == "anything-but":
        if value is None:
            return False
        if isinstance(arg, dict):
            prefixes = arg["prefix"] if isinstance(arg["prefix"], list) else [arg["prefix"]]
            return not (isinstance(value, str) and any(value.startswith(p) for p in prefixes))
        return value not in (arg if isinstance(arg, list) else [arg])
    raise DetectiveError(f"unsupported filter {op}")


def matches(pattern: dict, event: dict) -> bool:
    """EventBridge matching for the filters above: every field matches; a list
    matches if any element does; an array in the event matches if any element does."""
    for key, want in pattern.items():
        if key == "$or":
            if not any(matches(branch, event) for branch in want):
                return False
            continue
        present = isinstance(event, dict) and key in event
        value = event.get(key) if present else None
        if isinstance(want, dict):
            if not isinstance(value, dict) or not matches(want, value):
                return False
            continue
        exists = [w for w in want if isinstance(w, dict) and "exists" in w]
        if exists:
            if any(w["exists"] != present for w in exists):
                return False
            if len(exists) == len(want):
                continue
            want = [w for w in want if w not in exists]
        values = value if isinstance(value, list) else [value]
        if not present or not any(_filter_matches(w, v) for w in want for v in values):
            return False
    return True


# ---------------------------------------------------------------- rendering


def _values(values: list[str], cid: str, name: str) -> list:
    """Parameter values as EventBridge filters: a pattern with * (a break-glass
    ARN like role/BreakGlass-*) becomes a wildcard filter, or it would never match."""
    out = []
    for v in values:
        if "?" in v:
            raise DetectiveError(f"{cid}: {name} value {v!r} uses ?, which an EventBridge pattern can't express")
        out.append({"wildcard": v} if "*" in v else v)
    return out


def _resolve(value, params: dict, cid: str, optional: set[str], in_filter: bool = False):
    """Replace ${parameters}; a list flattens list values. Returns None for an
    empty optional parameter, which drops the $or branch holding it."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in PATTERN_OPERATORS:  # inside a filter: plain values only
                out[key] = _resolve(item, params, cid, optional, in_filter=True)
                if out[key] is None:
                    return None
                continue
            if key == "$or":
                branches = [b for b in (_resolve(b, params, cid, optional) for b in item) if b is not None]
                if not branches:
                    return None
                if len(branches) == 1:
                    out.update(branches[0])
                else:
                    out[key] = branches
                continue
            resolved = _resolve(item, params, cid, optional)
            if resolved is None:
                return None
            out[key] = resolved
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            resolved = _resolve(item, params, cid, optional, in_filter)
            if resolved is None:
                return None
            out.extend(resolved if isinstance(resolved, list) and not isinstance(item, (dict, list)) else [resolved])
        return out
    m = _PARAMETER.match(value) if isinstance(value, str) else None
    if not m:
        return value
    resolved = params.get(m.group(1))
    if not resolved:
        if m.group(1) in optional:
            return None
        raise DetectiveError(f"{cid} needs the parameter {m.group(1)!r}, which the request doesn't provide")
    if in_filter:
        if any("*" in v or "?" in v for v in resolved):
            raise DetectiveError(f"{cid}: {m.group(1)} has patterns, which an EventBridge filter can't take")
        return list(resolved)
    return _values(list(resolved), cid, m.group(1))


def _name(cid: str) -> str:
    return f"onboard-{cid.lower()}"


def _header(record: dict, schema: str) -> dict:
    return {"schema": schema, "control_id": record["control_id"], "title": record["title"],
            "mode": record["mode"], "severity": record["severity"], "shared": bool(record.get("shared"))}


def _text(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _guard_literal(value) -> str:
    return json.dumps(value)


def _guard_path(path: list) -> str:
    return "configuration" + "".join(f"[{s}]" if isinstance(s, int) else f".{s}" for s in path)


def guard_clause(check: dict) -> str:
    path = _guard_path(check["path"])
    if "exists" in check:
        return f"{path} exists"
    if "equals" in check:
        return f"{path} == {_guard_literal(check['equals'])}"
    if "in" in check:
        return f"{path} IN [{', '.join(_guard_literal(v) for v in check['in'])}]"
    if "not_empty" in check:
        return f"{path} !empty"
    return f"{path}[ Key == {_guard_literal(check['has_tag'])} ] !empty"


def guard_policy(record: dict, guard: dict) -> str:
    rule = record["control_id"].lower().replace("-", "_")
    body = "\n".join(f"    {guard_clause(c)}" for c in guard["checks"])
    return (f"# {record['control_id']}: {record['title']}\n"
            f"rule {rule} when resourceType == {_guard_literal(guard['resource_type'])} {{\n{body}\n}}\n")


def render_config(record: dict, impl: dict) -> tuple[str, str]:
    cid = record["control_id"]
    doc = _header(record, CONFIG_SCHEMA)
    if "security_hub_control" in impl:
        doc["security_hub_control"] = impl["security_hub_control"]
    else:
        rule = {"ConfigRuleName": _name(cid), "Description": f"{cid}: {record['title']}"[:256]}
        if "managed" in impl:
            m = impl["managed"]
            if m.get("resource_types"):
                rule["Scope"] = {"ComplianceResourceTypes": list(m["resource_types"])}
            rule["Source"] = {"Owner": "AWS", "SourceIdentifier": m["identifier"]}
            if m.get("parameters"):
                rule["InputParameters"] = dict(m["parameters"])
        else:
            g = impl["guard"]
            rule["Scope"] = {"ComplianceResourceTypes": [g["resource_type"]]}
            rule["Source"] = {
                "Owner": "CUSTOM_POLICY",
                "SourceDetails": [{"EventSource": "aws.config", "MessageType": t} for t in CHANGE_TRIGGERS],
                "CustomPolicyDetails": {"PolicyRuntime": GUARD_RUNTIME, "PolicyText": guard_policy(record, g),
                                        "EnableDebugLogDelivery": False},
            }
        doc["rule"] = rule
    return f"detective/config-rules/{cid}.json", _text(doc)


def render_detection(record: dict, impl: dict, params: dict) -> tuple[str, str] | None:
    """The detection, or None when an empty optional parameter leaves nothing to detect."""
    cid = record["control_id"]
    detail = _resolve(copy.deepcopy(impl["match"]), params, cid, set(impl.get("optional_parameters", [])))
    if detail is None:
        return None
    doc = _header(record, DETECTION_SCHEMA)
    doc["detects"] = impl.get("detects", "")
    if impl.get("requires"):
        doc["requires"] = list(impl["requires"])
    doc["rule"] = {
        "Name": _name(cid),
        "Description": f"{cid}: {record['title']}"[:512],
        "State": RULE_STATE,
        "EventPattern": {"detail-type": [CLOUDTRAIL_DETAIL_TYPE], "detail": detail},
    }
    return f"detective/eventbridge/{cid}.json", _text(doc)


def _sentinel_literal(value) -> str:
    return json.dumps(value)


def _sentinel_value(path: list) -> str:
    return "rc.change.after" + "".join(f"[{s}]" if isinstance(s, int) else f".{s}" for s in path)


def sentinel_expression(check: dict) -> str:
    value = f"({_sentinel_value(check['path'])} else null)"
    if "exists" in check:
        return f"{value} is not null"
    if "equals" in check:
        return f"{value} is {_sentinel_literal(check['equals'])}"
    if "in" in check:
        return f"{value} in [{', '.join(_sentinel_literal(v) for v in check['in'])}]"
    if "not_in" in check:
        return f"{value} not in [{', '.join(_sentinel_literal(v) for v in check['not_in'])}]"
    if "not_empty" in check:
        return f"({value} is not null and length({_sentinel_value(check['path'])}) > 0)"
    return f"({_sentinel_value(check['path'])} else {{}}) contains {_sentinel_literal(check['has_tag'])}"


def render_sentinel(record: dict, impl: dict) -> tuple[str, str, str]:
    """Return (path, policy text, enforcement level)."""
    cid, plan = record["control_id"], impl["plan"]
    level = SENTINEL_LEVELS[Mode(record["mode"])]
    types = ", ".join(_sentinel_literal(t) for t in plan["resource_types"])
    lines = [
        f"# {cid}: {record['title']}",
        f"# Generated by onboard from the control record. Mode {record['mode']}: {level}.",
        'import "tfplan/v2" as tfplan',
        "",
        "resources = filter tfplan.resource_changes as _, rc {",
        '\trc.mode is "managed" and',
        f"\trc.type in [{types}] and",
        '\t(rc.change.actions contains "create" or rc.change.actions contains "update")',
        "}",
        "",
    ]
    if plan.get("forbid"):
        lines.append("main = rule { length(resources) is 0 }")
    else:
        checks = " and\n\t\t".join(sentinel_expression(c) for c in plan["checks"])
        lines += ["main = rule {", "\tall resources as _, rc {", f"\t\t{checks}", "\t}", "}"]
    return f"detective/sentinel/{cid.lower()}.sentinel", "\n".join(lines) + "\n", level


def sentinel_config(policies: dict[str, str]) -> str:
    """sentinel.hcl for the policy set: {policy file name: enforcement level}."""
    blocks = []
    for name, level in sorted(policies.items()):
        stem = name.removesuffix(".sentinel")
        blocks.append(f'policy "{stem}" {{\n  source            = "./{name}"\n'
                      f'  enforcement_level = "{level}"\n}}\n')
    return "\n".join(blocks)
