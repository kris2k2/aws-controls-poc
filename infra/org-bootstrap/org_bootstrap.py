#!/usr/bin/env python3
"""Bootstrap the test AWS organization from a fresh account (ADR-0013).

Turns a brand-new AWS account into the management account of the test
organization described by ``organization.json``: all features, the policy
types, trusted access, the OU tree, the member accounts, centralized root
access, delegated administrators, then the log archive, the organization
trail, AWS Config everywhere, the Config aggregator and Access Analyzer.

Every step reads the current state first and changes only what differs, so
``apply`` can be re-run safely and ``plan`` shows what ``apply`` would do
without changing anything.

It drives the AWS CLI v2 (preinstalled in AWS CloudShell) through argument
lists, never a shell, and uses only the Python standard library. It runs on
Python 3.9 or later, CloudShell's Python. See README.md in this directory
for the runbook, including the steps that only the console can do.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
DEFAULT_CONFIG = HERE / "organization.json"

SCHEMA = "org-bootstrap/v1"
ALLOWED_REGIONS = ("ca-central-1", "us-east-1")
ACCESS_ROLE = "OrganizationAccountAccessRole"
STACK_PREFIX = "org-bootstrap"
STACKS = {
    "log-archive": (STACK_PREFIX + "-log-archive", "log-archive.json"),
    "management": (STACK_PREFIX + "-management", "management.json"),
    "config": (STACK_PREFIX + "-config", "config-recorder.json"),
    "audit": (STACK_PREFIX + "-audit", "audit.json"),
}
CONFIG_STACK_SET = STACK_PREFIX + "-config"
POLICY_TYPES = (
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY",
    "CHATBOT_POLICY",
    "DECLARATIVE_POLICY_EC2",
)
ROOT_ACCESS_OPERATIONS = {
    "RootCredentialsManagement": "enable-organizations-root-credentials-management",
    "RootSessions": "enable-organizations-root-sessions",
}
TAG_KEYS = ("project", "env", "owner")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ERROR_CODE = re.compile(r"An error occurred \(([A-Za-z0-9_.]+)\)")

# (argv, env) -> (return code, stdout, stderr)
Runner = Callable[[List[str], Dict[str, str]], Tuple[int, str, str]]


class BootstrapError(Exception):
    """Stops the run with a message for the administrator."""


class AwsError(BootstrapError):
    def __init__(self, operation: str, code: Optional[str], message: str) -> None:
        self.operation = operation
        self.code = code
        self.message = message
        super().__init__(f"{operation} failed: {code or 'error'}: {message}")


class Pending(Exception):
    """In plan mode, a step needs something an earlier step would create."""


def subprocess_runner(argv: List[str], env: Dict[str, str]) -> Tuple[int, str, str]:
    proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=3600, check=False)
    return proc.returncode, proc.stdout, proc.stderr


class Credentials:
    """Temporary credentials for one member account, held in memory only."""

    def __init__(self, access_key_id: str, secret_access_key: str, session_token: str) -> None:
        self._env = {
            "AWS_ACCESS_KEY_ID": access_key_id,
            "AWS_SECRET_ACCESS_KEY": secret_access_key,
            "AWS_SESSION_TOKEN": session_token,
        }

    def as_env(self) -> Dict[str, str]:
        return dict(self._env)

    def __repr__(self) -> str:
        return "Credentials(<redacted>)"


def _error_message(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    for line in lines:
        if line.startswith("An error occurred"):
            return line[:500]
    return (lines[-1] if lines else "no output")[:500]


class Aws:
    """The AWS CLI v2, called with argument lists (no shell)."""

    def __init__(self, region: str, runner: Runner = subprocess_runner,
                 base_env: Optional[Dict[str, str]] = None) -> None:
        self.region = region
        self.runner = runner
        self.base_env = dict(os.environ if base_env is None else base_env)

    def _env(self, creds: Optional[Credentials]) -> Dict[str, str]:
        env = dict(self.base_env)
        env["AWS_PAGER"] = ""
        if creds is not None:
            # Explicit keys win over profiles and CloudShell's container credentials.
            env.pop("AWS_PROFILE", None)
            env.pop("AWS_DEFAULT_PROFILE", None)
            env.update(creds.as_env())
        return env

    def check_version(self) -> None:
        code, out, err = self.runner(["aws", "--version"], self._env(None))
        match = re.search(r"aws-cli/(\d+)\.", out + err)
        if code != 0 or not match:
            raise BootstrapError("the AWS CLI v2 is required (it is preinstalled in AWS CloudShell)")
        if int(match.group(1)) < 2:
            raise BootstrapError("the AWS CLI v2 is required; found " + match.group(0))

    def cli(self, args: List[str], creds: Optional[Credentials] = None,
            region: Optional[str] = None) -> str:
        argv = ["aws", *args, "--region", region or self.region, "--output", "json"]
        code, out, err = self.runner(argv, self._env(creds))
        if code != 0:
            match = ERROR_CODE.search(err)
            raise AwsError(" ".join(args[:2]), match.group(1) if match else None, _error_message(err))
        return out

    def call(self, service: str, operation: str, params: Optional[dict] = None,
             creds: Optional[Credentials] = None, region: Optional[str] = None) -> dict:
        args = [service, operation]
        if params is not None:
            args += ["--cli-input-json", json.dumps(params, sort_keys=True)]
        out = self.cli(args, creds, region)
        return json.loads(out) if out.strip() else {}


# --- configuration -----------------------------------------------------------

def load_config(path: Path) -> dict:
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BootstrapError(f"cannot read {path}: {exc}") from exc
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    errors: List[str] = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    need(cfg.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    need("@" not in json.dumps(cfg), "no email addresses in the configuration; pass them at apply time")

    tags = cfg.get("tags")
    need(isinstance(tags, dict) and sorted(tags) == sorted(TAG_KEYS)
         and all(isinstance(v, str) and re.fullmatch(r"[a-z0-9-]{1,64}", v) for v in tags.values()),
         "tags must be exactly project, env and owner, lowercase values")

    home = cfg.get("home_region")
    regions = cfg.get("config_regions")
    need(home in ALLOWED_REGIONS, f"home_region must be one of {ALLOWED_REGIONS}")
    need(isinstance(regions, list) and regions and home in regions
         and all(r in ALLOWED_REGIONS for r in regions) and len(set(regions)) == len(regions),
         f"config_regions must include home_region and only {ALLOWED_REGIONS}")
    need(cfg.get("config_recording_frequency") in ("DAILY", "CONTINUOUS"),
         "config_recording_frequency must be DAILY or CONTINUOUS")

    need(isinstance(cfg.get("policy_types"), list) and set(cfg["policy_types"]) <= set(POLICY_TYPES)
         and "SERVICE_CONTROL_POLICY" in cfg["policy_types"],
         f"policy_types must include SERVICE_CONTROL_POLICY, from {POLICY_TYPES}")
    need("TAG_POLICY" in cfg.get("policy_types", []), "policy_types must include TAG_POLICY (the cost-tag policy)")
    principals = cfg.get("trusted_access", []) + cfg.get("delegated_admin_services", [])
    need(all(isinstance(p, str) and re.fullmatch(r"[a-z0-9.-]+\.amazonaws\.com", p) for p in principals),
         "trusted_access and delegated_admin_services are service principals (*.amazonaws.com)")
    need(set(cfg.get("delegated_admin_services", [])) <= set(cfg.get("trusted_access", [])),
         "every delegated_admin_services entry needs trusted_access")
    need(set(cfg.get("root_access_features", [])) <= set(ROOT_ACCESS_OPERATIONS),
         f"root_access_features must be from {sorted(ROOT_ACCESS_OPERATIONS)}")
    need(not cfg.get("root_access_features") or "iam.amazonaws.com" in cfg.get("trusted_access", []),
         "root_access_features need trusted access for iam.amazonaws.com")

    ous = cfg.get("organizational_units")
    seen: List[str] = []
    if isinstance(ous, list):
        for path in ous:
            if not isinstance(path, str) or not all(
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,127}", part) for part in path.split("/")):
                errors.append(f"bad OU path {path!r}")
                continue
            parent = path.rpartition("/")[0]
            need(path not in seen, f"OU {path} listed twice")
            need(parent == "" or parent in seen, f"OU {path}: list its parent {parent} first")
            seen.append(path)
    else:
        errors.append("organizational_units must be a list of OU paths")

    keys: List[str] = []
    names: List[str] = []
    for account in cfg.get("accounts", []):
        key, name, ou = account.get("key"), account.get("name"), account.get("ou")
        need(isinstance(key, str) and bool(re.fullmatch(r"[a-z][a-z0-9-]{1,30}", key)), f"bad account key {key!r}")
        need(isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,49}", name)),
             f"bad account name {name!r}")
        need(ou in seen, f"account {key}: OU {ou!r} is not in organizational_units")
        need(key not in keys, f"account key {key} listed twice")
        need(name not in names, f"account name {name} listed twice")
        keys.append(key)
        names.append(name)
    need(cfg.get("log_archive_account") in keys, "log_archive_account must be an account key")
    need(cfg.get("audit_account") in keys, "audit_account must be an account key")
    need(cfg.get("log_archive_account") != cfg.get("audit_account"),
         "log_archive_account and audit_account must differ")

    retention = cfg.get("log_retention_days")
    need(isinstance(retention, int) and 30 <= retention <= 3650,
         "log_retention_days must be 30-3650 (impact replay needs 30 days, ADR-0012)")
    need(isinstance(cfg.get("trail_name"), str) and bool(re.fullmatch(r"[A-Za-z0-9._-]{3,128}", cfg["trail_name"])),
         "bad trail_name")
    budget = cfg.get("budget_monthly_limit_usd")
    need(isinstance(budget, int) and 1 <= budget <= 10000, "budget_monthly_limit_usd must be 1-10000")

    if errors:
        raise BootstrapError("invalid configuration:\n  " + "\n  ".join(errors))


def account_email(template: str, key: str) -> str:
    email = template.replace("{key}", key)
    if template.count("{key}") != 1 or not EMAIL.fullmatch(email):
        raise BootstrapError("--email-template must be an address with one {key}, e.g. aws+{key}@example.com")
    return email


def log_bucket_name(account_id: str, region: str) -> str:
    return f"{STACK_PREFIX}-logs-{account_id}-{region}"


# --- run state ------------------------------------------------------------------

class Context:
    def __init__(self, cfg: dict, aws: Aws, apply: bool, *,
                 email_template: Optional[str] = None, budget_email: Optional[str] = None,
                 out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                 poll_interval: float = 10.0, max_polls: int = 180) -> None:
        self.cfg = cfg
        self.aws = aws
        self.apply = apply
        self.email_template = email_template
        self.budget_email = budget_email
        self.out = out
        self.sleep = sleep
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.caller_account = ""
        self.caller_arn = ""
        self.org: dict = {}
        self.root_id = ""
        self.ou_ids: Dict[str, str] = {}
        self.account_ids: Dict[str, str] = {}
        self.member_ids: List[str] = []
        self.changes = 0
        self._creds: Dict[str, Credentials] = {}

    @property
    def caller_is_root(self) -> bool:
        return self.caller_arn.endswith(":root")

    @property
    def home(self) -> str:
        return self.cfg["home_region"]

    @property
    def tags(self) -> Dict[str, str]:
        return dict(self.cfg["tags"])

    def tag_list(self) -> List[dict]:
        return [{"Key": k, "Value": v} for k, v in sorted(self.tags.items())]

    def ok(self, step: str, text: str) -> None:
        self.out(f"[{step}] ok: {text}")

    def changed(self, step: str, text: str) -> None:
        self.changes += 1
        self.out(f"[{step}] {'done' if self.apply else 'would'}: {text}")

    def credentials_for(self, account_id: str) -> Credentials:
        if account_id not in self._creds:
            resp = self.aws.call("sts", "assume-role", {
                "RoleArn": f"arn:aws:iam::{account_id}:role/{ACCESS_ROLE}",
                "RoleSessionName": "org-bootstrap",
                "DurationSeconds": 3600,
            })["Credentials"]
            self._creds[account_id] = Credentials(
                resp["AccessKeyId"], resp["SecretAccessKey"], resp["SessionToken"])
        return self._creds[account_id]

    def poll(self, what: str, check: Callable[[], Optional[dict]]) -> dict:
        for _ in range(self.max_polls):
            result = check()
            if result is not None:
                return result
            self.sleep(self.poll_interval)
        raise BootstrapError(f"timed out waiting for {what}; re-run apply to resume")


# --- steps ---------------------------------------------------------------------

def identify(ctx: Context) -> None:
    who = ctx.aws.call("sts", "get-caller-identity")
    ctx.caller_account = who["Account"]
    ctx.caller_arn = who["Arn"]


def step_organization(ctx: Context) -> None:
    step = "organization"
    try:
        org = ctx.aws.call("organizations", "describe-organization")["Organization"]
        ctx.ok(step, f"organization {org['Id']}")
    except AwsError as exc:
        if exc.code != "AWSOrganizationsNotInUseException":
            raise
        ctx.changed(step, f"create the organization (all features) with {ctx.caller_account} as management account")
        if not ctx.apply:
            raise Pending("the organization") from None
        org = ctx.aws.call("organizations", "create-organization", {"FeatureSet": "ALL"})["Organization"]
        ctx.out(f"[{step}] organization {org['Id']} created")
    if org.get("MasterAccountId") != ctx.caller_account:
        raise BootstrapError(
            f"account {ctx.caller_account} is a member of organization {org['Id']}, not its management "
            "account; run from the management account")
    if org.get("FeatureSet") != "ALL":
        raise BootstrapError(
            "the organization has consolidated billing only; enable all features in the AWS Organizations "
            "console first (every member account must accept)")
    ctx.org = org


def step_policy_types(ctx: Context) -> None:
    step = "policy-types"
    roots = ctx.aws.call("organizations", "list-roots")["Roots"]
    if len(roots) != 1:
        raise BootstrapError(f"expected one organization root, found {len(roots)}")
    ctx.root_id = roots[0]["Id"]
    status = {p["Type"]: p["Status"] for p in roots[0].get("PolicyTypes", [])}
    for policy_type in ctx.cfg["policy_types"]:
        if status.get(policy_type) in ("ENABLED", "PENDING_ENABLE"):
            ctx.ok(step, f"{policy_type} {status[policy_type].lower()}")
            continue
        ctx.changed(step, f"enable {policy_type} on {ctx.root_id}")
        if ctx.apply:
            ctx.aws.call("organizations", "enable-policy-type",
                         {"RootId": ctx.root_id, "PolicyType": policy_type})


def step_trusted_access(ctx: Context) -> None:
    step = "trusted-access"
    enabled = {s["ServicePrincipal"] for s in ctx.aws.call(
        "organizations", "list-aws-service-access-for-organization").get("EnabledServicePrincipals", [])}
    for principal in ctx.cfg["trusted_access"]:
        if principal in enabled:
            ctx.ok(step, principal)
            continue
        ctx.changed(step, f"enable trusted access for {principal}")
        if ctx.apply:
            ctx.aws.call("organizations", "enable-aws-service-access", {"ServicePrincipal": principal})
    # Service-managed StackSets (the Config recorder in every member account).
    if ctx.aws.call("cloudformation", "describe-organizations-access").get("Status") == "ENABLED":
        ctx.ok(step, "CloudFormation StackSets")
    else:
        ctx.changed(step, "activate trusted access for CloudFormation StackSets")
        if ctx.apply:
            ctx.aws.call("cloudformation", "activate-organizations-access")


def step_organizational_units(ctx: Context) -> None:
    step = "organizational-units"
    ctx.ou_ids = {"": ctx.root_id}
    children: Dict[str, Dict[str, str]] = {}
    pending = False
    for path in ctx.cfg["organizational_units"]:
        parent, _, name = path.rpartition("/")
        parent_id = ctx.ou_ids.get(parent)
        if parent_id is None:  # plan mode: the parent would be created first
            ctx.changed(step, f"create OU {path}")
            pending = True
            continue
        if parent_id not in children:
            children[parent_id] = {ou["Name"]: ou["Id"] for ou in ctx.aws.call(
                "organizations", "list-organizational-units-for-parent",
                {"ParentId": parent_id})["OrganizationalUnits"]}
        if name in children[parent_id]:
            ctx.ou_ids[path] = children[parent_id][name]
            ctx.ok(step, f"OU {path}")
            continue
        ctx.changed(step, f"create OU {path}")
        if not ctx.apply:
            pending = True
            continue
        ou = ctx.aws.call("organizations", "create-organizational-unit",
                          {"ParentId": parent_id, "Name": name, "Tags": ctx.tag_list()})["OrganizationalUnit"]
        ctx.ou_ids[path] = children[parent_id][name] = ou["Id"]
    if pending:
        raise Pending("the organizational units")


def _account_state(account: dict) -> str:
    return account.get("State") or account.get("Status") or ""


def _create_account(ctx: Context, account: dict) -> str:
    if not ctx.email_template:
        raise BootstrapError(f"--email-template is required to create account {account['name']}")
    email = account_email(ctx.email_template, account["key"])
    status = ctx.aws.call("organizations", "create-account", {
        "Email": email,
        "AccountName": account["name"],
        "RoleName": ACCESS_ROLE,
        "IamUserAccessToBilling": "DENY",
        "Tags": ctx.tag_list(),
    })["CreateAccountStatus"]
    request_id = status["Id"]

    def check() -> Optional[dict]:
        current = ctx.aws.call("organizations", "describe-create-account-status",
                               {"CreateAccountRequestId": request_id})["CreateAccountStatus"]
        if current["State"] == "FAILED":
            raise BootstrapError(f"creating account {account['name']} failed: "
                                 f"{current.get('FailureReason', 'unknown reason')}")
        return current if current["State"] == "SUCCEEDED" else None

    return ctx.poll(f"account {account['name']}", check)["AccountId"]


def step_accounts(ctx: Context) -> None:
    step = "accounts"
    management = ctx.org["MasterAccountId"]
    existing = ctx.aws.call("organizations", "list-accounts")["Accounts"]
    ctx.member_ids = sorted(a["Id"] for a in existing
                            if a["Id"] != management and _account_state(a) == "ACTIVE")
    by_name: Dict[str, List[dict]] = {}
    for account in existing:
        by_name.setdefault(account["Name"], []).append(account)
    pending = False
    for account in ctx.cfg["accounts"]:
        matches = by_name.get(account["name"], [])
        if len(matches) > 1:
            raise BootstrapError(f"{len(matches)} accounts are named {account['name']}; rename or close the extras")
        if matches:
            if _account_state(matches[0]) != "ACTIVE":
                raise BootstrapError(f"account {account['name']} ({matches[0]['Id']}) is "
                                     f"{_account_state(matches[0]).lower()}; rename it in the configuration")
            account_id = matches[0]["Id"]
            ctx.ok(step, f"account {account['name']} {account_id}")
        else:
            ctx.changed(step, f"create account {account['name']} in {account['ou']}")
            if not ctx.apply:
                pending = True
                continue
            account_id = _create_account(ctx, account)
            ctx.member_ids.append(account_id)
            ctx.out(f"[{step}] account {account['name']} is {account_id}")
        ctx.account_ids[account["key"]] = account_id

        target = ctx.ou_ids[account["ou"]]
        current = ctx.aws.call("organizations", "list-parents", {"ChildId": account_id})["Parents"][0]["Id"]
        if current == target:
            continue
        ctx.changed(step, f"move account {account['name']} to {account['ou']}")
        if ctx.apply:
            ctx.aws.call("organizations", "move-account", {
                "AccountId": account_id, "SourceParentId": current, "DestinationParentId": target})
    if pending:
        raise Pending("the accounts")


def step_root_access(ctx: Context) -> None:
    step = "root-access"
    enabled = ctx.aws.call("iam", "list-organizations-features").get("EnabledFeatures", [])
    for feature in ctx.cfg["root_access_features"]:
        if feature in enabled:
            ctx.ok(step, feature)
            continue
        ctx.changed(step, f"enable centralized root access: {feature}")
        if ctx.apply:
            ctx.aws.call("iam", ROOT_ACCESS_OPERATIONS[feature])


def step_delegated_admins(ctx: Context) -> None:
    step = "delegated-admins"
    audit = ctx.account_ids[ctx.cfg["audit_account"]]
    for principal in ctx.cfg["delegated_admin_services"]:
        admins = ctx.aws.call("organizations", "list-delegated-administrators",
                              {"ServicePrincipal": principal}).get("DelegatedAdministrators", [])
        if audit in {a["Id"] for a in admins}:
            ctx.ok(step, f"{principal}: {audit}")
            continue
        ctx.changed(step, f"register {audit} as delegated administrator for {principal}")
        if ctx.apply:
            ctx.aws.call("organizations", "register-delegated-administrator",
                         {"AccountId": audit, "ServicePrincipal": principal})


def stack_status(ctx: Context, name: str, creds: Optional[Credentials] = None,
                 region: Optional[str] = None) -> Optional[str]:
    try:
        stacks = ctx.aws.call("cloudformation", "describe-stacks", {"StackName": name}, creds, region)["Stacks"]
    except AwsError as exc:
        if exc.code == "ValidationError" and "does not exist" in exc.message:
            return None
        raise
    return stacks[0]["StackStatus"]


def deploy_stack(ctx: Context, step: str, key: str, params: Dict[str, str], where: str,
                 creds: Optional[Credentials] = None, region: Optional[str] = None) -> None:
    name, template = STACKS[key]
    status = stack_status(ctx, name, creds, region)
    if status == "ROLLBACK_COMPLETE":
        raise BootstrapError(f"stack {name} {where} failed to create (ROLLBACK_COMPLETE); read its events, "
                             "fix the cause, delete the stack and re-run apply")
    if status is None:
        ctx.changed(step, f"create stack {name} {where}")
    elif not ctx.apply:
        # Only a change set can tell; apply deploys and reports whether anything changed.
        ctx.out(f"[{step}] check: stack {name} {where} ({status}); apply updates it if the template "
                "or parameters changed")
    if not ctx.apply:
        return
    args = ["cloudformation", "deploy", "--stack-name", name,
            "--template-file", str(TEMPLATES / template),
            "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset",
            "--parameter-overrides", *[f"{k}={v}" for k, v in sorted(params.items())],
            "--tags", *[f"{k}={v}" for k, v in sorted(ctx.tags.items())]]
    output = ctx.aws.cli(args, creds, region)
    if status is not None:
        if "No changes to deploy" in output:
            ctx.ok(step, f"stack {name} {where} up to date")
        else:
            ctx.changed(step, f"update stack {name} {where}")
    ctx.aws.call("cloudformation", "update-termination-protection",
                 {"StackName": name, "EnableTerminationProtection": True}, creds, region)


def _log_bucket(ctx: Context) -> str:
    return log_bucket_name(ctx.account_ids[ctx.cfg["log_archive_account"]], ctx.home)


def step_log_archive(ctx: Context) -> None:
    account = ctx.account_ids[ctx.cfg["log_archive_account"]]
    deploy_stack(ctx, "log-archive", "log-archive", {
        "BucketName": _log_bucket(ctx),
        "OrganizationId": ctx.org["Id"],
        "ManagementAccountId": ctx.org["MasterAccountId"],
        "TrailName": ctx.cfg["trail_name"],
        "TrailRegion": ctx.home,
        "RetentionDays": str(ctx.cfg["log_retention_days"]),
    }, f"in account {account}", ctx.credentials_for(account))


def step_management(ctx: Context) -> None:
    step = "management"
    params = {
        "TrailName": ctx.cfg["trail_name"],
        "LogBucketName": _log_bucket(ctx),
        "RootId": ctx.root_id,
        "BudgetLimitUsd": str(ctx.cfg["budget_monthly_limit_usd"]),
    }
    if ctx.budget_email:
        params["BudgetEmail"] = ctx.budget_email
    elif ctx.apply and stack_status(ctx, STACKS["management"][0]) is None:
        raise BootstrapError("--budget-email is required the first time (the budget alerts' mailbox)")
    deploy_stack(ctx, step, "management", params, "in the management account")


def step_config(ctx: Context) -> None:
    step = "config"
    regions = ctx.cfg["config_regions"]
    params = {
        "LogBucketName": _log_bucket(ctx),
        "HomeRegion": ctx.home,
        "RecordingFrequency": ctx.cfg["config_recording_frequency"],
    }
    for region in regions:
        deploy_stack(ctx, step, "config", params, f"in the management account, {region}", region=region)

    body = (TEMPLATES / STACKS["config"][1]).read_text(encoding="utf-8")
    parameters = [{"ParameterKey": k, "ParameterValue": v} for k, v in sorted(params.items())]
    preferences = {"RegionConcurrencyType": "PARALLEL", "MaxConcurrentPercentage": 100,
                   "FailureTolerancePercentage": 0}
    try:
        stack_set = ctx.aws.call("cloudformation", "describe-stack-set",
                                 {"StackSetName": CONFIG_STACK_SET})["StackSet"]
    except AwsError as exc:
        if exc.code != "StackSetNotFoundException":
            raise
        stack_set = None

    if stack_set is None:
        ctx.changed(step, f"create StackSet {CONFIG_STACK_SET} (service-managed, auto-deploys to new accounts)")
        if not ctx.apply:
            ctx.changed(step, f"deploy {CONFIG_STACK_SET} to every member account in {', '.join(regions)}")
            return
        ctx.aws.call("cloudformation", "create-stack-set", {
            "StackSetName": CONFIG_STACK_SET,
            "Description": "AWS Config recorder in every member account (ADR-0013)",
            "TemplateBody": body,
            "Parameters": parameters,
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "PermissionModel": "SERVICE_MANAGED",
            "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
            "ManagedExecution": {"Active": True},
            "Tags": ctx.tag_list(),
        })
    else:
        current = {p["ParameterKey"]: p.get("ParameterValue") for p in stack_set.get("Parameters", [])}
        if json.loads(stack_set.get("TemplateBody", "{}")) == json.loads(body) and current == params:
            ctx.ok(step, f"StackSet {CONFIG_STACK_SET}")
        else:
            ctx.changed(step, f"update StackSet {CONFIG_STACK_SET} on every member account")
            if ctx.apply:
                op = ctx.aws.call("cloudformation", "update-stack-set", {
                    "StackSetName": CONFIG_STACK_SET,
                    "TemplateBody": body,
                    "Parameters": parameters,
                    "Capabilities": ["CAPABILITY_NAMED_IAM"],
                    "OperationPreferences": preferences,
                })["OperationId"]
                _wait_stack_set_operation(ctx, op)

    instances = ctx.aws.call("cloudformation", "list-stack-instances",
                             {"StackSetName": CONFIG_STACK_SET}).get("Summaries", [])
    have = {(i["Account"], i["Region"]) for i in instances}
    missing = {(a, r) for a in ctx.member_ids for r in regions} - have
    if not have and missing:
        ctx.changed(step, f"deploy {CONFIG_STACK_SET} to every member account in {', '.join(regions)}")
        if ctx.apply:
            op = ctx.aws.call("cloudformation", "create-stack-instances", {
                "StackSetName": CONFIG_STACK_SET,
                "DeploymentTargets": {"OrganizationalUnitIds": [ctx.root_id]},
                "Regions": regions,
                "OperationPreferences": preferences,
            })["OperationId"]
            _wait_stack_set_operation(ctx, op)
    elif missing:
        ctx.out(f"[{step}] note: {len(missing)} account/region pairs have no {CONFIG_STACK_SET} instance yet; "
                "auto-deployment adds them, check the StackSet if this persists")
    else:
        ctx.ok(step, f"{CONFIG_STACK_SET} on {len(have)} account/region pairs")
    failed = [i for i in instances if i.get("Status") == "INOPERABLE"
              or i.get("StackInstanceStatus", {}).get("DetailedStatus") == "FAILED"]
    if failed:
        raise BootstrapError(f"{len(failed)} {CONFIG_STACK_SET} instances failed; see the StackSet's "
                             "instances in the CloudFormation console")


def _wait_stack_set_operation(ctx: Context, operation_id: str) -> None:
    def check() -> Optional[dict]:
        op = ctx.aws.call("cloudformation", "describe-stack-set-operation",
                          {"StackSetName": CONFIG_STACK_SET, "OperationId": operation_id})["StackSetOperation"]
        if op["Status"] in ("FAILED", "STOPPED"):
            raise BootstrapError(f"StackSet {CONFIG_STACK_SET} operation {operation_id} {op['Status'].lower()}; "
                                 "see the StackSet's operations in the CloudFormation console")
        return op if op["Status"] == "SUCCEEDED" else None

    ctx.poll(f"StackSet {CONFIG_STACK_SET} operation {operation_id}", check)


def step_audit(ctx: Context) -> None:
    account = ctx.account_ids[ctx.cfg["audit_account"]]
    deploy_stack(ctx, "audit", "audit", {"AggregatorRegions": ",".join(ctx.cfg["config_regions"])},
                 f"in account {account}", ctx.credentials_for(account))


STEPS: List[Tuple[str, Callable[[Context], None]]] = [
    ("organization", step_organization),
    ("policy-types", step_policy_types),
    ("trusted-access", step_trusted_access),
    ("organizational-units", step_organizational_units),
    ("accounts", step_accounts),
    ("root-access", step_root_access),
    ("delegated-admins", step_delegated_admins),
    ("log-archive", step_log_archive),
    ("management", step_management),
    ("config", step_config),
    ("audit", step_audit),
]

ROOT_NEXT_STEPS = """\
Signed in as the root user: stopping after the organization step.
Next (README.md, step 3): enable IAM Identity Center for the organization in
the console, give yourself the AdministratorAccess permission set on this
account, sign out of the root user, sign in through the access portal and run
`plan`, then `apply`, again."""


def run(ctx: Context) -> None:
    for name, step in STEPS:
        try:
            step(ctx)
        except Pending as pending:
            if ctx.apply:
                raise BootstrapError(f"{name}: {pending} is still missing") from None
            ctx.out(f"[{name}] pending: the remaining steps need {pending}; apply creates it, then plan again")
            return
        # The root user does the one thing that needs it, and can't assume
        # roles into member accounts anyway.
        if name == "organization" and ctx.caller_is_root:
            ctx.out(ROOT_NEXT_STEPS)
            return


def main(argv: Optional[List[str]] = None, *, runner: Runner = subprocess_runner,
         input_fn: Callable[[str], str] = input, out: Callable[[str], None] = print,
         sleep: Callable[[float], None] = time.sleep) -> int:
    parser = argparse.ArgumentParser(
        prog="org_bootstrap.py", description="Bootstrap the test AWS organization (ADR-0013).")
    parser.add_argument("command", choices=("plan", "apply"),
                        help="plan: read-only, show what apply would change; apply: make the changes")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="desired state (organization.json)")
    parser.add_argument("--email-template",
                        help="root email of new accounts, with {key} for the account key, e.g. aws+{key}@example.com")
    parser.add_argument("--budget-email", help="mailbox for budget alerts (required on the first apply)")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation before apply")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
        if args.email_template:
            account_email(args.email_template, "check")
        if args.budget_email and not EMAIL.fullmatch(args.budget_email):
            raise BootstrapError("--budget-email is not an email address")
        aws = Aws(cfg["home_region"], runner)
        aws.check_version()
        ctx = Context(cfg, aws, args.command == "apply", email_template=args.email_template,
                      budget_email=args.budget_email, out=out, sleep=sleep)
        identify(ctx)
        out(f"Caller: {ctx.caller_arn}")
        if ctx.apply and not args.yes:
            answer = input_fn(f"Apply the test organization from account {ctx.caller_account}? "
                              "Type the account ID to continue: ")
            if answer.strip() != ctx.caller_account:
                out("Not confirmed; nothing changed.")
                return 1
        run(ctx)
    except BootstrapError as exc:
        out(f"error: {exc}")
        return 1
    except (KeyboardInterrupt, EOFError):
        out("interrupted; re-run apply to resume")
        return 1
    noun = "change" if ctx.changes == 1 else "changes"
    out(f"{ctx.changes} {noun} {'made' if ctx.apply else 'planned'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
