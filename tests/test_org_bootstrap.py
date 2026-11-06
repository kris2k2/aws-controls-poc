"""Tests for the test-organization bootstrap (ADR-0013), offline.

A fake AWS CLI keeps an in-memory organization, so the bootstrap runs end to
end, from a fresh account to a converged organization, without the network.
Account IDs and the organization ID are synthetic.
"""

from __future__ import annotations

import ast
import configparser
import copy
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_DIR = ROOT / "infra" / "org-bootstrap"
SCRIPT = BOOTSTRAP_DIR / "org_bootstrap.py"
CONFIG = BOOTSTRAP_DIR / "organization.json"

_spec = importlib.util.spec_from_file_location("org_bootstrap", SCRIPT)
ob = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ob)

MANAGEMENT = "111122223333"
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1111222233334444"
IDENTITY_STORE = "d-1234567890"
ADMIN_ARN = f"arn:aws:sts::{MANAGEMENT}:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/analyst-a"
ROOT_ARN = f"arn:aws:iam::{MANAGEMENT}:root"
EMAILS = "aws+{key}@example.com"
BUDGET_EMAIL = "aws-budget@example.com"
WRITE_OPS = re.compile(r"^(create|enable|activate|register|move|update|deploy)")
ORG_WRITE_OPS = re.compile(r"^(create|enable|activate|register|move)")


class FakeError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class FakeCloud:
    """The subset of the AWS CLI the bootstrap uses, over one in-memory organization."""

    def __init__(self, *, organization: bool = True, caller_arn: str = ADMIN_ARN,
                 master: str = MANAGEMENT, feature_set: str = "ALL", identity_center: bool = True) -> None:
        self.caller_arn = caller_arn
        self.org = ({"Id": "o-exampleorgid", "MasterAccountId": master, "FeatureSet": feature_set}
                    if organization else None)
        self.root_id = "r-ex12"
        self.policy_types: set = set()
        self.services: set = set()
        self.stack_sets_access = False
        self.ous: dict = {}        # id -> {"Name", "Parent"}
        self.accounts: dict = {}   # id -> {"Name", "Email", "State", "Parent"}
        self.delegated: dict = {}  # principal -> set of account ids
        self.root_features: set = set()
        self.stacks: dict = {}     # (account, region, name) -> stack
        self.stack_set = None
        self.instances: set = set()
        self.operations: dict = {}
        self.pending_accounts: dict = {}
        self.account_failure = None
        self.operation_failure = None
        self.instance = ({"InstanceArn": INSTANCE_ARN, "IdentityStoreId": IDENTITY_STORE,
                          "OwnerAccountId": master, "Status": "ACTIVE"} if identity_center else None)
        self.permission_sets: dict = {}  # arn -> {"Name", "Description", "SessionDuration", "policies", "inline"}
        self.provisioned: list = []
        self.groups: dict = {}       # id -> {"DisplayName", "Description"}
        self.users: dict = {}        # id -> user name
        self.memberships: set = set()
        self.assignments: set = set()  # (account, permission set arn, principal type, principal id)
        self.sso_requests: dict = {}
        self.calls: list = []      # (service, operation, params, account, region)
        self.argvs: list = []
        self._n = 0

    # --- plumbing ---------------------------------------------------------------
    def _next(self) -> int:
        self._n += 1
        return self._n

    def __call__(self, argv, env):
        self.argvs.append(list(argv))
        assert argv[0] == "aws"
        if argv[1] == "--version":
            return 0, "aws-cli/2.31.0 Python/3.13.7 Linux/6 exe/x86_64\n", ""
        service, operation, rest = argv[1], argv[2], argv[3:]
        flags = _parse_flags(rest)
        region = flags["--region"][0]
        params = json.loads(flags["--cli-input-json"][0]) if "--cli-input-json" in flags else {}
        account = self._caller_account(env)
        self.calls.append((service, operation, params, account, region))
        try:
            handler = getattr(self, f"{service}__{operation}".replace("-", "_"))
            result = handler(params=params, flags=flags, account=account, region=region, env=env)
        except FakeError as exc:
            return 254, "", (f"\nAn error occurred ({exc.code}) when calling the "
                             f"{operation} operation: {exc.message}\n")
        if result is None or isinstance(result, str):
            return 0, result or "", ""
        return 0, json.dumps(result), ""

    def _caller_account(self, env) -> str:
        key = env.get("AWS_ACCESS_KEY_ID", "")
        if key.startswith("ASIAFAKE"):
            assert env["AWS_SECRET_ACCESS_KEY"] == f"fake-secret-{key[8:]}"
            return key[8:]
        return MANAGEMENT

    def writes(self, pattern=WRITE_OPS):
        return [(s, o) for s, o, *_ in self.calls if pattern.match(o)]

    def ou_path(self, ou_id: str) -> str:
        parts = []
        while ou_id != self.root_id:
            parts.append(self.ous[ou_id]["Name"])
            ou_id = self.ous[ou_id]["Parent"]
        return "/".join(reversed(parts))

    def account_by_name(self, name: str) -> str:
        return next(i for i, a in self.accounts.items() if a["Name"] == name)

    def _need_org(self):
        if self.org is None:
            raise FakeError("AWSOrganizationsNotInUseException", "Your account is not a member of an organization.")

    def add_account(self, name: str, parent=None, state: str = "ACTIVE") -> str:
        account_id = f"2000000000{self._next():02d}"
        self.accounts[account_id] = {"Name": name, "Email": f"{account_id}@example.com",
                                     "State": state, "Parent": parent or self.root_id}
        return account_id

    # --- sts ------------------------------------------------------------------------
    def sts__get_caller_identity(self, account, **_):
        arn = self.caller_arn if account == MANAGEMENT else \
            f"arn:aws:sts::{account}:assumed-role/OrganizationAccountAccessRole/org-bootstrap"
        return {"Account": account, "Arn": arn, "UserId": "AIDAEXAMPLE"}

    def sts__assume_role(self, params, **_):
        if self.caller_arn.endswith(":root"):
            raise FakeError("AccessDenied", "Roles may not be assumed by root accounts.")
        target = params["RoleArn"].split(":")[4]
        assert params["RoleArn"].endswith(":role/OrganizationAccountAccessRole")
        assert target in self.accounts
        return {"Credentials": {"AccessKeyId": f"ASIAFAKE{target}", "SecretAccessKey": f"fake-secret-{target}",
                                "SessionToken": f"fake-token-{target}"}}

    # --- organizations --------------------------------------------------------------
    def organizations__describe_organization(self, **_):
        self._need_org()
        return {"Organization": dict(self.org)}

    def organizations__create_organization(self, params, **_):
        if self.org is not None:
            raise FakeError("AlreadyInOrganizationException", "already in an organization")
        assert params == {"FeatureSet": "ALL"}
        self.org = {"Id": "o-exampleorgid", "MasterAccountId": MANAGEMENT, "FeatureSet": "ALL"}
        return {"Organization": dict(self.org)}

    def organizations__list_roots(self, **_):
        self._need_org()
        return {"Roots": [{"Id": self.root_id, "Name": "Root", "PolicyTypes": [
            {"Type": t, "Status": "ENABLED"} for t in sorted(self.policy_types)]}]}

    def organizations__enable_policy_type(self, params, **_):
        assert params["RootId"] == self.root_id
        if params["PolicyType"] in self.policy_types:
            raise FakeError("PolicyTypeAlreadyEnabledException", "already enabled")
        self.policy_types.add(params["PolicyType"])
        return {"Root": {}}

    def organizations__list_aws_service_access_for_organization(self, **_):
        return {"EnabledServicePrincipals": [{"ServicePrincipal": s} for s in sorted(self.services)]}

    def organizations__enable_aws_service_access(self, params, **_):
        self.services.add(params["ServicePrincipal"])

    def organizations__list_organizational_units_for_parent(self, params, **_):
        return {"OrganizationalUnits": [{"Id": i, "Name": ou["Name"]} for i, ou in self.ous.items()
                                        if ou["Parent"] == params["ParentId"]]}

    def organizations__create_organizational_unit(self, params, **_):
        parent = params["ParentId"]
        assert parent == self.root_id or parent in self.ous
        if any(ou["Parent"] == parent and ou["Name"] == params["Name"] for ou in self.ous.values()):
            raise FakeError("DuplicateOrganizationalUnitException", "duplicate")
        assert {t["Key"] for t in params["Tags"]} == {"project", "env", "owner"}
        ou_id = f"ou-ex12-{self._next():08d}"
        self.ous[ou_id] = {"Name": params["Name"], "Parent": parent}
        return {"OrganizationalUnit": {"Id": ou_id, "Name": params["Name"]}}

    def organizations__list_accounts(self, **_):
        accounts = [{"Id": MANAGEMENT, "Name": "management", "Email": "mgmt@example.com", "State": "ACTIVE"}]
        accounts += [{"Id": i, "Name": a["Name"], "Email": a["Email"], "State": a["State"]}
                     for i, a in self.accounts.items()]
        return {"Accounts": accounts}

    def organizations__create_account(self, params, **_):
        assert params["RoleName"] == "OrganizationAccountAccessRole"
        assert params["IamUserAccessToBilling"] == "DENY"
        assert {t["Key"] for t in params["Tags"]} == {"project", "env", "owner"}
        request = f"car-{self._next():032d}"
        self.pending_accounts[request] = {"params": params, "polls": 0}
        return {"CreateAccountStatus": {"Id": request, "State": "IN_PROGRESS"}}

    def organizations__describe_create_account_status(self, params, **_):
        pending = self.pending_accounts[params["CreateAccountRequestId"]]
        pending["polls"] += 1
        if pending["polls"] == 1:
            return {"CreateAccountStatus": {"Id": params["CreateAccountRequestId"], "State": "IN_PROGRESS"}}
        if self.account_failure:
            return {"CreateAccountStatus": {"State": "FAILED", "FailureReason": self.account_failure}}
        if "AccountId" not in pending:
            pending["AccountId"] = self.add_account(pending["params"]["AccountName"])
            self.accounts[pending["AccountId"]]["Email"] = pending["params"]["Email"]
        return {"CreateAccountStatus": {"State": "SUCCEEDED", "AccountId": pending["AccountId"]}}

    def organizations__list_parents(self, params, **_):
        return {"Parents": [{"Id": self.accounts[params["ChildId"]]["Parent"]}]}

    def organizations__move_account(self, params, **_):
        account = self.accounts[params["AccountId"]]
        if account["Parent"] != params["SourceParentId"]:
            raise FakeError("SourceParentNotFoundException", "wrong source parent")
        account["Parent"] = params["DestinationParentId"]

    def organizations__list_delegated_administrators(self, params, **_):
        return {"DelegatedAdministrators": [{"Id": i} for i in sorted(self.delegated.get(params["ServicePrincipal"], ()))]}

    def organizations__register_delegated_administrator(self, params, **_):
        if params["ServicePrincipal"] not in self.services:
            raise FakeError("AccessDeniedException", "trusted access is not enabled")
        self.delegated.setdefault(params["ServicePrincipal"], set()).add(params["AccountId"])

    # --- iam ----------------------------------------------------------------------------
    def iam__list_organizations_features(self, **_):
        if "iam.amazonaws.com" not in self.services:
            raise FakeError("ServiceAccessNotEnabledException", "trusted access for IAM is not enabled")
        return {"OrganizationId": self.org["Id"], "EnabledFeatures": sorted(self.root_features)}

    def iam__enable_organizations_root_credentials_management(self, **_):
        self.root_features.add("RootCredentialsManagement")

    def iam__enable_organizations_root_sessions(self, **_):
        self.root_features.add("RootSessions")

    # --- cloudformation -------------------------------------------------------------
    def cloudformation__describe_organizations_access(self, **_):
        return {"Status": "ENABLED" if self.stack_sets_access else "DISABLED"}

    def cloudformation__activate_organizations_access(self, **_):
        self.stack_sets_access = True

    def cloudformation__describe_stacks(self, params, account, region, **_):
        stack = self.stacks.get((account, region, params["StackName"]))
        if stack is None:
            raise FakeError("ValidationError", f"Stack with id {params['StackName']} does not exist")
        return {"Stacks": [{"StackName": params["StackName"], "StackStatus": stack["status"]}]}

    def cloudformation__deploy(self, flags, account, region, **_):
        name = flags["--stack-name"][0]
        template = json.loads(Path(flags["--template-file"][0]).read_text())
        assert flags["--capabilities"] == ["CAPABILITY_NAMED_IAM"]
        assert "--no-fail-on-empty-changeset" in flags
        params = dict(v.split("=", 1) for v in flags["--parameter-overrides"])
        unknown = set(params) - set(template["Parameters"])
        assert not unknown, f"{name}: parameters not in the template: {unknown}"
        key = (account, region, name)
        previous = self.stacks.get(key, {}).get("params", {})
        merged = {**previous, **params}
        missing = {p for p, d in template["Parameters"].items() if "Default" not in d} - set(merged)
        assert not missing, f"{name}: required parameters missing: {missing}"
        tags = dict(v.split("=", 1) for v in flags["--tags"])
        if key in self.stacks and (self.stacks[key]["params"], self.stacks[key]["template"]) == (merged, template):
            return f"\nNo changes to deploy. Stack {name} is up to date\n"
        self.stacks[key] = {"status": "UPDATE_COMPLETE" if key in self.stacks else "CREATE_COMPLETE",
                            "params": merged, "tags": tags, "template": template,
                            "protected": self.stacks.get(key, {}).get("protected", False)}
        return f"\nSuccessfully created/updated stack - {name}\n"

    def cloudformation__update_termination_protection(self, params, account, region, **_):
        self.stacks[(account, region, params["StackName"])]["protected"] = params["EnableTerminationProtection"]

    def cloudformation__describe_stack_set(self, params, **_):
        if self.stack_set is None:
            raise FakeError("StackSetNotFoundException", f"StackSet {params['StackSetName']} not found")
        return {"StackSet": copy.deepcopy(self.stack_set)}

    def cloudformation__create_stack_set(self, params, **_):
        if not self.stack_sets_access:
            raise FakeError("ValidationError", "trusted access for StackSets is not activated")
        assert params["PermissionModel"] == "SERVICE_MANAGED"
        assert params["AutoDeployment"]["Enabled"] is True
        self.stack_set = {"StackSetName": params["StackSetName"], "TemplateBody": params["TemplateBody"],
                          "Parameters": params["Parameters"], "Status": "ACTIVE", "Tags": params["Tags"]}
        return {"StackSetId": params["StackSetName"] + ":1"}

    def _operation(self) -> dict:
        op = f"op-{self._next()}"
        self.operations[op] = 0
        return {"OperationId": op}

    def cloudformation__update_stack_set(self, params, **_):
        self.stack_set.update(TemplateBody=params["TemplateBody"], Parameters=params["Parameters"])
        return self._operation()

    def cloudformation__list_stack_instances(self, **_):
        return {"Summaries": [{"Account": a, "Region": r, "Status": "CURRENT",
                               "StackInstanceStatus": {"DetailedStatus": "SUCCEEDED"}}
                              for a, r in sorted(self.instances)]}

    def cloudformation__create_stack_instances(self, params, **_):
        assert params["DeploymentTargets"] == {"OrganizationalUnitIds": [self.root_id]}
        for account_id, account in self.accounts.items():
            if account["State"] == "ACTIVE":
                for region in params["Regions"]:
                    self.instances.add((account_id, region))
        return self._operation()

    def cloudformation__describe_stack_set_operation(self, params, **_):
        self.operations[params["OperationId"]] += 1
        if self.operation_failure:
            return {"StackSetOperation": {"Status": self.operation_failure}}
        done = self.operations[params["OperationId"]] > 1
        return {"StackSetOperation": {"Status": "SUCCEEDED" if done else "RUNNING"}}


    # --- sso-admin and identitystore ------------------------------------------
    def _ic(self, params, region):
        assert region == "ca-central-1", "Identity Center lives in the home region"
        if "InstanceArn" in params:
            assert params["InstanceArn"] == INSTANCE_ARN

    def console_permission_set(self, name="AdministratorAccess", duration="PT1H",
                               policies=("arn:aws:iam::aws:policy/AdministratorAccess",), inline=""):
        """A permission set made by hand in the console (README step 3), assigned to a user."""
        arn = f"{INSTANCE_ARN}/ps-{self._next():016d}"
        self.permission_sets[arn] = {"Name": name, "Description": "", "SessionDuration": duration,
                                     "policies": set(policies), "inline": inline}
        self.assignments.add((MANAGEMENT, arn, "USER", "user-console"))
        return arn

    def sso_admin__list_instances(self, region, **_):
        self._ic({}, region)
        return {"Instances": [dict(self.instance)] if self.instance else []}

    def sso_admin__list_permission_sets(self, params, region, **_):
        self._ic(params, region)
        return {"PermissionSets": sorted(self.permission_sets)}

    def sso_admin__describe_permission_set(self, params, region, **_):
        self._ic(params, region)
        ps = self.permission_sets[params["PermissionSetArn"]]
        return {"PermissionSet": {"PermissionSetArn": params["PermissionSetArn"], "Name": ps["Name"],
                                  "Description": ps["Description"], "SessionDuration": ps["SessionDuration"]}}

    def sso_admin__create_permission_set(self, params, region, **_):
        self._ic(params, region)
        if any(ps["Name"] == params["Name"] for ps in self.permission_sets.values()):
            raise FakeError("ConflictException", "permission set exists")
        assert {t["Key"] for t in params["Tags"]} == {"project", "env", "owner"}
        arn = f"{INSTANCE_ARN}/ps-{self._next():016d}"
        self.permission_sets[arn] = {"Name": params["Name"], "Description": params["Description"],
                                     "SessionDuration": params["SessionDuration"], "policies": set(), "inline": ""}
        return {"PermissionSet": {"PermissionSetArn": arn, "Name": params["Name"]}}

    def sso_admin__update_permission_set(self, params, region, **_):
        self._ic(params, region)
        self.permission_sets[params["PermissionSetArn"]].update(
            SessionDuration=params["SessionDuration"], Description=params["Description"])

    def sso_admin__list_managed_policies_in_permission_set(self, params, region, **_):
        self._ic(params, region)
        return {"AttachedManagedPolicies": [{"Arn": p, "Name": p.rsplit("/", 1)[-1]} for p in
                                            sorted(self.permission_sets[params["PermissionSetArn"]]["policies"])]}

    def sso_admin__attach_managed_policy_to_permission_set(self, params, region, **_):
        self._ic(params, region)
        self.permission_sets[params["PermissionSetArn"]]["policies"].add(params["ManagedPolicyArn"])

    def sso_admin__get_inline_policy_for_permission_set(self, params, region, **_):
        self._ic(params, region)
        return {"InlinePolicy": self.permission_sets[params["PermissionSetArn"]]["inline"]}

    def _sso_request(self, key):
        request = f"req-{self._next()}"
        self.sso_requests[request] = 0
        return {key: {"RequestId": request, "Status": "IN_PROGRESS"}}

    def _sso_status(self, request, key):
        self.sso_requests[request] += 1
        return {key: {"RequestId": request, "Status": "SUCCEEDED" if self.sso_requests[request] > 1 else "IN_PROGRESS"}}

    def sso_admin__provision_permission_set(self, params, region, **_):
        self._ic(params, region)
        assert params["TargetType"] == "ALL_PROVISIONED_ACCOUNTS"
        self.provisioned.append(params["PermissionSetArn"])
        return self._sso_request("PermissionSetProvisioningStatus")

    def sso_admin__describe_permission_set_provisioning_status(self, params, region, **_):
        self._ic(params, region)
        return self._sso_status(params["ProvisionPermissionSetRequestId"], "PermissionSetProvisioningStatus")

    def sso_admin__list_account_assignments(self, params, region, **_):
        self._ic(params, region)
        return {"AccountAssignments": [
            {"AccountId": a, "PermissionSetArn": p, "PrincipalType": t, "PrincipalId": i}
            for a, p, t, i in sorted(self.assignments)
            if a == params["AccountId"] and p == params["PermissionSetArn"]]}

    def sso_admin__create_account_assignment(self, params, region, **_):
        self._ic(params, region)
        assert params["TargetType"] == "AWS_ACCOUNT" and params["PrincipalType"] == "GROUP"
        assert params["TargetId"] == MANAGEMENT or params["TargetId"] in self.accounts
        assert params["PrincipalId"] in self.groups and params["PermissionSetArn"] in self.permission_sets
        self.assignments.add((params["TargetId"], params["PermissionSetArn"], "GROUP", params["PrincipalId"]))
        return self._sso_request("AccountAssignmentCreationStatus")

    def sso_admin__describe_account_assignment_creation_status(self, params, region, **_):
        self._ic(params, region)
        return self._sso_status(params["AccountAssignmentCreationRequestId"], "AccountAssignmentCreationStatus")

    def _store(self, params, region):
        assert region == "ca-central-1" and params["IdentityStoreId"] == IDENTITY_STORE

    def identitystore__get_group_id(self, params, region, **_):
        self._store(params, region)
        attr = params["AlternateIdentifier"]["UniqueAttribute"]
        assert attr["AttributePath"] == "displayName"
        for gid, group in self.groups.items():
            if group["DisplayName"] == attr["AttributeValue"]:
                return {"GroupId": gid, "IdentityStoreId": IDENTITY_STORE}
        raise FakeError("ResourceNotFoundException", "GROUP not found")

    def identitystore__create_group(self, params, region, **_):
        self._store(params, region)
        gid = f"group-{self._next()}"
        self.groups[gid] = {"DisplayName": params["DisplayName"], "Description": params["Description"]}
        return {"GroupId": gid, "IdentityStoreId": IDENTITY_STORE}

    def identitystore__get_user_id(self, params, region, **_):
        self._store(params, region)
        attr = params["AlternateIdentifier"]["UniqueAttribute"]
        assert attr["AttributePath"] == "userName"
        for uid, name in self.users.items():
            if name == attr["AttributeValue"]:
                return {"UserId": uid, "IdentityStoreId": IDENTITY_STORE}
        raise FakeError("ResourceNotFoundException", "USER not found")

    def identitystore__get_group_membership_id(self, params, region, **_):
        self._store(params, region)
        if (params["GroupId"], params["MemberId"]["UserId"]) in self.memberships:
            return {"MembershipId": "m-1", "IdentityStoreId": IDENTITY_STORE}
        raise FakeError("ResourceNotFoundException", "GROUP_MEMBERSHIP not found")

    def identitystore__create_group_membership(self, params, region, **_):
        self._store(params, region)
        self.memberships.add((params["GroupId"], params["MemberId"]["UserId"]))
        return {"MembershipId": "m-1", "IdentityStoreId": IDENTITY_STORE}


def _parse_flags(args):
    flags: dict = {}
    current = None
    for arg in args:
        if arg.startswith("--"):
            current = arg
            flags.setdefault(current, [])
        else:
            flags[current].append(arg)
    return flags


def run_main(cloud, *argv, answer=None):
    lines: list = []
    prompts: list = []

    def input_fn(prompt):
        prompts.append(prompt)
        return answer if answer is not None else ""

    code = ob.main(list(argv), runner=cloud, input_fn=input_fn, out=lines.append, err=lines.append,
                   sleep=lambda _: None)
    return code, "\n".join(lines), prompts


def apply_all(cloud, *extra):
    return run_main(cloud, "apply", "--yes", "--email-template", EMAILS, "--budget-email", BUDGET_EMAIL, *extra)


class FreshAccountTest(unittest.TestCase):
    def test_plan_on_a_fresh_account_changes_nothing(self):
        cloud = FakeCloud(organization=False, caller_arn=ROOT_ARN)
        code, out, _ = run_main(cloud, "plan")
        self.assertEqual(code, 0, out)
        self.assertEqual(cloud.writes(), [])
        self.assertIn("would: create the organization (all features)", out)
        self.assertIn("pending", out)

    def test_root_user_only_creates_the_organization(self):
        cloud = FakeCloud(organization=False, caller_arn=ROOT_ARN)
        code, out, _ = run_main(cloud, "apply", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(cloud.writes(), [("organizations", "create-organization")])
        self.assertEqual(cloud.org["FeatureSet"], "ALL")
        self.assertIn("IAM Identity Center", out)

    def test_root_user_stops_after_the_organization_on_later_runs_too(self):
        cloud = FakeCloud(caller_arn=ROOT_ARN)
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 0, out)
        self.assertEqual(cloud.writes(), [])
        self.assertIn("IAM Identity Center", out)


class FullBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(CONFIG.read_text())
        self.cloud = FakeCloud()
        code, self.out, _ = apply_all(self.cloud)
        self.assertEqual(code, 0, self.out)

    def account(self, key):
        name = next(a["name"] for a in self.cfg["accounts"] if a["key"] == key)
        return self.cloud.account_by_name(name)

    def test_organization_features(self):
        cloud = self.cloud
        self.assertEqual(cloud.policy_types, set(self.cfg["policy_types"]))
        self.assertTrue({"SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"} <= cloud.policy_types)
        self.assertEqual(cloud.services, set(self.cfg["trusted_access"]))
        self.assertTrue(cloud.stack_sets_access)
        self.assertEqual(cloud.root_features, {"RootCredentialsManagement", "RootSessions"})

    def test_ou_tree_and_account_placement(self):
        cloud = self.cloud
        self.assertEqual(sorted(cloud.ou_path(i) for i in cloud.ous), sorted(self.cfg["organizational_units"]))
        for account in self.cfg["accounts"]:
            account_id = cloud.account_by_name(account["name"])
            self.assertEqual(cloud.ou_path(cloud.accounts[account_id]["Parent"]), account["ou"])
            self.assertEqual(cloud.accounts[account_id]["Email"], f"aws+{account['key']}@example.com")

    def test_audit_account_is_the_delegated_administrator(self):
        audit = self.account("audit")
        for principal in self.cfg["delegated_admin_services"]:
            self.assertEqual(self.cloud.delegated[principal], {audit})

    def test_stacks_land_in_the_right_accounts_protected_and_tagged(self):
        home = self.cfg["home_region"]
        expected = {
            (self.account("log-archive"), home, "org-bootstrap-log-archive"),
            (MANAGEMENT, home, "org-bootstrap-management"),
            (MANAGEMENT, home, "org-bootstrap-config"),
            (self.account("audit"), home, "org-bootstrap-audit"),
        }
        self.assertEqual(set(self.cloud.stacks), expected)
        for key, stack in self.cloud.stacks.items():
            self.assertTrue(stack["protected"], key)
            self.assertEqual(stack["tags"], self.cfg["tags"], key)

    def test_trail_and_config_point_at_the_log_archive_bucket(self):
        home = self.cfg["home_region"]
        bucket = f"org-bootstrap-logs-{self.account('log-archive')}-{home}"
        log_archive = self.cloud.stacks[(self.account("log-archive"), home, "org-bootstrap-log-archive")]
        self.assertEqual(log_archive["params"]["BucketName"], bucket)
        self.assertEqual(log_archive["params"]["ManagementAccountId"], MANAGEMENT)
        self.assertEqual(log_archive["params"]["OrganizationId"], "o-exampleorgid")
        management = self.cloud.stacks[(MANAGEMENT, home, "org-bootstrap-management")]
        self.assertEqual(management["params"]["LogBucketName"], bucket)
        self.assertEqual(management["params"]["TrailName"], log_archive["params"]["TrailName"])
        self.assertEqual(management["params"]["RootId"], self.cloud.root_id)
        self.assertEqual(self.cloud.stacks[(MANAGEMENT, home, "org-bootstrap-config")]["params"]["LogBucketName"],
                         bucket)
        stack_set_params = {p["ParameterKey"]: p["ParameterValue"] for p in self.cloud.stack_set["Parameters"]}
        self.assertEqual(stack_set_params["LogBucketName"], bucket)

    def test_config_recorder_reaches_every_member_account(self):
        members = {i for i, a in self.cloud.accounts.items() if a["State"] == "ACTIVE"}
        self.assertEqual(self.cloud.instances, {(m, r) for m in members for r in self.cfg["config_regions"]})
        self.assertEqual(json.loads(self.cloud.stack_set["TemplateBody"]),
                         json.loads((BOOTSTRAP_DIR / "templates" / "config-recorder.json").read_text()))

    def test_second_apply_changes_nothing_in_the_organization(self):
        before = len(self.cloud.calls)
        code, out, _ = run_main(self.cloud, "apply", "--yes")  # no emails needed once created
        self.assertEqual(code, 0, out)
        later = self.cloud.calls[before:]
        self.assertEqual([(s, o) for s, o, *_ in later if ORG_WRITE_OPS.match(o)], [])
        self.assertEqual({o for _, o, *_ in later if WRITE_OPS.match(o)},
                         {"deploy", "update-termination-protection"})
        self.assertEqual(self.cloud.stacks[(MANAGEMENT, "ca-central-1", "org-bootstrap-management")]
                         ["params"]["BudgetEmail"], BUDGET_EMAIL)
        self.assertIn("0 changes made.", out)
        self.assertIn("up to date", out)

    def test_plan_after_apply_is_read_only(self):
        before = len(self.cloud.calls)
        code, out, _ = run_main(self.cloud, "plan")
        self.assertEqual(code, 0, out)
        self.assertEqual([o for _, o, *_ in self.cloud.calls[before:] if WRITE_OPS.match(o)], [])
        self.assertNotIn("would:", out)
        self.assertIn("0 changes planned.", out)

    def test_changed_configuration_updates_the_stack(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["budget_monthly_limit_usd"] = 40
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        scratch = Path(tmp.name) / "organization.json"
        scratch.write_text(json.dumps(cfg))
        code, out, _ = run_main(self.cloud, "apply", "--yes", "--config", str(scratch))
        self.assertEqual(code, 0, out)
        self.assertIn("done: update stack org-bootstrap-management", out)
        self.assertIn("1 change made.", out)
        self.assertEqual(self.cloud.stacks[(MANAGEMENT, "ca-central-1", "org-bootstrap-management")]
                         ["params"]["BudgetLimitUsd"], "40")

    def test_changed_stack_set_template_is_rolled_out(self):
        self.cloud.stack_set["TemplateBody"] = json.dumps({"Resources": {}})
        code, out, _ = run_main(self.cloud, "apply", "--yes")
        self.assertEqual(code, 0, out)
        self.assertIn(("cloudformation", "update-stack-set"), self.cloud.writes())
        self.assertIn("update StackSet org-bootstrap-config", out)

    def test_member_credentials_stay_out_of_arguments_and_output(self):
        for argv in self.cloud.argvs:
            self.assertFalse(any("fake-secret" in a or "fake-token" in a for a in argv), argv)
        self.assertNotIn("fake-secret", self.out)
        self.assertNotIn("fake-token", self.out)
        self.assertEqual(repr(ob.Credentials("a", "b", "c")), "Credentials(<redacted>)")

    def test_member_stacks_are_deployed_with_member_credentials(self):
        deploys = [(acct, p) for s, o, p, acct, _ in self.cloud.calls if o == "deploy"]
        self.assertTrue(deploys)
        self.assertIn(self.account("log-archive"), {acct for acct, _ in deploys})


class GuardTest(unittest.TestCase):
    def test_refuses_a_member_account(self):
        cloud = FakeCloud(master="999988887777")
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("not its management account", out)
        self.assertEqual(cloud.writes(), [])

    def test_refuses_consolidated_billing_only(self):
        cloud = FakeCloud(feature_set="CONSOLIDATED_BILLING")
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("enable all features", out)
        self.assertEqual(cloud.writes(), [])

    def test_apply_asks_for_the_account_id(self):
        cloud = FakeCloud()
        code, out, prompts = run_main(cloud, "apply", "--email-template", EMAILS,
                                      "--budget-email", BUDGET_EMAIL, answer="yes")
        self.assertEqual(code, 1)
        self.assertIn(MANAGEMENT, prompts[0])
        self.assertEqual(cloud.writes(), [])
        code, out, _ = run_main(cloud, "apply", "--email-template", EMAILS,
                                "--budget-email", BUDGET_EMAIL, answer=MANAGEMENT)
        self.assertEqual(code, 0, out)

    def test_new_accounts_need_an_email_template(self):
        cloud = FakeCloud()
        code, out, _ = run_main(cloud, "apply", "--yes", "--budget-email", BUDGET_EMAIL)
        self.assertEqual(code, 1)
        self.assertIn("--email-template is required", out)
        self.assertNotIn(("organizations", "create-account"), cloud.writes())

    def test_rejects_a_bad_email_template_before_any_call(self):
        for template in ("aws@example.com", "aws+{key}", "{key}{key}@example.com"):
            cloud = FakeCloud()
            code, out, _ = run_main(cloud, "apply", "--yes", "--email-template", template)
            self.assertEqual(code, 1, template)
            self.assertEqual(cloud.calls, [], template)

    def test_budget_email_is_required_the_first_time(self):
        cloud = FakeCloud()
        code, out, _ = run_main(cloud, "apply", "--yes", "--email-template", EMAILS)
        self.assertEqual(code, 1)
        self.assertIn("--budget-email is required", out)
        self.assertNotIn((MANAGEMENT, "ca-central-1", "org-bootstrap-management"), cloud.stacks)

    def test_failed_account_creation_stops_with_the_reason(self):
        cloud = FakeCloud()
        cloud.account_failure = "EMAIL_ALREADY_EXISTS"
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("EMAIL_ALREADY_EXISTS", out)

    def test_existing_account_is_moved_not_recreated(self):
        cloud = FakeCloud()
        existing = cloud.add_account("controls-poc-preview")
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 0, out)
        self.assertEqual(cloud.ou_path(cloud.accounts[existing]["Parent"]), "Sandbox/Preview")
        self.assertEqual(sum(1 for a in cloud.accounts.values() if a["Name"] == "controls-poc-preview"), 1)
        self.assertIn(("organizations", "move-account"), cloud.writes())

    def test_duplicate_or_closed_accounts_stop_the_run(self):
        cloud = FakeCloud()
        cloud.add_account("controls-poc-audit")
        cloud.add_account("controls-poc-audit")
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("2 accounts are named controls-poc-audit", out)
        cloud = FakeCloud()
        cloud.add_account("controls-poc-audit", state="SUSPENDED")
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("suspended", out)

    def test_failed_stack_set_operation_stops_the_run(self):
        cloud = FakeCloud()
        cloud.operation_failure = "FAILED"
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("operation", out)

    def test_aws_cli_v1_is_refused(self):
        def v1(argv, env):
            return 0, "", "aws-cli/1.29.0 Python/3.9\n"
        code = ob.main(["plan"], runner=v1, out=lambda _: None, err=lambda _: None)
        self.assertEqual(code, 1)


ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_ONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"


class IdentityCenterTest(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(CONFIG.read_text())
        self.ic = self.cfg["identity_center"]

    def sets_by_name(self, cloud):
        return {ps["Name"]: (arn, ps) for arn, ps in cloud.permission_sets.items()}

    def all_accounts(self, cloud):
        return {MANAGEMENT} | set(cloud.accounts)

    def test_permission_sets_group_and_assignments_on_every_account(self):
        cloud = FakeCloud()
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 0, out)
        sets = self.sets_by_name(cloud)
        self.assertEqual(sets["AdministratorAccess"][1]["policies"], {ADMIN})
        self.assertEqual(sets["AdministratorAccess"][1]["SessionDuration"], "PT4H")
        self.assertEqual(sets["ReadOnlyAccess"][1]["policies"], {READ_ONLY})
        [(group_id, group)] = cloud.groups.items()
        self.assertEqual(group["DisplayName"], "controls-poc-admins")
        expected = {(account, sets[name][0], "GROUP", group_id)
                    for account in self.all_accounts(cloud) for name in ("AdministratorAccess", "ReadOnlyAccess")}
        self.assertEqual(cloud.assignments, expected)
        self.assertEqual(len(expected), 10)

    def test_console_made_permission_set_is_adopted_not_duplicated(self):
        cloud = FakeCloud()
        arn = cloud.console_permission_set()
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 0, out)
        names = [ps["Name"] for ps in cloud.permission_sets.values()]
        self.assertEqual(names.count("AdministratorAccess"), 1)
        self.assertEqual(cloud.permission_sets[arn]["SessionDuration"], "PT4H")
        self.assertEqual(cloud.provisioned, [arn])  # the change reaches accounts already using it
        self.assertIn((MANAGEMENT, arn, "USER", "user-console"), cloud.assignments)  # left alone

    def test_extra_policies_are_reported_not_removed(self):
        cloud = FakeCloud()
        arn = cloud.console_permission_set(name="ReadOnlyAccess", duration="PT8H",
                                           policies=(READ_ONLY, ADMIN), inline='{"Statement": []}')
        cloud.permission_sets[arn]["Description"] = self.ic["permission_sets"][1]["description"]
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 0, out)
        self.assertIn(f"warning: permission set ReadOnlyAccess also has {ADMIN}", out)
        self.assertIn("inline policy", out)
        self.assertEqual(cloud.permission_sets[arn]["policies"], {READ_ONLY, ADMIN})

    def test_admin_user_is_added_to_the_admins_group(self):
        cloud = FakeCloud()
        cloud.users["user-1"] = "analyst-a"
        code, out, _ = apply_all(cloud, "--admin-user", "analyst-a")
        self.assertEqual(code, 0, out)
        [group_id] = cloud.groups
        self.assertEqual(cloud.memberships, {(group_id, "user-1")})
        code, out, _ = run_main(cloud, "apply", "--yes", "--admin-user", "analyst-a")
        self.assertIn("0 changes made.", out)

    def test_unknown_admin_user_stops_the_run(self):
        cloud = FakeCloud()
        code, out, _ = apply_all(cloud, "--admin-user", "analyst-b")
        self.assertEqual(code, 1)
        self.assertIn("no IAM Identity Center user named analyst-b", out)

    def test_identity_center_not_enabled(self):
        cloud = FakeCloud(identity_center=False)
        code, out, _ = run_main(cloud, "plan")
        self.assertEqual(code, 0, out)
        code, out, _ = apply_all(cloud)
        self.assertEqual(code, 1)
        self.assertIn("README step 3", out)
        self.assertIn((MANAGEMENT, "ca-central-1", "org-bootstrap-management"), cloud.stacks)  # the rest is done
        cloud.instance = {"InstanceArn": INSTANCE_ARN, "IdentityStoreId": IDENTITY_STORE,
                          "OwnerAccountId": MANAGEMENT, "Status": "ACTIVE"}
        code, out, _ = run_main(cloud, "plan")
        self.assertIn("would: create permission set AdministratorAccess", out)

    def sso_config(self, cloud, *extra):
        lines: list = []
        code = ob.main(["sso-config", *extra], runner=cloud, out=lines.append, err=lines.append,
                       sleep=lambda _: None)
        return code, "\n".join(lines)

    def test_sso_config_has_a_profile_per_account_and_role(self):
        cloud = FakeCloud()
        self.assertEqual(apply_all(cloud)[0], 0)
        before = len(cloud.calls)
        code, text = self.sso_config(cloud)
        self.assertEqual(code, 0, text)
        self.assertEqual([o for _, o, *_ in cloud.calls[before:] if WRITE_OPS.match(o)], [])
        parser = configparser.ConfigParser()
        parser.read_string(text)
        session = parser["sso-session controls-poc"]
        self.assertEqual(session["sso_start_url"], f"https://{IDENTITY_STORE}.awsapps.com/start")
        self.assertEqual(session["sso_region"], "ca-central-1")
        profiles = {s: parser[s] for s in parser.sections() if s.startswith("profile ")}
        keys = ["management"] + [a["key"] for a in self.cfg["accounts"]]
        self.assertEqual(set(profiles), {f"profile controls-poc-{k}-{s}" for k in keys for s in ("admin", "readonly")})
        audit = profiles["profile controls-poc-audit-readonly"]
        self.assertEqual(audit["sso_account_id"], cloud.account_by_name("controls-poc-audit"))
        self.assertEqual(audit["sso_role_name"], "ReadOnlyAccess")
        self.assertEqual(audit["sso_session"], "controls-poc")
        self.assertEqual(profiles["profile controls-poc-management-admin"]["sso_account_id"], MANAGEMENT)
        # Every profile names an assignment that exists.
        sets = {ps["Name"]: arn for arn, ps in cloud.permission_sets.items()}
        for profile in profiles.values():
            self.assertTrue(any(a == profile["sso_account_id"] and p == sets[profile["sso_role_name"]]
                                for a, p, *_ in cloud.assignments), profile)

    def test_sso_config_start_url_and_out_file(self):
        cloud = FakeCloud()
        self.assertEqual(apply_all(cloud)[0], 0)
        code, text = self.sso_config(cloud, "--start-url", "https://controls-poc.awsapps.com/start")
        self.assertIn("sso_start_url = https://controls-poc.awsapps.com/start", text)
        code, text = self.sso_config(cloud, "--start-url", "https://x.example/start\n[profile evil]")
        self.assertEqual(code, 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "controls-poc.config"
            code, text = self.sso_config(cloud, "--out", str(path))
            self.assertEqual(code, 0, text)
            self.assertIn("[sso-session controls-poc]", path.read_text())
            code, text = self.sso_config(cloud, "--out", str(path))
            self.assertEqual(code, 1)
            self.assertIn("nothing is overwritten", text)

    def test_sso_config_skips_accounts_not_created_yet(self):
        cloud = FakeCloud()
        cloud.add_account("controls-poc-audit")
        code, text = self.sso_config(cloud)
        self.assertEqual(code, 0, text)
        self.assertIn("# Not created yet, no profile: controls-poc-preview", text)
        self.assertIn("[profile controls-poc-audit-admin]", text)
        self.assertNotIn("controls-poc-preview-admin", text)


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(CONFIG.read_text())

    def test_committed_configuration_is_valid(self):
        ob.validate_config(self.cfg)

    def test_ou_tree_matches_the_tools_org_state(self):
        # The Athena journey's org_state (tests/fixtures/athena) runs against these OUs.
        request = json.loads((ROOT / "tests/fixtures/athena/request-private-preview.json").read_text())
        fixture_ous = {ou["path"] for ou in request["org_state"]["ous"]}
        self.assertLessEqual(fixture_ous, set(self.cfg["organizational_units"]))
        self.assertEqual(self.cfg["home_region"], "ca-central-1")

    def assertInvalid(self, change, message):
        cfg = copy.deepcopy(self.cfg)
        change(cfg)
        with self.assertRaisesRegex(ob.BootstrapError, message):
            ob.validate_config(cfg)

    def test_rejects_unsafe_or_inconsistent_configuration(self):
        self.assertInvalid(lambda c: c["accounts"][0].update(name="team@example.com"), "no email addresses")
        self.assertInvalid(lambda c: c.update(home_region="eu-west-1"), "home_region")
        self.assertInvalid(lambda c: c.update(config_regions=["ca-central-1", "eu-west-1"]), "config_regions")
        self.assertInvalid(lambda c: c.update(organizational_units=["Sandbox/Preview", "Sandbox"]), "parent")
        self.assertInvalid(lambda c: c["accounts"][0].update(ou="Nowhere"), "not in organizational_units")
        self.assertInvalid(lambda c: c.update(audit_account="log-archive"), "must differ")
        self.assertInvalid(lambda c: c.update(log_retention_days=7), "30")
        self.assertInvalid(lambda c: c["trusted_access"].remove("iam.amazonaws.com"), "iam.amazonaws.com")
        self.assertInvalid(lambda c: c["trusted_access"].remove("access-analyzer.amazonaws.com"),
                           "delegated_admin_services entry needs trusted_access")
        self.assertInvalid(lambda c: c["policy_types"].remove("SERVICE_CONTROL_POLICY"), "SERVICE_CONTROL_POLICY")
        self.assertInvalid(lambda c: c["tags"].pop("owner"), "tags")
        self.assertInvalid(lambda c: c["accounts"][0].update(key="management"), "reserved")
        ic = "identity_center"
        self.assertInvalid(lambda c: c[ic]["permission_sets"][0].update(session_duration="PT24H"), "PT12H")
        self.assertInvalid(lambda c: c[ic]["permission_sets"][0].update(
            managed_policies=["arn:aws:iam::111122223333:policy/Mine"]), "AWS managed")
        self.assertInvalid(lambda c: c[ic]["groups"][0].update(permission_sets=["PowerUserAccess"]),
                           "permission_sets must be listed")
        self.assertInvalid(lambda c: c[ic]["groups"][0].update(accounts=["nowhere"]), "accounts must be")
        self.assertInvalid(lambda c: c[ic].update(admins_group="someone-else"), "admins_group")
        self.assertInvalid(lambda c: c[ic]["permission_sets"][1].update(profile_suffix="admin"), "twice")


PSEUDO = {"AWS::AccountId", "AWS::Partition", "AWS::Region", "AWS::StackName", "AWS::URLSuffix",
          "AWS::NoValue", "AWS::StackId"}


def _templates():
    for path in sorted((BOOTSTRAP_DIR / "templates").glob("*.json")):
        yield path.name, json.loads(path.read_text())


def _walk(node):
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _statements(template):
    for resource in template["Resources"].values():
        for node in _walk(resource.get("Properties", {})):
            if isinstance(node, dict) and "Effect" in node and "Action" in node:
                yield node


class TemplateTest(unittest.TestCase):
    def test_references_resolve(self):
        for name, template in _templates():
            known = set(template.get("Parameters", {})) | set(template["Resources"]) | PSEUDO
            for node in _walk(template):
                if not isinstance(node, dict):
                    continue
                if "Ref" in node:
                    self.assertIn(node["Ref"], known, name)
                if "Fn::GetAtt" in node:
                    self.assertIn(node["Fn::GetAtt"][0], template["Resources"], name)
                if "Fn::Sub" in node:
                    for var in re.findall(r"\$\{([^!}][^}]*)\}", node["Fn::Sub"]):
                        self.assertIn(var.split(".")[0], known, f"{name}: ${{{var}}}")
                if "Fn::If" in node:
                    self.assertIn(node["Fn::If"][0], template.get("Conditions", {}), name)
            for param, spec in template.get("Parameters", {}).items():
                self.assertTrue(any(isinstance(n, dict) and (n.get("Ref") == param or (
                    "Fn::Sub" in n and "${" + param + "}" in n["Fn::Sub"])) for n in _walk(template)),
                    f"{name}: parameter {param} is unused")

    def test_log_bucket_is_private_encrypted_versioned_and_expires(self):
        template = dict(_templates())["log-archive.json"]
        bucket = template["Resources"]["LogBucket"]
        props = bucket["Properties"]
        self.assertEqual(bucket["DeletionPolicy"], "Retain")
        self.assertTrue(all(props["PublicAccessBlockConfiguration"].values()))
        self.assertEqual(len(props["PublicAccessBlockConfiguration"]), 4)
        self.assertEqual(props["OwnershipControls"]["Rules"][0]["ObjectOwnership"], "BucketOwnerEnforced")
        self.assertEqual(props["VersioningConfiguration"]["Status"], "Enabled")
        self.assertTrue(props["BucketEncryption"]["ServerSideEncryptionConfiguration"])
        rule = props["LifecycleConfiguration"]["Rules"][0]
        self.assertEqual(rule["ExpirationInDays"], {"Ref": "RetentionDays"})
        self.assertEqual(rule["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"], 7)
        self.assertGreaterEqual(template["Parameters"]["RetentionDays"]["MinValue"], 30)

    def test_log_bucket_policy_admits_only_the_trail_and_the_organizations_recorders(self):
        template = dict(_templates())["log-archive.json"]
        statements = template["Resources"]["LogBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        by_sid = {s["Sid"]: s for s in statements}
        self.assertEqual(by_sid["DenyInsecureTransport"]["Condition"], {"Bool": {"aws:SecureTransport": "false"}})
        self.assertEqual(by_sid["DenyLogDeletion"]["Effect"], "Deny")
        for statement in statements:
            if statement["Effect"] != "Allow":
                continue
            condition = statement["Condition"]
            if statement["Principal"] == {"Service": "cloudtrail.amazonaws.com"}:
                self.assertIn("aws:SourceArn", condition["StringEquals"], statement["Sid"])
            else:
                self.assertEqual(statement["Principal"], {"AWS": "*"})
                self.assertEqual(condition["StringEquals"], {"aws:PrincipalOrgID": {"Ref": "OrganizationId"}})
                self.assertIn("role/org-bootstrap/org-bootstrap-config-recorder-",
                              condition["ArnLike"]["aws:PrincipalArn"]["Fn::Sub"])
        write = by_sid["ConfigRecorderWriteOwnAccount"]
        self.assertIn("/AWSLogs/${!aws:PrincipalAccount}/Config/*", write["Resource"]["Fn::Sub"])

    def test_recorder_role_matches_the_bucket_policy(self):
        role = dict(_templates())["config-recorder.json"]["Resources"]["RecorderRole"]["Properties"]
        self.assertEqual(role["Path"], "/org-bootstrap/")
        self.assertTrue(role["RoleName"]["Fn::Sub"].startswith("org-bootstrap-config-recorder-"))

    def test_roles_are_on_the_bootstrap_path_and_trust_only_their_own_account(self):
        roles = 0
        for name, template in _templates():
            for resource in template["Resources"].values():
                if resource["Type"] != "AWS::IAM::Role":
                    continue
                roles += 1
                props = resource["Properties"]
                self.assertEqual(props["Path"], "/org-bootstrap/", name)
                for statement in props["AssumeRolePolicyDocument"]["Statement"]:
                    self.assertEqual(statement["Principal"], {"Service": "config.amazonaws.com"}, name)
                    self.assertEqual(statement["Condition"]["StringEquals"]["aws:SourceAccount"],
                                     {"Ref": "AWS::AccountId"}, name)
        self.assertEqual(roles, 2)

    def test_no_allow_to_everyone_without_an_organization_condition(self):
        for name, template in _templates():
            for statement in _statements(template):
                if statement["Effect"] == "Allow" and statement.get("Principal") in ("*", {"AWS": "*"}):
                    self.assertIn("aws:PrincipalOrgID", statement["Condition"]["StringEquals"], name)

    def test_organization_trail(self):
        trail = dict(_templates())["management.json"]["Resources"]["OrganizationTrail"]["Properties"]
        for flag in ("IsLogging", "IsOrganizationTrail", "IsMultiRegionTrail", "IncludeGlobalServiceEvents",
                     "EnableLogFileValidation"):
            self.assertIs(trail[flag], True, flag)
        self.assertNotIn("EventSelectors", trail)  # all management events, read and write

    def test_budget_alerts_and_report_only_tag_policy(self):
        resources = dict(_templates())["management.json"]["Resources"]
        notes = [n["Notification"] for n in resources["MonthlyBudget"]["Properties"]["NotificationsWithSubscribers"]]
        self.assertEqual({(n["NotificationType"], n["Threshold"]) for n in notes},
                         {("ACTUAL", 50), ("ACTUAL", 80), ("ACTUAL", 100), ("FORECASTED", 100)})
        policy = resources["CostTagPolicy"]["Properties"]
        self.assertEqual(policy["Type"], "TAG_POLICY")
        self.assertEqual(set(policy["Content"]["tags"]), {"project", "env", "owner"})
        self.assertNotIn("enforced_for", json.dumps(policy["Content"]))

    def test_config_records_everything_once(self):
        recorder = dict(_templates())["config-recorder.json"]["Resources"]["Recorder"]["Properties"]
        self.assertIs(recorder["RecordingGroup"]["AllSupported"], True)
        self.assertEqual(recorder["RecordingGroup"]["IncludeGlobalResourceTypes"],
                         {"Fn::If": ["IsHomeRegion", True, False]})

    def test_audit_account_resources(self):
        resources = dict(_templates())["audit.json"]["Resources"]
        self.assertEqual(resources["OrganizationAnalyzer"]["Properties"]["Type"], "ORGANIZATION")
        self.assertIn("OrganizationAggregationSource", resources["OrganizationAggregator"]["Properties"])

    def test_only_expected_resource_types(self):
        allowed = {"AWS::S3::Bucket", "AWS::S3::BucketPolicy", "AWS::CloudTrail::Trail", "AWS::Budgets::Budget",
                   "AWS::Organizations::Policy", "AWS::IAM::Role", "AWS::Config::ConfigurationRecorder",
                   "AWS::Config::DeliveryChannel", "AWS::Config::ConfigurationAggregator",
                   "AWS::AccessAnalyzer::Analyzer"}
        for name, template in _templates():
            self.assertLessEqual({r["Type"] for r in template["Resources"].values()}, allowed, name)


class CompatibilityTest(unittest.TestCase):
    def test_runs_on_cloudshell_python(self):
        # CloudShell's python3 is older than the repository's; keep the script 3.9-compatible.
        ast.parse(SCRIPT.read_text(), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
