# Threat Model: Test organization bootstrap

| | |
|---|---|
| Author | Repository owner, drafted with an AI coding agent |
| Date | 2026-11-06 |
| Reviewers | Pending |
| Related PR / ADR | [ADR-0013](../adr/0013-test-organization-bootstrap.md) |

Scope: `infra/org-bootstrap/` — the script that turns a fresh AWS account
into the test organization's management account, its CloudFormation
templates, and the organization it builds. The onboarding tool itself is in
[onboarding-tool.md](onboarding-tool.md). Revisit when the bootstrap adds a
service, an account, a region, a credential, or runs anywhere but an
administrator's CloudShell.

## 1. What are we building?

```
[Administrator] --console, MFA--> [IAM Identity Center] --AdministratorAccess--> [CloudShell, management account]
       |                                                                              |
       +--root user, MFA, once: create the organization                               |
                                                                                      v
                              org_bootstrap.py --argv, no shell--> [AWS CLI v2] --HTTPS, SigV4--> AWS APIs
                                      |                                 |
                                      |   sts:AssumeRole OrganizationAccountAccessRole (1 h, env only)
                                      v                                 v
        [management account]: Organizations, IAM root access,    [member accounts]: log-archive bucket,
        org trail, budget, tag policy, Config, StackSet          audit aggregator + analyzer, Config (StackSet)

        Every account's CloudTrail events and Config history --> [log-archive bucket]
```

Trust boundaries: (1) the administrator's identity (root once, then
Identity Center with MFA); (2) the management account, which can reach
every member account; (3) member accounts, whose administrators must not
reach the log archive or other accounts; (4) the repository, whose reviewed
`organization.json` and templates decide what `apply` builds; (5) project
CI, which must never manage the bootstrap's stacks or roles.

### Data handled

| Data | Classification | Stored where | Retention |
|---|---|---|---|
| Account root emails, budget mailbox | personal if a person's address; use role mailboxes | Command line at apply time; AWS Organizations and the budget | Life of the organization; never in the repository |
| Account IDs, organization ID | internal | Terminal output, AWS | Never in the repository |
| Temporary credentials for member accounts | secret | Memory of the script and the CLI child process's environment | One hour (role chaining limit) |
| CloudTrail logs, Config history | internal (may hold identifiers of the test organization's users) | Log archive bucket, `ca-central-1` | 365 days (configurable, at least 30) |

## 2. What can go wrong? (STRIDE)

| Threat | Applies? | Scenario | Mitigation | Status |
|---|---|---|---|---|
| **S**poofing | Yes | Someone runs `apply` in the wrong account, or a member account, and reshapes an organization they didn't mean to | `apply` reads the caller's identity and the organization first, refuses a member account and an organization without all features, and asks for the management account ID to be typed before any change (tests) | Done |
| **S**poofing | Yes | The root user is used for routine work | Root only creates the organization and the script stops; the rest refuses to run as root by stopping after that step. Root has MFA and no access keys (runbook). Member accounts get no root credentials (centralized root access) | Done |
| **T**ampering | Yes | A member account administrator, or a compromised workload, deletes or rewrites the trail's logs to hide activity | The bucket is in its own account; its policy denies deletes and non-TLS access, and admits writes only from the management account's trail (by `aws:SourceArn`) and from this organization's `/org-bootstrap/` recorder roles, each into its own account's prefix; versioning; CloudTrail log file validation; the trail lives in the management account | Done (tests) |
| **T**ampering | Yes | A member account administrator stops its Config recorder or deletes the `/org-bootstrap/` role | Not prevented yet: the protecting SCP is the tool's to generate (organization baseline). The aggregator in the audit account shows a silent account | Open |
| **T**ampering | Yes | Project CI changes the bootstrap's stacks or roles | Stacks are `org-bootstrap-*` and roles under `/org-bootstrap/`; the CI bootstrap's boundary allows only `aws-controls-poc` stacks and `/aws-controls-poc/` roles, and blocks StackSets and Organizations calls | Done (by naming; boundary tested in governance) |
| **T**ampering | Yes | A changed `organization.json` or template widens access | Changes go through pull requests; the tests check the bucket policy, role trust, resource types and that every allow to everyone carries the organization condition; `plan` shows the change before `apply` | Done (tests) |
| **T**ampering | Low | Command injection through configuration or arguments | The CLI is called with argument lists, no shell; API parameters go as one JSON document (`--cli-input-json`); configuration values are validated against patterns | Done |
| **R**epudiation | Yes | No record of who changed the organization | The organization trail records every API call from the moment it exists; calls before it (creating the organization and the first steps) are in the management account's 90-day CloudTrail event history | Partly done |
| **I**nformation disclosure | Yes | Member account credentials leak into a log, the terminal or the process list | Credentials go into the child process's environment, never its arguments; `Credentials` hides them from `repr`; errors carry the AWS error code and message only (tests) | Done |
| **I**nformation disclosure | Yes | Emails or account IDs end up in the repository | The configuration rejects any `@`; emails come from the command line; IDs are read from AWS and printed only; the PII scan runs on every commit | Done |
| **D**enial of service | Yes | Runaway cost in a test account (denial of wallet) | Monthly budget with alerts at 50/80/100 % and 100 % forecast; no hourly resources; daily Config recording | Done |
| **E**levation of privilege | Yes | Whoever controls the management account controls every account (`OrganizationAccountAccessRole` trusts it) | Nothing runs in the management account but this bootstrap; administrators come from Identity Center with MFA; delegated administration keeps security tooling in the audit account | Accepted for a test organization |
| **E**levation of privilege | Yes | Service-managed StackSets run with organization-wide permissions | Only the management account creates them; project CI's boundary blocks StackSets; the one StackSet deploys the reviewed Config template | Done |
| **E**levation of privilege | Low | The Config recorder role is abused to write elsewhere | It trusts only `config.amazonaws.com` for its own account (`aws:SourceAccount`) and may write only its own prefix in the log bucket | Done (tests) |

## 3. Privacy

- Personal data: none needed. Account root emails and the budget mailbox
  should be role mailboxes; if a person's address is used, it is stored
  only in AWS (Organizations, Budgets), in Canada or AWS's global billing
  services, never in the repository.
- Logs: CloudTrail and Config record the test organization's own users'
  identifiers (Identity Center user names). They stay in `ca-central-1`
  and expire with the bucket's lifecycle. Use synthetic data only in the
  test organization's workloads.

## 4. What are we doing about it?

Mitigations are linked above. Open items: an SCP protecting the
`/org-bootstrap/` roles, the Config recorder and the trail from member
accounts (from the tool's organization baseline), reading `org_state` from
AWS instead of declaring it, and a review of this model before the
organization holds anything but synthetic data.

## 5. Did we do a good job?

- [x] Abuse cases have tests (wrong account, root, missing confirmation, credential handling, bucket policy, role trust)
- [ ] Reviewed by someone outside the implementing team
- [x] Revisit trigger defined
