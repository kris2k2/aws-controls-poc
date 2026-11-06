# ADR-0013: Bootstrap the test organization from a fresh account with a script and CloudFormation

- **Status:** proposed
- **Date:** 2026-11-06
- **Deciders:** repository owner (pending review)

## Context

The tool writes organization policies, Config rules and detections, and
composes them onto an OU tree it reads from a declared `org_state`
(ADR-0011). None of it has run in AWS: Validate isn't started, impact
replay (ADR-0012) needs a real organization trail, and Assess's first
signed Control Catalog run needs an account. We're getting a brand-new AWS
account to host a test organization, and have to build the organization
ourselves.

Forces:

- **A clean canvas.** The test organization must hold only what the tool
  will be tested against, so that a deny or a quota count is the tool's
  doing. Anything that brings its own SCPs or Config rules gets in the way.
- **From nothing.** The account starts with only its root user. Several
  steps (creating the organization, enabling policy types and trusted
  access, delegated administrators, centralized root access) have no
  CloudFormation resource, and IAM Identity Center's organization instance
  can only be enabled in the console.
- **Governance.** Home region `ca-central-1`; new infrastructure in CDK,
  but plain CloudFormation is acceptable "for the bootstrap itself"; CI
  never touches account-level setup; idle cost near zero; every bucket has
  a lifecycle, every resource cost tags.
- **The repository is Python standard library only (ADR-0001)** and tested
  offline.

## Decision

1. **The fresh account becomes the management account** of an organization
   with all features. OUs `Security`, `Sandbox/Preview`,
   `Workloads/Analytics` (the paths in the Athena journey's `org_state`),
   and four member accounts: `log-archive` and `audit` in `Security`,
   `preview` and `analytics` under the tiers' OUs. The desired state is
   `infra/org-bootstrap/organization.json`, with no emails or account IDs.
2. **Organization features:** SCP, RCP and tag policy types; trusted access
   for CloudTrail, Config, IAM Access Analyzer, IAM and CloudFormation
   StackSets; centralized root access (root credentials management and root
   sessions); the audit account as delegated administrator for Config and
   Access Analyzer.
3. **Shared services, in CloudFormation templates** (`templates/*.json`):
   a log archive bucket in the log-archive account; an organization trail
   (all regions, read and write management events, log file validation), a
   monthly budget and a report-only cost-tag policy in the management
   account; a Config recorder (daily, home region) in every account,
   through a service-managed StackSet with auto-deployment plus a stack in
   the management account; an organization Config aggregator and an
   organization Access Analyzer in the audit account.
4. **One script drives it all**: `org_bootstrap.py`, standard library,
   Python 3.9 or later, calling the AWS CLI v2 with argument lists. Both
   ship in AWS CloudShell, so the administrator needs nothing installed.
   `plan` is read-only; `apply` reads each step's state and changes only
   what differs, so it resumes after a failure. It reaches member accounts
   by assuming `OrganizationAccountAccessRole`, with the credentials in the
   child process's environment only.
5. **The root user does one step.** Signed in as root, `apply` creates the
   organization and stops. The administrator enables IAM Identity Center in
   the console, then runs the rest as an Identity Center administrator.
6. **Named outside the project's reach.** Stacks are `org-bootstrap-*` and
   roles are under `/org-bootstrap/`, so the CI bootstrap's boundary
   (stacks `aws-controls-poc` or `aws-controls-poc-*`, roles under `/aws-controls-poc/`) keeps
   every project CI role away from them.
7. **Templates are JSON**, so the tests can load and check them with the
   standard library: private, versioned, expiring bucket; a bucket policy
   that admits only the trail and the organization's recorder roles; roles
   on the bootstrap path trusting only their own account; every reference
   resolving.
8. **No SCPs or RCPs**, no Security Hub or GuardDuty, no Control Tower.
   The guardrails come from the tool; the paid detectors wait for Validate.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Script + CloudFormation, own landing zone (chosen)** | Only what we test against; covers the API-only steps; nothing to install in CloudShell; offline-testable; idempotent | We maintain it; drift is found by re-running `plan`, not continuously |
| AWS Control Tower | AWS-managed landing zone, drift detection, account factory | Adds its own SCPs and Config rules to the OUs it governs, which mix with the tool's guardrails and use up the SCP quota Compose budgets (ADR-0011); Config in every governed region; less control over OU names |
| CDK (TypeScript) | Governance default for new infrastructure | Needs `cdk bootstrap` or the project CI bootstrap in every account; the organization-level steps still need API calls; adds Node dependencies to a Python repository |
| Terraform | Has Organizations resources | New toolchain and state backend; needs its own ADR under the AWS standard |
| Console clicks and a checklist | Nothing to build | Not reproducible or reviewable; easy to miss a step |
| boto3 instead of the AWS CLI | Richer error handling | A dependency (ADR-0001); not guaranteed in CloudShell's Python |

## Consequences

- The organization exists as reviewed code: changing it is a pull request,
  then an administrator's `plan` and `apply`. CI can't apply it.
- `org_state` stays declared (ADR-0011), but now describes a real
  organization; reading it from AWS is a later step.
- Security: the management account and its administrators can reach every
  account through `OrganizationAccountAccessRole`; nothing runs there but
  this bootstrap. Member accounts have no root credentials. Until the
  tool's organization baseline is applied, a member account administrator
  could stop that account's Config recorder; the trail and log bucket are
  out of their reach. See the
  [threat model](../threat-models/test-organization.md).
- Privacy: account root emails and the budget mailbox are given at run
  time and stored only in AWS.
- Cost: no hourly resources; estimated under USD 5 a month idle, with a
  USD 25 budget alerting from 50 %.
- Revisit when Validate needs Security Hub or GuardDuty, when a second
  region joins `config_regions`, or if the organization ever holds data
  that isn't synthetic (then KMS and Object Lock on the log bucket).
