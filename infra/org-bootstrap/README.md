# Test organization bootstrap

Turns a fresh AWS account into the management account of the
`aws-controls-poc` test organization: the AWS Organizations setup, the
member accounts, and the logging and inventory the onboarding tool's
controls will be validated against. Decision and alternatives:
[ADR-0013](../../docs/adr/0013-test-organization-bootstrap.md). Threats:
[test-organization threat model](../../docs/threat-models/test-organization.md).

A human administrator runs it, never CI. It deploys no SCPs or RCPs: those
are the onboarding tool's output, composed onto this organization later.

## What it builds

```
Root (r-…)                       SCP, RCP and tag policies enabled; tag policy org-bootstrap-cost-tags (report-only)
├── management account (this)    organization trail, monthly budget, Config recorder
├── Security
│   ├── controls-poc-log-archive log archive bucket: CloudTrail + every account's Config
│   └── controls-poc-audit       delegated admin: Config aggregator, IAM Access Analyzer (organization)
├── Sandbox
│   └── Preview
│       └── controls-poc-preview   the Private Preview tier's account
└── Workloads
    └── Analytics
        └── controls-poc-analytics a workload account
```

The OU paths match the `org_state` in the Athena journey's fixtures, so a
request written for the tests describes this organization once its account
IDs are filled in.

| Setting | Value | Why |
|---|---|---|
| Feature set | All features | SCPs, RCPs, tag policies, trusted access |
| Policy types | `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`, `TAG_POLICY` | The tool generates SCPs and RCPs; the tag policy reports missing cost tags |
| Trusted access | CloudTrail, Config (+ multi-account setup), IAM Access Analyzer, IAM, CloudFormation StackSets | Organization trail, Config everywhere, organization analyzer, centralized root access, the Config StackSet |
| Centralized root access | Root credentials management and root sessions | Member accounts have no root password or keys; privileged root tasks run from the management account |
| Delegated administrator | `controls-poc-audit` for Config and Access Analyzer | Keeps day-to-day security work out of the management account |
| Organization trail | `org-bootstrap`, all regions, all management events (read and write), log file validation | Impact replay (ADR-0012) needs 30 days of read and write calls |
| AWS Config | Every account, `ca-central-1`, daily recording, IAM types once | Detective artifacts (ADR-0009); daily keeps idle cost low |
| Log retention | 365 days, versioned, deletes denied, TLS only | Evidence for impact replay; minimum 30 |
| Budget | USD 25/month: alerts at 50 %, 80 %, 100 % actual and 100 % forecast | Cost standard |
| IAM Identity Center | Permission sets `AdministratorAccess` (4 h) and `ReadOnlyAccess` (8 h); group `controls-poc-admins` assigned both on every account, management included | One sign-in, every account in the access portal and as CLI profiles ([switching accounts](#switching-between-accounts)) |

Everything is tagged `project=aws-controls-poc`, `env=test`,
`owner=aws-controls-poc-maintainers`. Stacks are named `org-bootstrap-*`,
not `aws-controls-poc-*`, so no project CI role can ever manage them (the
CI bootstrap's boundary only allows stacks named `aws-controls-poc` or `aws-controls-poc-*`). IAM roles
it creates live under `/org-bootstrap/`, outside the project's path.

## Before you start

- A brand-new AWS account, with a payment method, that will be the
  management account. Don't run workloads in it.
- Five mailboxes you control: one per member account (the account's root
  email) and one for budget alerts. A domain with plus-addressing works:
  `aws+{key}@example.com` becomes `aws+log-archive@example.com` and so on.
  Use role mailboxes, not a person's address. They're given on the command
  line and never committed.
- The `infra/org-bootstrap/` directory of this repository.

## Runbook

### 1. Secure the root user (console, root)

1. Sign in as the root user, add an MFA device (a security key or
   passkey), and don't create access keys.
2. Optional: set the alternate contacts (Account → Alternate contacts).

### 2. Create the organization (CloudShell, root)

Open CloudShell in **ca-central-1** (Canada Central). Upload a zip of
`infra/org-bootstrap/` (Actions → Upload file) and unzip it, or clone the
repository. Then:

```sh
cd org-bootstrap        # or aws-controls-poc/infra/org-bootstrap
python3 org_bootstrap.py plan
python3 org_bootstrap.py apply
```

Signed in as root, `apply` creates the organization with all features and
stops. Everything else runs as an administrator from IAM Identity Center:
the root user can't assume roles into member accounts, and shouldn't be
used for more than it has to.

### 3. Enable IAM Identity Center (console, root)

1. IAM Identity Center → Enable, for the organization, in **ca-central-1**.
2. Settings → Authentication: require MFA on every sign-in.
3. Create a user for yourself (Users → Add user), a permission set
   `AdministratorAccess` (Permission sets → Create → Predefined →
   AdministratorAccess) and assign it to your user on the management
   account. That's enough to run step 4, which takes the permission set
   over (session 4 hours), adds `ReadOnlyAccess` and assigns both to the
   `controls-poc-admins` group on every account.
4. Note the **AWS access portal URL** (Dashboard → Settings summary); you'll
   need it if you give the portal a custom alias.
5. Sign out of the root user. Store its MFA device safely; you'll rarely
   need it again.

### 4. Bootstrap the rest (CloudShell, administrator)

Sign in through the access portal, open the management account with
`AdministratorAccess`, open CloudShell in ca-central-1 and run:

```sh
python3 org_bootstrap.py plan
python3 org_bootstrap.py apply \
  --email-template 'aws+{key}@example.com' \
  --budget-email 'aws-budget@example.com' \
  --admin-user 'your-identity-center-user-name'
```

`--admin-user` adds your Identity Center user to `controls-poc-admins`, so
you get every account. Leave it out to manage group membership in the
console instead.

`apply` asks you to type the management account ID before it changes
anything (`--yes` skips the prompt). It takes 15 to 30 minutes, mostly
account creation and the Config StackSet. If anything fails, fix the cause
and run `apply` again: every step checks the current state first and does
only what's missing. Later runs need no emails unless a new account is
added.

`apply` prints the new account IDs. Keep them, and the organization ID,
out of the repository; the `org_state` you give the onboarding tool lives
next to your run outputs.

### 5. Finish in the console (administrator)

1. **Identity Center:** reload the access portal: every account now shows
   `AdministratorAccess` and `ReadOnlyAccess`. Then remove the direct
   assignment from step 3 (AWS accounts → management account → your user),
   so all access comes through the group. Set up the CLI as in
   [Switching between accounts](#switching-between-accounts).
2. **Cost allocation tags:** Billing → Cost allocation tags → activate
   `project`, `env` and `owner` (they appear about a day after the first
   tagged resource).
3. **Cost Anomaly Detection:** check that an AWS services monitor exists
   and that its alerts go to the budget mailbox.
4. **Check it works:**
   ```sh
   aws cloudtrail get-trail-status --name org-bootstrap   # IsLogging: true
   aws organizations list-delegated-administrators
   ```
   In the audit account: the Config aggregator `org-bootstrap` lists every
   account, and IAM Access Analyzer's `org-bootstrap` analyzer is active.

### 6. Project CI (later, per project account)

A project that deploys into one of these accounts gets its CI access from
the governance CI bootstrap (`.governance/templates/aws/github-ci-bootstrap.yaml`),
deployed by an administrator in that account as the
[AWS CI bootstrap standard](../../.governance/standards/security/aws-ci-bootstrap.md)
describes. That's per project, not part of this bootstrap.

## Switching between accounts

**In the browser:** the AWS access portal lists every account with its two
roles; pick one to open the console there. Open several accounts side by
side in separate browser profiles or containers.

**On the command line** (AWS CLI v2, on your laptop): one sign-in covers every
account. Generate the profiles in CloudShell, as an administrator:

```sh
python3 org_bootstrap.py sso-config --out controls-poc.aws-config
# portal with a custom alias:  --start-url https://<alias>.awsapps.com/start
```

Download the file (Actions → Download file) and append it on your laptop:

```sh
cat controls-poc.aws-config >> ~/.aws/config
aws sso login --sso-session controls-poc          # opens the browser, once per session
aws sts get-caller-identity --profile controls-poc-audit-readonly
```

Profiles are named `controls-poc-<account>-<role>`:

| Account | Admin | Read-only |
|---|---|---|
| management | `controls-poc-management-admin` | `controls-poc-management-readonly` |
| log-archive | `controls-poc-log-archive-admin` | `controls-poc-log-archive-readonly` |
| audit | `controls-poc-audit-admin` | `controls-poc-audit-readonly` |
| preview | `controls-poc-preview-admin` | `controls-poc-preview-readonly` |
| analytics | `controls-poc-analytics-admin` | `controls-poc-analytics-readonly` |

Switch per command with `--profile`, or for the whole shell:

```sh
export AWS_PROFILE=controls-poc-preview-admin
aws configure list-profiles | grep controls-poc   # everything you can switch to
```

Prefer `readonly` unless you're changing something. The token from
`aws sso login` lasts for the Identity Center session (8 hours by default);
each role session lasts its permission set's duration and is renewed
silently while the token is valid. `aws sso logout` ends it. The file
holds account IDs only, no credentials; keep it out of the repository.
`sso-config` is read-only and never overwrites a file. Re-run it after
adding an account or a permission set.

## Not included, on purpose

| Not included | Why | Where it goes |
|---|---|---|
| SCPs and RCPs (region deny, protecting the trail and Config, break-glass) | They're what the onboarding tool generates and verifies | The tool's delivery bundle, composed onto this organization |
| AWS Control Tower | Its own SCPs and Config rules would mix with the tool's and use up the SCP quota the tool's Compose stage budgets | ADR-0013 |
| Security Hub, GuardDuty | Cost; nothing reads them until the Validate stage | A config change and a PR when Validate needs them |
| KMS for the log bucket, S3 Object Lock | Cost and teardown friction in a test organization | Production organizations |
| `BreakGlass-Responder` roles | Belong to the break-glass design the tool's ORG baseline protects | With the Validate stage |

## Before the tool's guardrails go on

The tool's ORG-S-02 denies changing Config recording to everyone but
break-glass and the request's `platform_principals`
([ADR-0014](../../docs/adr/0014-close-workload-escape-paths.md)). The
Config StackSet deploys to each member account through the role
CloudFormation creates there, `stacksets-exec-*`, which SCPs bind. So in
every onboarding request for this organization:

- list that role once per member account in `platform_principals`, as
  `arn:aws:iam::<account-id>:role/stacksets-exec-*`;
- give each role's ARN and trust policy in `org_state.roles`, so Review can
  check who may assume it. Without one, Review asks a person.

Otherwise the next StackSet update, or auto-deployment to a new account,
fails on the deny. The management account's own stack needs nothing: SCPs
don't bind the management account. Members also can't leave the
organization (ORG-C-07), which teardown doesn't need: it closes accounts from
the management account.

## Changing it

Edit `organization.json` or a template in a pull request (tests:
`python3 -m unittest tests.test_org_bootstrap`), then an administrator
runs `plan` and `apply`. A new account needs `--email-template` again.
Adding a region to `config_regions` deploys the recorder there too; only
`ca-central-1` and `us-east-1` are allowed (AWS platform standard).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ACCOUNT_NUMBER_LIMIT_EXCEEDED` | New organizations can start with a low account quota. Request an increase in Service Quotas (AWS Organizations), then re-run `apply` |
| `EMAIL_ALREADY_EXISTS` | That email is another AWS account's root email, or an interrupted `apply` is still creating the account: wait a few minutes and re-run (it finds the account by name). Otherwise use another template |
| `AccessDenied` assuming `OrganizationAccountAccessRole` right after account creation | The new account is still being set up. Wait a few minutes and re-run `apply` |
| A stack in `ROLLBACK_COMPLETE` | Read its events, fix the cause, delete the stack (turn off termination protection first) and re-run |
| Config StackSet instance failed with "maximum number of configuration recorders" | Someone enabled Config in that account by hand; delete that recorder and re-run |
| `IAM Identity Center isn't enabled ... in ca-central-1` | Enable it (step 3) in ca-central-1. An instance enabled in another region can't be moved: delete it and enable it again in ca-central-1 |
| Creating the group fails | Your identity source is an external IdP (Entra ID, Okta), whose groups are provisioned by SCIM. Create `controls-poc-admins` there, let it sync, and re-run |
| `aws sso login` works but a profile says `ForbiddenException` | You aren't in `controls-poc-admins` yet, or the assignment is still provisioning; check the access portal |
| `warning: permission set ... also has ...` | Someone attached a policy by hand. The bootstrap doesn't remove it; review it in the console |

## Cost when idle

An estimate, not a quote; prices weren't checked live:

| Item | Idle cost |
|---|---|
| Organizations, IAM Identity Center, Access Analyzer (external access), tag policy, StackSets, budget | No charge |
| Organization trail | First copy of management events is free; S3 storage of a few MB a month |
| AWS Config, 5 accounts, daily recording | A few dollars for the first inventory, then cents a month while nothing changes |
| S3 log bucket | Cents a month at test-organization volume |

Expect **under USD 5 a month** idle; the budget alerts at USD 12.50.
Nothing is billed by the hour.

## Tearing it down

Close the member accounts (`aws organizations close-account`; AWS limits
how many can be closed in 30 days, and closed accounts stay suspended for
90 days), then delete the stacks (turn off termination protection), then
close the management account. The log bucket is retained by design and
its policy denies deleting logs; closing the log-archive account removes
it with the account. To empty it sooner, delete the bucket policy from the
log-archive account first.
