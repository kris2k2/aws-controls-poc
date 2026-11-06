# ADR-0014: Close the paths a workload's own IAM permissions open around the guardrails

- **Status:** proposed
- **Date:** 2026-11-06
- **Deciders:** repository owner and security team (pending review)

## Context

ADR-0003 proves that each generated statement denies exactly what its
security property says. It doesn't show that the properties together cover
every way out. Probing the generated Athena policies with the local
evaluator, with a workload that holds broad IAM permissions but never
touches a protected role, found these paths:

- **Leaving the organization.** No guardrail denied
  `organizations:LeaveOrganization`. A member principal can call it with IAM
  permissions alone, once the account meets AWS's standalone-account
  prerequisites, and every SCP and RCP stops applying.
- **Becoming an outside principal.** ORG-C-02 covers S3 only. A workload
  could assume a role in an account it controls outside the organization,
  where no SCP binds it, and use any service from there.
- **Letting outsiders in.** The RCP (ORG-C-03) covers S3 and KMS only. A
  workload could trust an outside account in a role's trust policy, or share
  an SQS queue or a Secrets Manager secret through its resource policy. STS,
  SQS and Secrets Manager are RCP-supported (verified 2026-11-06).
- **Blinding detection.** ORG-S-02 denied stopping and deleting the Config
  recorder, but not overwriting it (an empty recording group records
  nothing), changing its resource types, moving its delivery channel or
  shortening retention. ORG-S-01 didn't deny `cloudtrail:CreateTrail`, and a
  new trail can deliver to a bucket outside the organization: CloudTrail
  writes as a service principal, which no SCP or RCP binds.
- **Becoming break-glass.** Review accepted a break-glass trust policy that
  trusts the account root with MFA required. In that account, anyone allowed
  to create an IAM user and an MFA device could then assume break-glass.

Off the organization's endpoints, organization credentials could also reach
outside resources of services other than S3. AR-05 covered only
third-party credentials.

## Decision

1. **ORG-C-07 (SCP, Containment, Critical):** deny
   `organizations:LeaveOrganization`. Break-glass isn't exempt: leaving is
   never how to recover from a guardrail, and it would take break-glass out
   of the data perimeter.
2. **ORG-C-08 (SCP, Containment, High):** deny `sts:AssumeRole` when the
   role is outside the organization and its account isn't in
   `trusted_resource_accounts`. The condition fails closed: a role in a
   standalone account has no `aws:ResourceOrgID`. Break-glass isn't
   exempt, as for the rest of the data perimeter.
3. **ORG-C-09 (RCP, Containment, Critical):** on `sts:AssumeRole`, `sqs:*`
   and `secretsmanager:*`, deny every caller that is neither an
   organization principal, an AWS service, nor in a new optional request
   field, `trusted_principal_accounts` (empty by default: no outside
   account). Only `AssumeRole` is covered: `AssumeRoleWithSAML` and
   `AssumeRoleWithWebIdentity` (IAM Identity Center, GitHub OIDC) carry no
   organization ID and stay open. Review asks a person about every trusted
   principal account.
4. **ORG-S-01 and ORG-S-02** deny every action in the AWS service reference
   that stops, narrows or redirects recording or trail delivery
   (`cloudtrail:CreateTrail`; `config:PutConfigurationRecorder`,
   `PutDeliveryChannel`, `AssociateResourceTypes`,
   `DisassociateResourceTypes`, `PutRetentionConfiguration`,
   `DeleteRetentionConfiguration`). Organizations deploy Config with an
   ordinary IAM role that SCPs bind, such as the role a service-managed
   StackSet uses in each member account. So a new request field,
   `platform_principals` (role ARNs in named accounts, like break-glass), is
   exempt from these two controls only. The guardrail sets
   `platform_exempt: true`. Platform roles join the protected roles: ORG-C-04
   stops anyone but break-glass creating, changing or passing them, and
   Review checks their trust policies like break-glass's, without requiring
   MFA.
5. **Trust policies naming a whole account block.** Review rejects a
   break-glass or platform trust policy whose AWS principal is an account
   root or a bare account ID: it must name the principals.
6. **AR-05 widens** to the organization-credential path off the endpoints,
   for services other than S3. A deny on outside resources for every service
   would break AWS-owned resources and services that don't set
   `aws:ResourceOrgID`. The path belongs to network egress controls. ORG-C-08
   bounds it: those principals can't assume roles outside the organization,
   so the SCPs still bind them.
7. **The attacker model follows AWS on unsigned requests.** The IAM
   condition-key reference says of `aws:PrincipalIsAWSService`: "Anonymous
   requests do not include this key." The model set it on every request, so
   the proof couldn't tell `BoolIfExists` from `Bool` on that key. With the
   model corrected, it catches that mutant for ORG-C-03 and ORG-C-09. The
   ORG-C-03 equivalent-mutant entry is dropped, as the test requires once a
   listed mutant is caught. The model's actions now include SQS and Secrets
   Manager.

Each new or changed control has its property in `onboard/specs/organization.py`,
written from its objective, with request vectors in the journey test and
named attacks A21 to A32. A separate adversarial scenario names a trusted
principal account, so ORG-C-09's `aws:PrincipalAccount` condition is proved
and mutated too.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| New ORG controls, a platform exemption, and AR-05 widened (chosen) | Each path closed where an organization policy can close it; every deny proved; Config deployment keeps working | Two new request fields; platform roles are a new exemption to review |
| Deny the Config and CloudTrail changes to everyone but break-glass | No new exemption | Config setup in a new account, and every StackSet update, needs a break-glass session |
| Detect, don't deny, the Config and CloudTrail changes | No breakage | The gap stays open; detection reads the same logs being tampered with |
| Widen ORG-C-02 to every data service | Closes more off-endpoint egress | Each service's condition-key support needs checking; breaks AWS-owned resources and legitimate cross-organization use |
| Extend ORG-C-03 to STS, SQS and Secrets Manager with a trusted list | One RCP statement | Adds an exception to the S3/KMS perimeter, which weakens a reviewed property |
| RCP with no trusted principal accounts | Simpler | Any vendor integration that assumes a role needs a policy change |

## Consequences

- The Athena journey now generates 9 SCP, 2 RCP and 2 endpoint deny
  statements at Private Preview and 10, 2 and 2 from Contained. Verify proves
  13 statements at Private Preview and 14 later.
- Review asks one impact replay per new organization deny, and the replay
  answers them. Across the journey a person still makes 4 decisions
  (ADR-0012). A request that names trusted principal accounts adds one.
- Members can no longer create trails, or set up or change Config, unless
  the request names the role that does it in `platform_principals`. Platform
  principals name an account each, like break-glass, so an organization
  lists the role in each account it deploys to.
- Organization principals can no longer assume roles in outside accounts
  unless those accounts are in `trusted_resource_accounts`. Some AWS
  services may ask a caller to assume an AWS-owned role: calibrate before
  deploying.
- Outside accounts can no longer assume organization roles, or reach its
  queues and secrets, unless named in `trusted_principal_accounts`.
- Break-glass trust policies that trust the account root now block. They
  must name the responders' principals.
- Not verified: that STS sets `aws:ResourceOrgID` and `aws:ResourceAccount`
  on `AssumeRole`. ORG-C-08's citation is `not-run` until calibration.
- Still open: a role or user named in a break-glass trust policy isn't
  protected, so a workload that can take it over can still become
  break-glass. Organization credentials off the endpoints still reach
  outside resources of services other than S3 (AR-05).
- The new properties, the platform exemption, the widened AR-05 and the
  dropped equivalent mutant need security team review and sign-off.
