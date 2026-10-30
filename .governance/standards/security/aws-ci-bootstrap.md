# AWS CI Bootstrap Standard

Every AWS project gets its CI access from one CloudFormation stack,
[`templates/aws/github-ci-bootstrap.yaml`](../../templates/aws/github-ci-bootstrap.yaml),
deployed by a human administrator. It sets up the trust between the AWS
account and GitHub Actions and knows almost nothing about the project:

| The bootstrap knows | The bootstrap doesn't know |
|---|---|
| A project slug (stack name and IAM path) | The project's resources, architecture, or templates |
| The GitHub org/repo (and their numeric IDs), and the allowed OIDC subject | Branch names beyond the subject, build tooling |
| Which AWS actions the project's stacks manage | Anything that changes per deploy |
| Optionally, what CI does outside CloudFormation (e.g. upload a built site) | |
| Which regions it may use (default `ca-central-1`, then `us-east-1`) | |

Everything else lives in the project's own stacks, which CI deploys.

## The model

```
GitHub Actions ──OIDC──► CI role ──CreateChangeSet(--role-arn exec)──► CloudFormation ──as──► execution role ──► project resources
                         (no resource                                                         (AllowedActions)
                          permissions)
            both roles, and every role they create, carry the same permissions boundary
```

1. **GitHub OIDC provider** (or the account's existing one). CI gets
   short-lived credentials per run. There are **no long-lived access keys**,
   anywhere.
2. **CI role** `/bootstrap/<project>-github-ci`. It's assumable only by
   tokens whose `sub` matches the repository and `SubjectFilter`, with
   audience `sts.amazonaws.com`. It holds **no resource permissions**. It can
   create change sets on the project's stacks only when they run as the
   execution role, execute and inspect them, and pass the execution role to
   CloudFormation. Optionally it gets `CiDirectActions` on
   `CiDirectResources` for work done outside CloudFormation, such as
   uploading a built site and invalidating the CDN.
3. **Asset stores**: an S3 bucket `<project>-assets-<account>-<region>`
   (and optionally an ECR repository `<project>-assets`) in each region the
   project deploys to. CDK publishes Lambda code, Docker images, and
   templates here. Only CI can write to them, and the boundary stops
   anyone in the project from reconfiguring or deleting them.
4. **CloudFormation execution role** `/bootstrap/<project>-cfn-exec`.
   Only CloudFormation can assume it. It holds `AllowedActions`, which is
   what the project's stacks manage.
5. **Permissions boundary** `/bootstrap/<project>-ci-boundary`, on both
   roles and required on every role they create:

| Guard | Effect |
|---|---|
| `ProjectServices`, `DeployMechanics`, `CiDirectActions` | The only actions possible at all. Everything else is implicitly denied. |
| `StayInAllowedRegions` | Regional services only in `AllowedRegions` (default: the bootstrap's region). |
| `IamWritesOnlyUnderProjectPath` | IAM writes only on `role/`, `policy/`, `instance-profile/` under `/<project>/`, plus service-linked roles. No users, groups, access keys, OIDC/SAML providers, account settings, or bootstrap resources (`/bootstrap/`). |
| `PassOnlyBoundedRoles` | `iam:PassRole` only for `/<project>/` roles and the execution role, all of which carry the boundary. |
| `RolesOnlyWithThisBoundary` | Creating a role, or changing its policies, requires the role to carry this boundary. |
| `BoundaryCannotBeRemoved` | No deleting permissions boundaries. |
| `AssumeOnlyProjectRoles` | `sts:AssumeRole` only into `/<project>/` roles. |
| `StacksOnlyWithProjectName` | CloudFormation writes only on stacks named `<project>` or `<project>-*` (plus AWS transforms such as SAM). |
| `ProtectThisBootstrapStack` | No CloudFormation action on the bootstrap stack, in any region, even if its name matches. |
| `ProjectAssets`, `ProtectAssetStores` | Publishing to and reading from the asset stores; no deleting or reconfiguring them. |
| `NoStackSetsOrRegistryTypes` | No StackSets or registry types/hooks, which run under their own roles and would sidestep the boundary. |
| `NoAccountOrGuardrailTampering` | No Organizations/account changes; no stopping CloudTrail, Config, GuardDuty, Security Hub, Access Analyzer; no editing budgets. |

[`tools/tests/test_ci_bootstrap.py`](../../tools/tests/test_ci_bootstrap.py)
evaluates each role's effective permissions (its own policy intersected
with the boundary) against concrete scenarios: escalation attempts must
fail, and normal deploys must succeed.

## OIDC subjects: use the immutable form

Since 2026-07-15, GitHub puts **immutable numeric IDs** in the OIDC `sub`
claim for repositories that are created, renamed, or transferred after that
date, or that opt in:

```
repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:production
```

A trust policy that matches only `repo:OWNER/REPO:…` fails for those
repositories. It's also weaker: a deleted and recreated repository with the
same name would match it. Always pass `GitHubOwnerId` and `GitHubRepositoryId`
(`gh api repos/OWNER/REPO --jq '.owner.id, .id'`), and opt older
repositories into immutable subjects in their OIDC settings. Leave the IDs
empty only for an older repository that hasn't been migrated yet.

## Deploying it (human administrator, once per account and project)

Use administrator credentials from your identity provider (IAM Identity
Center), never from CI. Deploy the full bootstrap in the home region
(`ca-central-1`), then the regional asset store, **under the same stack
name**, in each other region the project uses:

```sh
# 1. Home region: OIDC, roles, boundary, ca-central-1 asset bucket
aws cloudformation deploy --region ca-central-1 \
  --stack-name ci-bootstrap-shop \
  --template-file templates/aws/github-ci-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProjectName=shop GitHubOrg=example-org GitHubRepo=shop \
      GitHubOwnerId=1111111 GitHubRepositoryId=2222222 \
      SubjectFilter=environment:production \
      AllowedActions='cloudformation:*,iam:*,lambda:*,apigateway:*,dynamodb:*,s3:*,logs:*,ssm:*Parameter*'

# 2. Alternate region, only if the project deploys there: asset bucket only
aws cloudformation deploy --region us-east-1 \
  --stack-name ci-bootstrap-shop \
  --template-file templates/aws/github-ci-bootstrap.yaml \
  --parameter-overrides ProjectName=shop GitHubOrg=example-org GitHubRepo=shop \
      RegionalAssetsOnly=true

for r in ca-central-1 us-east-1; do
  aws cloudformation update-termination-protection --region "$r" \
    --stack-name ci-bootstrap-shop --enable-termination-protection
done
```

- Name the bootstrap stack so it doesn't look like a project stack
  (`ci-bootstrap-<project>`). It's protected either way.
- Add `EnableImageAssets=true` when the project builds Docker images (Lambda
  container images, ECS).

- If the account already has the GitHub OIDC provider, pass
  `ExistingOidcProviderArn`. An account can hold only one per URL.
- Changing the project's scope (new services, regions, subjects, direct
  actions) is a PR to the project's bootstrap parameters, reviewed, then
  **redeployed by an administrator**. CI can't apply it, by design.
- After deploying, compare the `TrustedSubject` output with the `sub` in a
  workflow's token, and spot-check with the IAM policy simulator and Access
  Analyzer's `validate-policy`.
- The rendered boundary is about 4,800 of IAM's 6,144 characters with the
  default action list. Keep `AllowedActions` to service-level wildcards
  rather than long lists of individual actions.

## Using it from GitHub Actions

With CDK (recommended, see [AWS platform standard](../cloud/aws.md)):

```yaml
permissions:
  contents: read
  id-token: write          # required for OIDC

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: production  # matches SubjectFilter=environment:production
    concurrency: { group: deploy-production, cancel-in-progress: false }
    steps:
      - uses: actions/checkout@<sha>  # vX.Y.Z (tools/check_runtimes.py --pin actions/checkout)
        with: { persist-credentials: false }
      - uses: actions/setup-node@<sha>  # vX.Y.Z
        with: { node-version-file: .nvmrc, cache: npm }
      - run: npm ci
      - uses: aws-actions/configure-aws-credentials@<sha>  # vX.Y.Z
        with:
          role-to-assume: ${{ vars.AWS_CI_ROLE_ARN }}
          aws-region: ca-central-1
      - run: >-
          npx cdk deploy --all --require-approval never
          --role-arn "${{ vars.AWS_CFN_EXECUTION_ROLE_ARN }}"
```

The stacks use `projectStackProps()` from
[`project-guardrails.ts`](../../templates/aws/cdk/project-guardrails.ts), so
`cdk deploy` publishes assets with the CI role's credentials to the
bootstrap's asset buckets and assumes no `cdk-*` roles. No `cdk bootstrap`
is needed. [`templates/aws/cdk/`](../../templates/aws/cdk/) contains an example
app and `verify.mjs`, which CI runs to prove the synthesized output meets
these rules.

With plain CloudFormation:

```yaml
permissions:
  contents: read
  id-token: write          # required for OIDC

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: production  # matches SubjectFilter=environment:production
    concurrency: { group: deploy-production, cancel-in-progress: false }
    steps:
      - uses: actions/checkout@<sha>  # vX.Y.Z (tools/check_runtimes.py --pin actions/checkout)
        with: { persist-credentials: false }
      - uses: aws-actions/configure-aws-credentials@<sha>  # vX.Y.Z
        with:
          role-to-assume: ${{ vars.AWS_CI_ROLE_ARN }}
          aws-region: ca-central-1
      - run: >-
          aws cloudformation deploy --stack-name shop-api
          --template-file template.yaml --capabilities CAPABILITY_NAMED_IAM
          --role-arn "${{ vars.AWS_CFN_EXECUTION_ROLE_ARN }}"
          --no-fail-on-empty-changeset
```

- **`--role-arn` is mandatory** (for `cdk deploy` and `aws cloudformation
  deploy` alike). Without it the deploy fails with `AccessDenied`, because
  the CI role can't create change sets as itself.
- Protect the `production` environment in GitHub (required reviewers, deploy
  branch rule `main`) and use `SubjectFilter=environment:production`. Then
  only approved runs from `main` get credentials. Never use a subject that
  matches pull requests; the template rejects `*` and `pull_request`.
- With plain CloudFormation, templates over 51,200 bytes must be uploaded
  first: use `--s3-bucket <project>-assets-<account>-<region>`.
- Role ARNs aren't secrets; keep them in repository or environment
  **variables**.

## What project templates must do

Every IAM role, managed policy, and instance profile a project defines has:

```yaml
Path: /shop/
PermissionsBoundary: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/bootstrap/shop-ci-boundary"
```

With CDK, `applyProjectGovernance(app, "shop")` sets both on every role,
including the ones CDK creates internally, and fails synth if a stack name is
outside the project. (For SAM functions, set `RolePath` and
`PermissionsBoundary` on each function, or let SAM's `Globals` set the
boundary.) Stacks are named `shop` or `shop-…`. A deploy that misses any of these fails with `AccessDenied`.
That failure is the boundary working; fix the template, not the boundary.

## Worked example: static site on S3 + CloudFront

A site with an S3 origin, an ACM certificate, a CloudFront distribution with
functions and response-header policies, and Route 53 records, whose CI
uploads the built files and invalidates the cache. The origin bucket stays in
`ca-central-1`; only the certificate goes to `us-east-1`:

```
ProjectName=example-site                       # stacks "example-site" (ca-central-1), "example-site-cert" (us-east-1)
AllowedRegions=ca-central-1,us-east-1          # the default
AllowedActions=cloudformation:*,s3:*,acm:*,cloudfront:*,route53:*,ssm:*Parameter*,iam:*,lambda:*,logs:*
CiDirectActions=s3:ListBucket,s3:GetObject,s3:PutObject,s3:DeleteObject,cloudfront:CreateInvalidation,cloudfront:GetInvalidation
CiDirectResources=arn:aws:s3:::example-site-*-site,arn:aws:s3:::example-site-*-site/*,arn:aws:cloudfront::<account>:distribution/*
MaxSessionDuration=7200                        # first deploy waits on CloudFront
```

Deploy the regional asset store in `us-east-1` too, for the certificate
stack's template. CDK's `crossRegionReferences` passes the certificate ARN
between the regions through SSM parameters, using a small custom resource
with its own Lambda function and IAM role. That's why this example includes
`ssm:*Parameter*`, `iam:*`, `lambda:*` and `logs:*`; the boundary still gives
those roles the project path and boundary. A project whose stacks create no
IAM roles can leave out `iam:*`, and then neither CI nor the execution role
can touch IAM at all.

## Other roles a repository uses

Some workflows need AWS access that isn't deploying the project, such as a
translation job calling a shared Amazon Bedrock model. Those roles belong to
the platform that owns the shared service, not to the project's bootstrap.
They follow the same rules: OIDC only, immutable subject, never a
pull-request subject, least privilege, and an owner who reviews changes.

## Limits and recommendations

- **One account per project and environment** (AWS Organizations). The
  boundary scopes IAM and CloudFormation by name, but most other services
  (S3, CloudFront, Lambda, …) aren't scoped by name: with `s3:*` the
  execution role can touch any bucket in the account. Separate accounts make
  the scope "everything in this account", which is also the cleanest cost
  boundary (see [aws-cost.md](../efficiency/aws-cost.md)).
- Keep `AllowedActions` as narrow as the project allows. `ssm:*`, `kms:*`,
  `ec2:*`, and `lambda:*` in shared accounts need extra thought.
- **AWS CDK**: use `project-guardrails.ts`. CDK's default synthesizer
  assumes the `cdk-*` bootstrap roles, which `AssumeOnlyProjectRoles` blocks;
  don't run `cdk bootstrap` in project accounts.
- Runtime roles for the application are defined by the project, under its
  path and boundary. The bootstrap only provides the deploy path.
