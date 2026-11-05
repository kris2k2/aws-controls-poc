# ADR-0009: Generate renders Config rules, CloudTrail detections and Sentinel policies from structured definitions

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

Every control declares its Config, CloudTrail and Sentinel implementations,
but only in prose (`"rule": "custom Guard: ResultConfiguration.ExpectedBucketOwner set"`,
`"detects": "the denied Spark and notebook actions"`). Generate reported all
of them as `pending`, so Review always doubted them and the delivery bundle
said it didn't hold them (ADR-0008). Prose can't be rendered without guessing,
and a guessed rule name or event field fails silently: the rule never fires.

The tool spec (draft v0.1) lists these artifacts but isn't in this
repository. This ADR records the formats chosen from the ADRs, the Athena
journey and AWS's documentation, for review.

## Decision

1. **A structured definition sits next to the prose.** A planned
   implementation may carry one; without it, the artifact stays `pending`
   with that reason. Nothing is derived from the prose.
   - `config`: exactly one of `managed` (an AWS managed rule identifier,
     resource types, parameters), `guard` (a resource type and checks on the
     configuration item) or `security_hub_control` (enable the Security Hub
     control; its AWS-managed Config rule evaluates). Assess sets
     `security_hub_control` on every Security Hub import.
   - `cloudtrail`: `match`, an EventBridge pattern for the `detail` of
     "AWS API Call via CloudTrail" events. It must filter on `eventSource`.
     It can use `${parameters}` from the request, `optional_parameters`, and
     `requires`, for prerequisites such as S3 data events on the trail.
   - `sentinel`: `plan`, the Terraform resource types and either `forbid` or
     checks on each created or updated resource's `after` values.
   - Checks are one small language: `exists`, `equals`, `in`, `not_in`
     (Sentinel only), `not_empty` and `has_tag`, on a path of field names and
     list indexes. `detective.evaluate` gives each check its meaning on a
     configuration item or a plan resource, and the tests use it.
2. **Formats.** Config: `AWS::Config::ConfigRule` properties; a Guard rule
   uses runtime `guard-2.x.x` and is triggered on configuration changes.
   CloudTrail: `AWS::Events::Rule` properties with state
   `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`; without it EventBridge
   skips read-only calls such as `GetSessionEndpoint`. Sentinel: a `tfplan/v2`
   policy per control, plus `sentinel.hcl` for the set. An undefined value is
   `null`, so a missing attribute fails a check rather than erroring.
   JSON artifacts carry the control's ID, title, mode, severity and whether it
   is shared. They are written under `detective/` in the run.
3. **Mode decides Sentinel's level and nothing else.** Enforce is
   `hard-mandatory`, Enforce with override is `soft-mandatory` (the meaning
   finding F11 proposes; still to be confirmed), and Advise and Report are
   `advisory`. A hand-written `level` is refused. Config rules and detections
   are rendered in every mode: they detect, and routing follows the mode and
   severity they carry.
4. **Parameters with patterns become wildcard filters.** Break-glass
   principals are ARN patterns (`role/BreakGlass-*`); an exact-match pattern
   would never fire. A `*` value becomes an EventBridge `wildcard` filter.
   A `?`, or a pattern inside `anything-but`, can't be expressed, so
   Generate fails. An empty optional parameter drops the `$or` branch that
   uses it. If nothing is left, the detection is `not_deployed` with the
   reason, as a guardrail on no resources is.
5. **The artifacts are released like the policies.** `generation.json`
   lists each file's SHA-256. Review re-runs Generate and blocks on any
   changed, missing or extra file. It records the hashes it releases, and
   raises a Low doubt that the artifacts haven't run in AWS Config,
   EventBridge or Sentinel. Deliver seals them under `detective/`, and
   `check-delivery` requires exactly the reviewed set. An enforcing control
   with no guardrail keeps its "unenforced" doubt even with a Sentinel
   policy, which stops only what Terraform plans.
6. **Facts are checked, not remembered.** The managed rule identifiers used
   for Athena were checked against AWS Config's managed rule list
   (2026-11-05): `ATHENA_WORKGROUP_*`, `MULTI_REGION_CLOUD_TRAIL_ENABLED`.
   `tagged-athena-workgroup` and `tagged-athena-datacatalog` couldn't be
   confirmed, so ATH-H-01 and ATH-H-02 enable Security Hub Athena.3 and
   Athena.2 instead. The denial wording matched in error messages ("explicit
   deny in a service control policy", "... in a VPC endpoint policy") is
   from IAM's access-denied troubleshooting page. Guard paths use
   CloudFormation property names under `configuration`, as AWS's own Athena
   managed rules do.

## Consequences

- At Hardened, Athena gets 12 Config rules, 14 detections and 12 Sentinel
  policies (39 files with `sentinel.hcl`). Nine stay pending, each with its
  reason. Config can't judge "resources outside allowed regions", a
  recorder's resource types, or an endpoint's policy document, and neither
  check is written for Sentinel. Provider regions need `tfconfig`.
  ORG-C-04's role changes need per-type role attributes and `before` values.
- Detections watch the guardrail's own actions. A test requires every API
  action a guardrail denies to appear in its detection's event names
  (finding F13's kind of drift).
- What isn't known yet, and is recorded on each run (`detective_notes`) or
  here:
  - EventBridge rules are regional, so each must be deployed in every
    enabled Region. Config rules evaluate one account and Region.
  - Whether AccessDenied calls reach EventBridge isn't documented on the
    pages read. S3 denials carry "Access Denied" without the policy type, so
    ORG-C-02 and ORG-C-03 match every S3 denial.
  - Guard paths, Terraform attributes and event fields haven't been checked
    against real configuration items, plans or events.
  - These are Level 2 checks (a disposable account, `cfn-guard`,
    `sentinel test`).
- Detections, unlike guardrails, have no independent security property: the
  tests check them against events written for the control, not against a
  spec. A spec for detections would be the next step if they ever gate a
  release.
- Placement per account, Region and OU is still Compose's job.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Structured definitions per control (chosen) | Nothing guessed; the analyst writes what a reviewer can check; the same checks render Guard and Sentinel | More fields in each control; definitions must be kept with the guardrail (tested for event names) |
| Derive detections from guardrails | No extra data | IAM action names aren't always CloudTrail event names (`s3:ListBucket` is `ListObjects`), and event sources aren't always `<prefix>.amazonaws.com` (finding F3) |
| Parse the prose | No schema change | Fragile, and a wrong guess fails silently |
| CloudWatch metric filters or CloudTrail Lake queries instead of EventBridge | Cross-Region from one trail | Ties detections to one log destination; EventBridge patterns can be tested offline as JSON |
