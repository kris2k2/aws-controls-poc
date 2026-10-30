# Simulated onboarding: Amazon Athena at Private Preview

A dry run of the onboarding tool on a real service, used to test the spec and
the code before the later stages exist. Sections follow the spec's
`report.md` layout.

| | |
|---|---|
| Date | 2026-10-30 |
| Request | synthetic: `Amazon Athena`, Private Preview, preview account `111122223333`, criticality Moderate (default), `ca-frfi-global`, empty `org_state` |
| Tool version | 0.1.0 (request validation, control model, Resolve only) |
| Source | AWS service reference, retrieved 2026-10-30, snapshot in `tests/fixtures/service-reference/2026-10-30/` |
| Regression test | `tests/test_athena_acceptance.py` |

**How to read this.** Statements marked **[tool]** come from the tool's
output and are pinned by the acceptance test. Everything else is
**[simulated]**: an analyst walking the stages the tool does not have yet.
Those statements are *unverified*. The spec's verification pass (re-fetch and
confirm each citation) has not run on them, and they must not be used as
controls until it has.

## 1. What the tool produced [tool]

`check-request` accepted the request with the documented defaults. `resolve`
wrote `capability-profile.json`:

| | |
|---|---|
| Prefixes | `athena` (no related prefixes to confirm) |
| Actions | 81: 33 write, 2 tagging, 34 read, 12 list, 0 permission management |
| Resource types | `workgroup`, `datacatalog`, `capacity-reservation`, `session` |
| Condition keys | `aws:RequestTag/${TagKey}`, `aws:ResourceTag/${TagKey}`, `aws:TagKeys` only |
| Cross-prefix actions in operations | `iam:PassRole` (from `StartSession`) only |
| Data-plane actions | none annotated |

## 2. Findings for the spec and the tool

These are the point of the exercise. F1 to F4 are facts in the tool's output
[tool]; what they imply is [simulated].

| # | Finding | Consequence | Proposed change |
|---|---|---|---|
| F1 | Athena has **no service-specific condition keys**, only the global tag keys. | Organization policies can't express workgroup-level controls: result location, encryption, enforced workgroup configuration, engine type. Those become configuration-state controls (Config and Sentinel); the policy can only deny whole actions. | Resolve should flag "no service condition keys". Select should then route configuration controls to Config and Sentinel, and keep guardrails to action-level denies. |
| F2 | The contract **doesn't show Athena's real dependencies.** `StartQueryExecution` authorizes only `athena:StartQueryExecution`. Queries also read and write S3, the Glue Data Catalog and KMS (and Lake Formation where it's used) as the caller [simulated]. | In a default-deny organisation, an allow-list built from Resolve admits `athena:*` but not `glue:*`. Athena would then fail at runtime, and the containment that matters (who can read the data) lives in S3, Glue and KMS policies, not Athena's. | Resolve needs a second dependency source: the service's Security chapter, plus a curated, cited dependency map in the registry. Prerequisites and Compose must check that the dependency prefixes are on the allow-list. |
| F3 | **No action is annotated `IsDataPlane`**, not even `StartQueryExecution` or `GetQueryResults`. | Data-event selectors can't be derived from this annotation. Athena API calls are expected to be management events [simulated]; the data access shows up as S3 data events. | Don't use `IsDataPlane` alone for CloudTrail selection; take the event type from the CloudTrail documentation per service. |
| F4 | **Risk tiers don't single out egress or sharing features.** `CreateDataCatalog`, `CreatePresignedNotebookUrl`, `ExportNotebook` and `StartSession` are ordinary "write". | The tool can't find "no external sharing" and "no data egress" candidates from the contract. | Add an egress and sharing feature catalog per service: reasoned, logged in `decision-log.jsonl`, checker-approved. Possibly seeded from the Security chapter. |
| F5 | **Containment of an analytics service mostly sits in shared controls** on S3, Glue and KMS (identity and resource perimeter) [simulated]. | Private Preview "contained by existing controls plus what is missing" depends on dependency controls the spec doesn't put in scope for this service. | Make dependency containment controls in scope at Private Preview when the dependency carries the service's data. Reuse them from the registry; never duplicate them. |
| F6 | **The network perimeter is a design choice, not a default** [simulated]. Athena supports VPC interface endpoints, but denying `athena:*` outside `aws:SourceVpce` blocks console use from outside the VPC. Athena's own calls to S3 need an `aws:ViaAWSService` carve-out. | "Containment is never permissive" forces Enforce, so the analyst must choose: VPC-only access (a prerequisite in each preview account) or recording the objective as not applicable with a reason. | Add a "network perimeter: endpoint-only or not applicable" decision to the request, approved by the checker. |
| F7 | **Regional availability isn't checked yet.** Athena is expected in `ca-central-1` and `eu-west-1`, so no `us-east-1` exception is needed [simulated]. | The region policy can't be confirmed by the tool. | Already planned (Resolve). |
| F8 | `data_classification` has no mapping to criticality in the spec. | Escalation can't be implemented. | Spec decision needed. |

## 3. Containment coverage at Private Preview [simulated]

With an empty `org_state`, nothing is covered by an existing policy. In a real
run, the shared controls (region, data perimeter) would come from the
registry.

| Objective | Status | Control |
|---|---|---|
| Preview accounts only | New | ATH-C-01 |
| Region containment | Shared (org-wide region deny) | REG-01 (registry) |
| Identity perimeter | Not applicable to Athena resources (no resource-based policies) [unverified]; Athena isn't on the RCP-supported list [unverified, check per run]. Covered through dependencies | S3/KMS RCP `aws:PrincipalOrgID` (shared, F5) |
| Resource perimeter | Dependency: query results, `UNLOAD` and CTAS write to S3 as the caller [unverified] | S3 SCP `aws:ResourceOrgID` (shared, F5) |
| Network perimeter | Decision needed (F6) | ATH-C-05 (proposed) |
| No external sharing paths | New: presigned notebook URLs, notebook export, cross-account data catalogs | ATH-C-03, ATH-C-04 |
| No data egress features | New: federated query through Lambda connectors (`CreateDataCatalog` with type `LAMBDA`), Spark sessions | ATH-C-03, ATH-C-04 |
| No provider data use | Not applicable: Athena isn't covered by the AI services opt-out policy [unverified] | none |

## 4. Proposed control set [simulated]

All are Containment class, so every one is **Enforce** at Private Preview
whatever its severity (tested in `test_model.py`). Severities come from the
rubric and are inferred, so High and Critical need the checker.

| Control | What | SCP | Detective | Sentinel | Severity (inferred) |
|---|---|---|---|---|---|
| ATH-C-01 | Athena usable only from preview accounts | Deny `athena:*` unless `aws:PrincipalAccount` is a preview account; break-glass exempt | CloudTrail: denied `athena:*` calls from other accounts | Not expressible: the plan doesn't reliably carry the target account | High |
| ATH-C-03 | No federated or cross-account data catalogs | Deny `athena:CreateDataCatalog`, `athena:UpdateDataCatalog` (no condition key tells catalog types apart, F1) | Config: `AWS::Athena::DataCatalog` present [unverified resource type]; CloudTrail: the two actions | Forbid `aws_athena_data_catalog` (hard-mandatory) | High |
| ATH-C-04 | No Spark notebooks or sessions | Deny `athena:StartSession`, `StartCalculationExecution`, `CreateNotebook`, `ImportNotebook`, `ExportNotebook`, `CreatePresignedNotebookUrl`, `GetSessionEndpoint` | CloudTrail: those actions | Forbid workgroups whose engine is Spark (hard-mandatory) | High |
| ATH-C-05 | Access through the VPC endpoint only (if F6 is chosen) | Deny `athena:*` unless `aws:SourceVpce` is listed or `aws:ViaAWSService` is true | CloudTrail: calls without `vpcEndpointId` | Not expressible | Medium |

`capabilities_excluded` for this run would list "federated and cross-account
data catalogs" and "Spark notebooks and sessions". The report shows them, so
the preview users know what's switched off.

Illustrative guardrail for ATH-C-01 and ATH-C-04. Placeholders are synthetic.
This is unverified and not generated by the tool:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ATHC01PreviewAccountsOnly",
      "Effect": "Deny",
      "Action": "athena:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {"aws:PrincipalAccount": ["111122223333"]},
        "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass-*"}
      }
    },
    {
      "Sid": "ATHC04NoSparkNotebooks",
      "Effect": "Deny",
      "Action": [
        "athena:StartSession", "athena:StartCalculationExecution", "athena:CreateNotebook",
        "athena:ImportNotebook", "athena:ExportNotebook", "athena:CreatePresignedNotebookUrl",
        "athena:GetSessionEndpoint"
      ],
      "Resource": "*",
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlass-*"}}
    }
  ]
}
```

Allow-list: `athena:*` at every level of the preview accounts' path. Under F2,
`glue:*`, `s3:*` and `kms:*` must already be allowed, or the preview doesn't
work.

## 5. Prerequisites [simulated]

- An S3 bucket in the organisation for query results in each preview account
  (also needed for the resource perimeter).
- Glue Data Catalog databases and tables for the preview data; Lake Formation
  permissions if Lake Formation is in use.
- If F6 picks endpoint-only access: an `athena` VPC interface endpoint in each
  preview account.

## 6. Next tier: what Contained would add [simulated]

Supervision controls, each Enforce with override at least:

- Workgroups enforce their configuration, so clients can't override the
  result location or encryption.
- Query results encrypted with customer-managed KMS keys; the expected bucket
  owner is set on the result location.
- CloudTrail detections for every containment control above; denied attempts
  count as evidence that a guardrail holds.
- Config recording of Athena workgroups and data catalogs in each allowed
  region.

Candidate AWS-mapped controls (Security Hub and Control Catalog) for Athena
workgroups would be pulled by Assess. None were looked up for this
simulation.

## 7. End-state tests this run would generate [simulated]

In a disposable account under the test OU:

- A query in a preview account succeeds in `ca-central-1` and `eu-west-1`,
  with results written to the organisation bucket.
- The same call from a non-preview account fails with an explicit SCP deny.
- `CreateDataCatalog`, `StartSession` and `CreatePresignedNotebookUrl` fail
  with an explicit deny; break-glass succeeds and is detected.
- A query in a disallowed region fails.
- `UNLOAD` to a bucket outside the organisation fails (resource perimeter,
  F5).

## 8. Process-only and out of scope

Contracts and third-party risk for Athena (OSFI B-10), and the data
classification of preview data beyond the maker's non-production
attestation.
