# Test case: Amazon Athena from Private Preview to Hardened

Athena is the tool's first end-to-end test case: one service taken through all
three maturity tiers, with the outcomes tested at each step. Sections follow
the spec's `report.md` layout where they apply.

| | |
|---|---|
| Date | 2026-10-30 |
| Requests | `tests/fixtures/athena/request-{private-preview,contained,hardened}.json` (synthetic org `o-exampleorgid`, preview account `111122223333`, data classification Internal Restricted, criticality Moderate) |
| Candidate controls | `tests/fixtures/athena/findings.json`: 21 candidates, hand-written in place of Assess |
| API contract | AWS service reference snapshot, `tests/fixtures/service-reference/2026-10-30/` |
| Tests | `tests/test_athena_journey.py` (outcomes), `tests/test_athena_acceptance.py` (Resolve) |
| Run it | see [Reproduce](#reproduce) |

**How to read this.** Tier outcomes, modes and guardrail behaviour are tool
output, pinned by the tests. The candidate controls are not: Assess isn't
built, so an analyst wrote them. In `findings.json`, each fact marked
`verified` was checked against the cited AWS page on 2026-10-30. Every
NIST SP 800-53 mapping is `inferred`, and the spec's independent verification
pass has not run. Each 800-53 identifier is checked to exist, and not be
withdrawn, in the pinned OSCAL catalog (5.2.0); whether it fits the control
is still the analyst's call. Guardrail behaviour is tested with the local evaluator;
the spec's calibration against the IAM policy simulator and live calls has
not run either.

## 1. The journey at a glance

| Tier | Controls | Modes | Guardrails generated | Checker items |
|---|---|---|---|---|
| Private Preview | 7: 7 containment | Enforce 7 | 6 SCP statements, 1 RCP statement | 13 |
| Contained (promotion) | 14: 6 containment, 8 supervision; ATH-C-01 retired | Enforce 9, Enforce with override 5 | 7 SCP, 1 RCP | 21 |
| Hardened (promotion) | 20: adds 6 hardening | Enforce 9, Enforce with override 5, Advise 5, Report 1 | 7 SCP, 1 RCP | 21 |

Each promotion runs as a `diff` with the registry the previous tier wrote. The
shared `ORG-*` controls are added once and then reused; none is duplicated
and none loses a mode.

## 2. Controls by tier

`(SCP)` or `(RCP)` means the run generated a guardrail statement for that
control. The detective column lists the platforms each control declares.
Their generators aren't built yet, so they show as `pending` in
`generation.json`.

| Control | What | Class | Severity | Private Preview | Contained | Hardened | Detective |
|---|---|---|---|---|---|---|---|
| ORG-C-01 | Requests only in allowed regions | Containment | High (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | config, cloudtrail |
| ORG-C-02 | Organization principals reach only organization S3 resources | Containment | High (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ORG-C-03 | Only organization principals reach S3 and KMS resources | Containment | Critical (rubric) | Enforce (RCP) | Enforce (RCP) | Enforce (RCP) | config, cloudtrail |
| ATH-C-01 | Athena only in the authorized preview accounts | Containment | High (rubric) | Enforce (SCP) | retired | retired | cloudtrail |
| ATH-C-02 | No federated or cross-account data catalogs | Containment | High (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | config, cloudtrail |
| ATH-C-03 | No Spark notebooks or sessions | Containment | High (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ATH-C-04 | Athena API only through the organization's VPC endpoints | Containment | Medium (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ORG-S-01 | CloudTrail can't be stopped or reconfigured | Supervision | High (rubric) | — | Enforce (SCP) | Enforce (SCP) | config, cloudtrail |
| ORG-S-02 | Config recording can't be stopped | Supervision | High (rubric) | — | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ATH-S-01 | Workgroups override client-side settings | Supervision | Medium (rubric) | — | Enforce with override | Enforce with override | config |
| ATH-S-02 | Query results encrypted with KMS | Supervision | Medium (rubric) | — | Enforce with override | Enforce with override | config |
| ATH-S-03 | Workgroups have logging enabled | Supervision | Medium (Security Hub Athena.4) | — | Enforce with override | Enforce with override | config |
| ATH-S-04 | Config records Athena resource types in every allowed region | Supervision | Medium (rubric) | — | Enforce with override | Enforce with override | config, cloudtrail |
| ATH-S-05 | Query results location names its expected bucket owner | Supervision | Medium (rubric) | — | Enforce with override | Enforce with override | config |
| ATH-S-06 | Denied attempts against Athena guardrails and break-glass use are detected | Supervision | High (rubric) | — | Enforce | Enforce | cloudtrail |
| ATH-H-01 | Workgroups are tagged | Hardening | Low (Security Hub Athena.3) | — | — | Advise | config |
| ATH-H-02 | Data catalogs are tagged | Hardening | Low (Security Hub Athena.2) | — | — | Advise | config |
| ATH-H-03 | Workgroup engine versions upgrade automatically | Hardening | Low (rubric) | — | — | Advise | config |
| ATH-H-04 | Workgroups have a description | Hardening | Informational (rubric) | — | — | Report | config |
| ATH-H-05 | Workgroups cap the data scanned per query | Hardening | Low (rubric) | — | — | Advise | config |
| ATH-H-06 | Workgroups are created with a cost-center tag | Hardening | Low (rubric) | — | — | Advise | config, cloudtrail |

## 3. Tier by tier

### Private Preview: containment only

Seven controls, all **Enforce**, because containment is never permissive.
Four belong to Athena: preview accounts only, no federated or cross-account
data catalogs, no Spark notebooks or sessions, and VPC-endpoint-only access.
Three are shared organization controls: the region policy, the S3 resource
perimeter and the S3/KMS identity perimeter. Athena's own resources aren't
RCP-supported, so its identity perimeter is the S3 and KMS resources it reads
and writes (verified, F5).

Tested outcomes, all through the evaluator:

- From the preview account, through the endpoint, `StartQueryExecution` is
  allowed in `ca-central-1` and `eu-west-1`.
- These are denied, each by the expected statement:
  - the same call from another organization account (ATHC01);
  - the call in `us-west-2` or `us-east-1` (ORGC01);
  - `CreateDataCatalog` (ATHC02);
  - `StartSession` or `CreatePresignedNotebookUrl` (ATHC03);
  - calls without the endpoint, or through an unknown one (ATHC04);
  - S3 writes to another organization's bucket (ORGC02);
  - reads of an organization bucket by an outside principal (ORGC03).
- Calls made through an AWS service (`aws:ViaAWSService`) pass the network
  perimeter, and global services pass the region policy.
- Break-glass is exempt from every one of these denies.

The `next_tier` section of `selection.json` previews Contained: it adds 8
supervision controls and retires ATH-C-01.

### Contained: containment plus supervision

ATH-C-01 retires, so other organization accounts in `target_scope` can now
use Athena. The test proves this with a call from `444455556666`.
Supervision controls are at least **Enforce with override** (tier floor):

- **Shared guardrails:** CloudTrail and Config recording can't be stopped
  (ORG-S-01 and ORG-S-02, High, Enforce, SCP). Both are tested with a
  negative, a positive and a break-glass vector.
- **Workgroup configuration:** override client-side settings, KMS encryption,
  logging, and the expected bucket owner. Athena has no condition keys for
  these (F1), so the SCP is `not_expressible`, and they go to Config managed
  rules and Sentinel, both pending. Three of the Config rules are verified
  AWS managed rules:
  - `athena-workgroup-enforce-workgroup-configuration`
  - `athena-workgroup-encrypted-at-rest`
  - `athena-workgroup-logging-enabled`
- **Detection of the containment controls** (ATH-S-06) and **Config
  recording of Athena's three resource types** (verified:
  `AWS::Athena::WorkGroup`, `DataCatalog`, `PreparedStatement`).

All the containment vectors still hold.

### Hardened: everything else

Six hardening controls come in. The matrix sets their modes, with no tier
floor: tagging (Security Hub Athena.2 and Athena.3, Low), engine
auto-upgrade, a scan cap per query, and a cost-center tag at creation are
**Advise**; the workgroup description is **Report**. Advise and Report deploy
no guardrail, so creating an untagged workgroup is still allowed at Moderate.

The override path is tested by rendering at **High** criticality. There,
ATH-H-06 becomes Enforce with override:

- with no approved exceptions, no guardrail is deployed;
- with one exception (owner, expiry, rationale), the deny is deployed and
  only the named principal may create untagged workgroups.

## 4. What holds across the journey (tested)

- Tiers are cumulative: Private Preview minus retired ⊆ Contained ⊆ Hardened.
- No control's mode drops on promotion, at any criticality.
- Containment is Enforce at every tier and every criticality.
- Every control declares a detective platform and maps to at least one NIST
  SP 800-53 Rev 5 control that exists, not withdrawn, in the pinned OSCAL
  catalog (the reconciliation gate). Each selection records the catalog
  version and the source file's hash.
- Every Athena action named in a guardrail exists in the pinned API contract
  (the action validity gate).
- Every policy is under the 5,120-character limit. Every deny statement's
  Sid traces back to a control.
- Every generated guardrail has positive, negative and exemption vectors (the
  coverage rule).
- The allow-list admits Athena and its dependencies (`glue`, `kms`, `s3`).
- The tests catch broken behaviour. With the break-glass exemption removed,
  the negated-operator rule wrong, or the tier floors dropped, the suite
  fails (24, 56 and 10 failures).

## 5. Findings for the spec and the tool

| # | Finding | Status | Proposed change |
|---|---|---|---|
| F1 | Athena has no service-specific condition keys, only the global tag keys. | Tool output | Configuration controls route to Config and Sentinel; guardrails only deny whole actions. Done in the fixture (`not_expressible` with a reason). |
| F2 | Athena's dependencies don't appear in the contract. Permissions "pass through Athena" to S3. | Verified | Resolve needs a cited dependency source. The fixture's `dependencies` drive the allow-list for now. |
| F3 | No Athena action is annotated data plane. | Tool output | Take CloudTrail event types from the CloudTrail documentation, not from `IsDataPlane`. |
| F4 | Egress and sharing features look like ordinary writes. | Tool output | A per-service egress and sharing catalog, approved by the checker. |
| F5 | Athena isn't RCP-supported; S3 and KMS are. | Verified | Dependency containment controls are in scope from Private Preview, as shared controls (ORG-C-02, ORG-C-03). |
| F6 | VPC-endpoint-only access is a decision: it blocks the console from outside the VPC. | Implemented | New request field `decisions.network_perimeter`. A missing decision fails Select; `not-applicable` excludes ATH-C-04 with the reason recorded. |
| F7 | Regional availability isn't checked yet. | Open | Planned in Resolve. |
| F8 | `data_classification` had no mapping to criticality. | Partly decided | Internal Restricted is the classification behind the Moderate default (decided 2026-10-30); Public and Internal imply Low. A classification raises criticality, never lowers it. Labels above Internal Restricted (for example Confidential, the spec's own example) still need a decision; a request using one fails until then. |
| F9 | **S3 requests made through Athena can't be restricted by `aws:SourceVpce` or `aws:SourceIp`.** | Verified, new | An S3 network perimeter must exempt calls via Athena (`aws:CalledVia`). Recorded as a blind spot on ATH-C-04. |
| F10 | **The preview restriction must retire on promotion**, but the spec says tiers are cumulative. | Implemented | `until_tier` on a candidate: the control applies until that tier, and the next tier's `selection.json` lists it as retired. |
| F11 | Most supervision controls are Enforce with override with no guardrail. "Override" then only means the Sentinel soft-mandatory path. | Open | Confirm this is the intended meaning for configuration controls. |

## 6. Not done yet

- **Detective and plan-time artifacts:** Config rules, CloudTrail detections
  and Sentinel policies are declared per control but show as `pending`.
- **Compose:** placement per OU level, budgets across all services, and the
  diff against `org_state`. The tests place organization policies at the
  root and Athena's at the account.
- **Assess:** the candidates are hand-written. The Control Catalog and
  Security Hub lookups and the verification pass are not built.
- **Validate:** gates are asserted in tests, but `validation.json`,
  `report.md`, approvals and the manifest aren't produced.
- **Level 2 end-state tests:** no disposable test account yet.

## Reproduce

```sh
python3 -m unittest tests.test_athena_journey -v
# or step by step for one tier:
python3 -m onboard resolve  tests/fixtures/athena/request-private-preview.json --out runs/athena-pp \
  --snapshot tests/fixtures/service-reference/2026-10-30
python3 -m onboard select   tests/fixtures/athena/request-private-preview.json \
  --findings tests/fixtures/athena/findings.json --out runs/athena-pp
python3 -m onboard generate tests/fixtures/athena/request-private-preview.json --run runs/athena-pp
```

For a promotion, put the previous run's `registry.json` into the next
request as `control_registry`.
