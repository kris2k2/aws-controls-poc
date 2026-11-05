# Test case: Amazon Athena from Private Preview to Hardened

Athena is the tool's first end-to-end test case: one service taken through all
three maturity tiers, with the outcomes tested at each step. Sections follow
the spec's `report.md` layout where they apply.

| | |
|---|---|
| Date | 2026-10-30 |
| Requests | `tests/fixtures/athena/request-{private-preview,contained,hardened}.json` (synthetic org `o-exampleorgid`, preview account `111122223333`, data classification Internal Restricted, criticality Moderate) |
| Candidate controls | `tests/fixtures/athena/findings.json`: 24 candidates, hand-written; Assess reproduces them from `overlay.json` (12) plus the baseline, the preview restriction and 3 Security Hub controls |
| API contract | AWS service reference snapshot, `tests/fixtures/service-reference/2026-10-30/` |
| Tests | `tests/test_athena_journey.py` (outcomes), `tests/test_athena_adversarial.py` (guardrails against an attacker, see [section 5](#5-adversarial-verification)), `tests/test_verify.py` (the Verify stage), `tests/test_review.py` (release review, [section 6](#6-release-review)), `tests/test_athena_acceptance.py` (Resolve), `tests/test_assess.py` (Assess, the same journey from assessed findings) |
| Run it | see [Reproduce](#reproduce) |

**How to read this.** Tier outcomes, modes and guardrail behaviour are tool
output, pinned by the tests. The candidate controls are not: Assess isn't
built, so an analyst wrote them. In `findings.json`, each fact marked
`verified` was checked against the cited AWS page on 2026-10-30. Every
NIST SP 800-53 mapping is `inferred`, and the spec's independent verification
pass has not run. Each 800-53 identifier is checked to exist, and not be
withdrawn, in the pinned OSCAL catalog (5.2.0); whether it fits the control
is still the analyst's call. Guardrail behaviour is tested with the local evaluator,
for the vectors below and against an attacker model (section 5); the spec's
calibration against the IAM policy simulator and live calls has not run
either.

## 1. The journey at a glance

| Tier | Controls | Modes | Guardrails generated | Checker items |
|---|---|---|---|---|
| Private Preview | 10: 10 containment | Enforce 10 | 7 SCP statements, 1 RCP statement, 2 endpoint policy statements | 19 |
| Contained (promotion) | 17: 9 containment, 8 supervision; ATH-C-01 retired | Enforce 12, Enforce with override 5 | 8 SCP, 1 RCP, 2 endpoint | 27 |
| Hardened (promotion) | 23: adds 6 hardening | Enforce 12, Enforce with override 5, Advise 5, Report 1 | 8 SCP, 1 RCP, 2 endpoint | 27 |

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
| ORG-C-02 | Organization principals reach only organization S3 resources and named trusted accounts | Containment | High (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ORG-C-03 | Only organization principals reach S3 and KMS resources | Containment | Critical (rubric) | Enforce (RCP) | Enforce (RCP) | Enforce (RCP) | config, cloudtrail |
| ORG-C-04 | Only break-glass principals change or pass break-glass and exception roles | Containment | Critical (rubric) | Enforce (SCP) | Enforce (SCP) | Enforce (SCP) | cloudtrail |
| ORG-C-05 | Only organization principals use the organization's VPC endpoints | Containment | Critical (rubric) | Enforce (endpoint) | Enforce (endpoint) | Enforce (endpoint) | config, cloudtrail |
| ORG-C-06 | The organization's VPC endpoints reach only organization resources and named trusted accounts | Containment | Critical (rubric) | Enforce (endpoint) | Enforce (endpoint) | Enforce (endpoint) | config, cloudtrail |
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

Ten controls, all **Enforce**, because containment is never permissive.
Four belong to Athena: preview accounts only, no federated or cross-account
data catalogs, no Spark notebooks or sessions, and VPC-endpoint-only access.
Six are shared organization controls: the region policy, the S3 resource
perimeter, the S3/KMS identity perimeter, ORG-C-04, which stops anyone
but break-glass creating, changing or passing the roles the guardrails
exempt (break-glass and exception roles), and the network perimeter
(ORG-C-05, ORG-C-06): one baseline policy on every VPC endpoint the
organization runs ([ADR-0004](../adr/0004-baseline-vpc-endpoint-policy.md)). Athena's own resources aren't
RCP-supported, so its identity perimeter is the S3 and KMS resources it reads
and writes (verified, F5).

Tested outcomes, all through the evaluator:

- From the preview account, through the endpoint, `StartQueryExecution` is
  allowed in `ca-central-1` and `eu-west-1`.
- These are denied, each by the expected statement:
  - the same call from another organization account (ATHC01);
  - the call in `us-west-2` or `us-east-1` (ORGC01);
  - `CreateDataCatalog` (ATHC02);
  - `StartSession`, `CreatePresignedNotebookUrl` or `UpdateNotebook` (ATHC03);
  - calls without the endpoint, or through an unknown one (ATHC04);
  - S3 writes to another organization's bucket (ORGC02);
  - reads of an organization bucket by an outside principal, even one
    whose role is named like break-glass (ORGC03);
  - creating a role with a break-glass name, or rewriting a break-glass
    role's trust policy (ORGC04);
  - any call through the organization's endpoints with credentials from
    outside the organization, or none (ORGC05);
  - any call through those endpoints to a resource outside the organization,
    such as a third-party Glue catalog, unless its account is named in
    `trusted_resource_accounts` (ORGC06).
- Calls made through an AWS service (`aws:ViaAWSService`) pass the network
  perimeter, and global services pass the region policy.
- Break-glass is exempt from every one of these denies except the data
  perimeter (ORGC02, ORGC03): a break-glass session can't move data out of
  the organization either. Break-glass principals are role ARNs in named
  accounts (`111122223333` and `444455556666`), never a wildcard account.

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
- Each generated statement denies exactly what its security property
  denies, over the whole attacker model, and every mutant of every statement
  is caught (section 5).

## 5. Adversarial verification

The vectors above show each guardrail works for the requests its author
thought of. `tests/test_athena_adversarial.py` checks the guardrails against
what an attacker can do instead ([ADR-0003](../adr/0003-adversarial-verification-of-guardrails.md)).
Layers 3, 4 and 6 also run on every real run, as the Verify stage
([ADR-0006](../adr/0006-verify-stage.md), `tests/test_verify.py`): every Athena
deny is proved at each tier, and 150 to 190 mutants per run are caught.

1. **Security spec** (`onboard/specs/organization.py` and `athena.py`): one property per
   preventive control, saying what it must deny, written from the control's
   objective rather than its guardrail. This is what the security team
   reviews.
2. **Attacker model** (`onboard/adversary.py`): the action (all 81 Athena
   actions in the contract, plus dependencies, global services and one
   service nothing allows, in any case), the resource, the principal (role
   name and path, account inside or outside the organization, a standalone
   account in no organization, an unsigned request, AWS service), the region,
   the VPC endpoint (each of the organization's, the attacker's own, or
   none), calls through an AWS service, the organization and account owning
   the resource, and request tags.
3. **Bounded proof:** for each tier, plus High criticality with an
   exception, every generated statement denies exactly what its property
   denies, over every combination of the dimensions either side reads. Actions
   and resources are grouped into classes every pattern treats alike, so the
   check is exhaustive over the model rather than sampled.
4. **Contract completeness** (`onboard/specs/athena-action-review.json`):
   every Athena action in the contract is listed, and every data catalog and
   Spark action is either denied or allowed with a reason. A contract refresh
   that adds an action fails the tests, and fails Verify for ATH-C-02 and
   ATH-C-03, until it is reviewed.
5. **Exemption hygiene:** exemptions name a role in a 12-digit account, and
   every exempt role is protected by ORG-C-04 from everyone else.
6. **Mutation testing:** 709 mutants of the generated statements (dropped or
   narrowed actions, dropped or negated conditions, widened exemptions and
   resources) are all caught, except 4 kinds that are equivalent in the
   model and listed with the reason. The endpoint policy's base allow is
   checked to allow everything its guardrails don't deny.
7. **Accepted risks:** the gaps left open on purpose, each with its reach,
   registered in the spec and pinned in the tests by a request that must stay
   allowed and by boundary requests that must stay denied. Their sign-off is
   pending; until then each is a doubt in the release review.

   | Risk | Who can use it, from where | Boundary pinned |
   |---|---|---|
   | AR-01: calls through an AWS service skip the VPC endpoint check | Organization principals, from any network (a stolen credential works from outside) | The data perimeter still holds on that path (ORGC02, ORGC03) |
   | AR-02: Spark-engine workgroups can be created | Organization principals; contained | Sessions and calculations stay denied (ATHC03) |
   | AR-03: global services aren't region-restricted | Organization principals, not contained to the allowed regions (CloudFront caches worldwide); only the global services the allow-list opens | Regional services stay region-restricted (ORGC01) |
   | AR-04: break-glass is exempt from every guardrail but the data perimeter | Whoever the break-glass roles' trust policies admit, which the tool doesn't check | Break-glass can't move data out of the organization (ORGC02) |
   | AR-05: traffic that bypasses the organization's endpoints | Anyone with a path around them (NAT or internet gateway, proxy, off-network device) and outside credentials, or none | The same request through an endpoint stays denied (ORGC05) |

A catalogue of 20 named attacks runs end to end through every policy,
including egress through the organization's own endpoints with someone
else's credentials, unsigned requests, and standalone accounts (A16 to A20).

When it was first run, the suite found three gaps, now fixed (F12, F13):
the break-glass pattern `arn:aws:iam::*:role/BreakGlass-*` let a role of that
name outside the organization through the RCP, any member allowed to create
roles could give itself that name and skip every guardrail, and ATH-C-03
missed `UpdateNotebook` and `UpdateNotebookMetadata`.

## 6. Release review

`onboard review` decides whether a run may be released without a person
([ADR-0005](../adr/0005-risk-based-release-review.md)), tested by
`tests/test_review.py`. It re-runs Select, Generate and Verify and blocks on
any difference, checks the policies themselves, then lists its doubts, each
with a risk and the question a person answers by accepting it. Proofs come
only from its own run of Verify, so all 10 Private Preview denies are proved
without anyone supplying evidence.

At Private Preview, with no evidence supplied, the run **holds**:

| Doubts | Risk | Status at Moderate (ceiling Low) |
|---|---|---|
| No impact replay for each of the 6 organization-wide denies (Athena's own need none: nobody uses Athena yet) | High | needs a person (6) |
| Inferred High or Critical severity (9 controls), evaluator not calibrated, break-glass trust policies unchecked | Medium | needs a person (11) |
| The security spec isn't signed off; accepted risks AR-01, AR-02, AR-03 and AR-05 aren't signed off | Medium | needs a person (5) |
| Enforce on inferred mappings only (10 controls), detective artifacts pending | Low | accepted by the reviewer (11) |

With impact and calibration evidence for every statement (synthetic in the
tests, since no stage produces it yet), what is left is judgement: the
severities, break-glass, the spec and its accepted risks. Once a person other
than the maker accepts those, the run **releases**. The next run releases on
its own while nothing changes. Opening a region changes ORG-C-01's statement:
Verify proves it again on its own, and only its impact replay comes back to a
person. Findings that weaken a guardrail (a Spark action dropped from
ATH-C-03) are reproduced faithfully by Select and Generate, and blocked by the
proof. The promotion to Contained adds doubts for the lifted
preview restriction (ATH-C-01 retired), the trusted resource account, the
supervision controls nothing enforces yet (F11), and impact replays for
Athena's own denies. Any edited file, failed proof or unexpected Allow
**blocks**, and no acceptance overrides a blocker.

## 7. Findings for the spec and the tool

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
| F12 | **Break-glass exemptions could be matched or created by an attacker.** A wildcard account matched roles outside the organization (RCP bypass), and nothing stopped a member creating a `BreakGlass-*` role. | Fixed | Break-glass and exception principals must be role ARNs in a 12-digit account. New shared control ORG-C-04 denies the IAM role changes (and `iam:PassRole`) on every exempt role to everyone but break-glass. |
| F13 | **ATH-C-03's deny list was hand-picked** and missed two Spark actions. | Fixed | Every capability action in the contract is classified in `onboard/specs/athena-action-review.json` (pending security review); the guardrail denies the reviewed list. |
| F14 | **Break-glass could move data out of the organization**: it was exempt from the S3 resource perimeter (ORG-C-02). Its reach is set by trust policies the tool doesn't check. | Fixed, pending sign-off | Guardrails can set `break_glass_exempt: false`; the data perimeter (ORG-C-02, ORG-C-03) does. Checking break-glass trust policies is open. |
| F15 | **The organization's VPC endpoints let data leave with someone else's credentials.** No SCP or RCP applies to an outside principal writing to an outside resource, and the endpoints carried AWS's default full-access policy. | Fixed for traffic through the endpoints | A baseline endpoint policy (ORG-C-05, ORG-C-06) on every endpoint; named exceptions in `trusted_resource_accounts`. Traffic around the endpoints is AR-05: a network control. |

## 8. Not done yet

- **Detective and plan-time artifacts:** Config rules, CloudTrail detections
  and Sentinel policies are declared per control but show as `pending`.
- **Compose:** placement per OU level, budgets across all services, and the
  diff against `org_state`. The tests place organization policies at the
  root and Athena's at the account.
- **Assess:** built for the baseline, the preview restriction and Security
  Hub controls from the Control Catalog ([ADR-0007](../adr/0007-assess-from-the-control-catalog.md)).
  From assessed findings (`tests/fixtures/athena/overlay.json` and a
  synthetic catalog snapshot) the three tiers give the same outcomes and
  byte-identical policies as the hand-written candidates
  (`tests/test_assess.py`). Not yet run against AWS; the verification pass
  for inferred mappings is not built.
- **Whole cycle and delivery:** `onboard run` takes Athena from the request
  to a sealed bundle ([ADR-0008](../adr/0008-run-and-sealed-delivery.md)):
  it holds on 22 doubts at Private Preview and delivers once the checker
  accepts them (`tests/test_run.py`).
- **Unattended release:** the review and Verify are built, but no stage
  produces impact or calibration evidence yet, the spec and accepted risks
  aren't signed off, acceptances aren't authenticated, and no pipeline deploys
  on `release` (ADR-0005, ADR-0006).
- **Validate:** gates are asserted in tests, but `validation.json`,
  `report.md`, approvals and the manifest aren't produced.
- **Level 2 end-state tests:** no disposable test account yet.
- **Network egress:** traffic that bypasses the endpoints (AR-05) needs
  network controls (no internet egress from workload VPCs, egress
  filtering); this tool writes no network configuration.
- **Evaluator calibration:** the adversarial proof holds in the local
  evaluator's model of IAM. Replaying the same requests through the IAM policy
  simulator and live calls in a sandbox account is what turns it into a claim
  about AWS; it needs AWS access and hasn't run.

## Reproduce

```sh
python3 -m unittest tests.test_athena_journey -v
python3 -m unittest tests.test_athena_adversarial -v
# or step by step for one tier:
python3 -m onboard resolve  tests/fixtures/athena/request-private-preview.json --out runs/athena-pp \
  --snapshot tests/fixtures/service-reference/2026-10-30
python3 -m onboard select   tests/fixtures/athena/request-private-preview.json \
  --findings tests/fixtures/athena/findings.json --out runs/athena-pp
python3 -m onboard generate tests/fixtures/athena/request-private-preview.json --run runs/athena-pp
python3 -m onboard verify   tests/fixtures/athena/request-private-preview.json --run runs/athena-pp
python3 -m onboard review   tests/fixtures/athena/request-private-preview.json --run runs/athena-pp
```

For a promotion, put the previous run's `registry.json` into the next
request as `control_registry`.
