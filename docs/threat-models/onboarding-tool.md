# Threat Model: AWS service onboarding tool

| | |
|---|---|
| Author | Repository owner, drafted with an AI coding agent |
| Date | 2026-10-30 |
| Reviewers | Pending |
| Related PR / ADR | [ADR-0001](../adr/0001-python-stdlib-staged-pipeline.md), [ADR-0003](../adr/0003-adversarial-verification-of-guardrails.md), [ADR-0004](../adr/0004-baseline-vpc-endpoint-policy.md), [ADR-0005](../adr/0005-risk-based-release-review.md), [ADR-0006](../adr/0006-verify-stage.md), [ADR-0007](../adr/0007-assess-from-the-control-catalog.md) |

Scope: the tool as built so far (request validation, the control model, the
Resolve, Assess, Select, Generate, Verify and Review stages, the local policy evaluator, the attacker model and the security specs). Update this model whenever a stage adds a source, a credential
or a model call.

## 1. What are we building?

A command-line tool, run by an analyst (the maker), that reads an onboarding
request and public AWS sources, then writes files to a run directory. It
deploys nothing. Only Assess needs AWS credentials, read-only, to list the
AWS Control Catalog's controls and mappings (ADR-0007).

```
[Analyst] --request.json--> [onboard CLI] --HTTPS (allowlisted host)--> [AWS service reference]
                                 |
                                 +--writes--> [run directory: capability-profile.json, ...]
                                 |
                                 +--reads (optional)--> [local snapshot of the service reference]
                                 |
                                 +--reads--> [pinned NIST SP 800-53 index, catalogs/]
                                 |
                                 +--HTTPS, SigV4, read-only, on `onboard assess` (one host)--> [AWS Control Catalog, ca-central-1]
                                 |        credentials from the analyst's environment, never written
                                 +--reads (optional)--> [Control Catalog snapshot] and [analyst overlay]
                                 |
                                 +--HTTPS, only on `onboard catalog` (allowlisted host and path)--> [NIST OSCAL catalog]
```

Trust boundaries: (1) the network: AWS and NIST responses are untrusted data; (2) the
request file, written by the analyst but validated as untrusted input;
(3) the run directory: what the checker reviews and approves;
(4) the release decision: `review.json`, which a deployment pipeline will act
on without a person when it says `release`, and the evidence and acceptance
files it is computed from; (5) the AWS credentials Assess signs Control
Catalog calls with, which come from the environment and never cross into
the run directory, a snapshot or an error.

### Data handled

| Data | Classification | Stored where | Retention |
|---|---|---|---|
| AWS service reference (actions, resources, condition keys) | public | run directory, snapshots | per run |
| NIST SP 800-53 Rev 5 catalog index (ids, labels, titles, withdrawn status) | public | `catalogs/` (committed, reviewed) | until the next refresh PR |
| Onboarding request: account IDs, OU names, org policies, maker/checker identities | internal (confidential once real org state is used) | analyst's machine, run directory | per run; never committed |
| AWS Control Catalog responses (Security Hub controls, severities, framework mappings) | public AWS data, fetched with credentials | run directory (`assessment.json`, `findings.json`), snapshots | per run |
| AWS credentials for the Control Catalog | secret | the analyst's or CI's environment only | the session |
| Analyst overlay (the service's judgment candidates) | internal | analyst's machine, run directory | per run |
| Generated controls (later stages) | internal | run directory | per run |

## 2. What can go wrong? (STRIDE)

| Threat | Applies? | Scenario | Mitigation | Status |
|---|---|---|---|---|
| **S**poofing | Yes | A spoofed or redirected source serves a fake IAM contract or a fake NIST catalog | HTTPS only; host allowlist (and, for NIST, the `usnistgov/oscal-content` path) checked before the request and after redirects; no credentials in URLs. The Control Catalog client allows one host (`controlcatalog.ca-central-1.amazonaws.com`), refuses redirects and signs with SigV4, so a spoofed host can't serve it | Done (`check_url`, `check_catalog_url`, `control_catalog.check_url`, tests) |
| **T**ampering | Yes | A service reference index entry points to another host; a source changes between review and use; the NIST index is edited to admit a made-up or withdrawn identifier | Per-service URLs re-checked against the allowlist; every source recorded with URL, version and retrieval time; snapshots for replay. The NIST index records the SHA-256 of NIST's file and is committed, so a refresh or an edit shows up in review, and runs record which catalog they used. Manifest hashes come with Validate | Partly done |
| **R**epudiation | Yes | Nobody can show who approved an enforcing control | Maker and checker required and must differ. Approvals over a hashed manifest come with Validate | Partly done |
| **I**nformation disclosure | Yes | Real org state or account IDs committed with fixtures or run outputs | Fixtures are synthetic (AWS documentation account ID); run outputs live outside the repo; the PII and secret scans run on every commit | Done for this slice |
| **I**nformation disclosure | Yes | Assess's AWS credentials leak: into a snapshot, `assessment.json`, a log line, an exception or a traceback | Credentials are read from the environment at call time and held only in memory; `Credentials` keeps the secret and token out of `repr`; snapshots record requests and responses, never headers; HTTP errors report the AWS error type and message, never the request; missing credentials fail before anything is written. Tests check the recording and the error path for the key | Done (tests) |
| **D**enial of service | Low | A huge or slow response stalls a run, or the catalog paginates forever | 30 s timeout, 32 MB response cap (8 MB for the Control Catalog); pagination stops on a repeated token or after 100 pages; failures stop the run with a clear error | Done |
| **E**levation of privilege | Yes | Someone gets a weak or edited policy set released without a person: editing a policy or control record after generation, supplying fake passing evidence or a forged proof report, accepting doubts about their own run, or lowering the release threshold | The reviewer re-runs Select, Generate and Verify and blocks on any difference; proofs come only from its own run of Verify against the reviewed spec in `onboard/specs/`, never from supplied files, so weak findings that Select and Generate reproduce faithfully still fail their proof; evidence binds to the SHA-256 of the exact statement (and calibration to the evaluator's source), so changed statements lose it; acceptances bind to a fingerprint of what was doubted, expire, and can't come from the maker; the auto-accept ceiling is a constant changed only by ADR; `review.json` records the hash of the released set. A spec edit is a code change under CODEOWNERS, and the spec's hash is in every proof and fingerprints its doubt. Not done: impact, calibration and acceptance files are checked for content, not authorship, so they must come from authenticated sources (a Verify stage, a reviewed pull request to a protected acceptances file); no deployment pipeline reads `review.json` yet | Partly done (ADR-0005, ADR-0006) |
| **E**levation of privilege | Yes | Generated guardrails are too permissive (a missing exemption check, a wrong condition, an unresolved parameter), or the tool's own credentials are too broad | Containment is always Enforce; the matrix can't drop a mode as criticality rises; a missing parameter or decision fails the run; every generated guardrail has positive, negative and exemption vectors through the local evaluator. Against an attacker (ADR-0003): each statement is checked to deny exactly what its reviewed security property denies, over every combination of an explicit attacker model (bounded proof); every excluded-capability action in the contract is reviewed; break-glass and exception principals are role ARNs in named accounts, protected by ORG-C-04 from anyone else creating, changing or passing them, and break-glass is held to the data perimeter (ORG-C-02, ORG-C-03); a baseline VPC endpoint policy (ADR-0004) stops anyone using the organization's endpoints with outside credentials or none, or reaching resources outside the organization through them, and traffic that bypasses the endpoints is a registered network-layer risk (AR-05); break-glass trust policies are not checked yet; every mutant of every statement is caught; deliberate gaps are pinned in an accepted-risk register with their reach and boundary. The evaluator isn't calibrated against the IAM policy simulator yet, so a pass means "holds in our model of AWS". The tool's only credentials are Assess's, for two List-level read-only actions (`controlcatalog:ListControls`, `controlcatalog:ListControlMappings`); the client refuses any other operation. End-state tests will use credentials scoped to a disposable test account only | Partly done |
| **T**ampering | Yes | Assess imports weak or wrong controls: a doctored snapshot, a synthetic snapshot passed off as real, or an overlay that replaces or drops a control | Imports are detective and add no guardrail, so they can't weaken an organization policy; preventive controls are still proved by Verify against the reviewed spec. A synthetic snapshot makes every imported citation and mapping `unverifiable`; the overlay can only add candidates and can't define `ORG-*`; `assessment.json` records the source of every candidate, the snapshot used and every skipped control. Not done: Review doesn't re-run Assess, so a dropped Security Hub control shows only in `assessment.json` | Partly done (ADR-0007) |

Agentic and LLM risks: no model is called yet. When reasoning stages arrive,
walk prompt injection (fetched docs steering mappings), excessive agency and
output handling before merge, as ADR-0001 requires.

## 3. Privacy

- No personal data is needed. Maker and checker are recorded as analyst
  identifiers; use role or employee IDs, not names or emails, in requests.
- Nothing is sent to a third party except fetches of public AWS documents
  and the Control Catalog's read-only List calls, which carry no request data.

## 4. What are we doing about it?

Mitigations are linked above. Open items: the first signed Control Catalog run (and a recorded snapshot to replace the synthetic one), a read-only role scoped to the two Control Catalog actions for CI, authenticated evidence and acceptances for the release review, manifest hashing and approvals
(Validate), the threat-model update for reasoning stages, the
credential scope for end-state tests, calibrating the evaluator against AWS,
and security team sign-off of the guardrail spec and accepted risks.

## 5. Did we do a good job?

- [x] Abuse cases have tests (URL allowlist, redirected index entries, malformed sources, invalid requests, attacks on generated guardrails)
- [ ] Reviewed by someone outside the implementing team
- [x] Revisit trigger defined: new source, credential, model call or deployment path (revisited for the Control Catalog, ADR-0007)
