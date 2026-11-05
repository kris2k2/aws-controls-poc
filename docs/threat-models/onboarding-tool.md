# Threat Model: AWS service onboarding tool

| | |
|---|---|
| Author | Repository owner, drafted with an AI coding agent |
| Date | 2026-10-30 |
| Reviewers | Pending |
| Related PR / ADR | [ADR-0001](../adr/0001-python-stdlib-staged-pipeline.md) |

Scope: the tool as built so far (request validation, the control model, the
Resolve, Select and Generate stages, and the local policy evaluator). Update this model whenever a stage adds a source, a credential
or a model call.

## 1. What are we building?

A command-line tool, run by an analyst (the maker), that reads an onboarding
request and public AWS sources, then writes files to a run directory. It
deploys nothing and needs no AWS credentials for what exists today.

```
[Analyst] --request.json--> [onboard CLI] --HTTPS (allowlisted host)--> [AWS service reference]
                                 |
                                 +--writes--> [run directory: capability-profile.json, ...]
                                 |
                                 +--reads (optional)--> [local snapshot of the service reference]
                                 |
                                 +--reads--> [pinned NIST SP 800-53 index, catalogs/]
                                 |
                                 +--HTTPS, only on `onboard catalog` (allowlisted host and path)--> [NIST OSCAL catalog]
```

Trust boundaries: (1) the network: AWS and NIST responses are untrusted data; (2) the
request file, written by the analyst but validated as untrusted input;
(3) the run directory: what the checker reviews and approves.

### Data handled

| Data | Classification | Stored where | Retention |
|---|---|---|---|
| AWS service reference (actions, resources, condition keys) | public | run directory, snapshots | per run |
| NIST SP 800-53 Rev 5 catalog index (ids, labels, titles, withdrawn status) | public | `catalogs/` (committed, reviewed) | until the next refresh PR |
| Onboarding request: account IDs, OU names, org policies, maker/checker identities | internal (confidential once real org state is used) | analyst's machine, run directory | per run; never committed |
| Generated controls (later stages) | internal | run directory | per run |

## 2. What can go wrong? (STRIDE)

| Threat | Applies? | Scenario | Mitigation | Status |
|---|---|---|---|---|
| **S**poofing | Yes | A spoofed or redirected source serves a fake IAM contract or a fake NIST catalog | HTTPS only; host allowlist (and, for NIST, the `usnistgov/oscal-content` path) checked before the request and after redirects; no credentials in URLs | Done (`check_url`, `check_catalog_url`, tests) |
| **T**ampering | Yes | A service reference index entry points to another host; a source changes between review and use; the NIST index is edited to admit a made-up or withdrawn identifier | Per-service URLs re-checked against the allowlist; every source recorded with URL, version and retrieval time; snapshots for replay. The NIST index records the SHA-256 of NIST's file and is committed, so a refresh or an edit shows up in review, and runs record which catalog they used. Manifest hashes come with Validate | Partly done |
| **R**epudiation | Yes | Nobody can show who approved an enforcing control | Maker and checker required and must differ. Approvals over a hashed manifest come with Validate | Partly done |
| **I**nformation disclosure | Yes | Real org state or account IDs committed with fixtures or run outputs | Fixtures are synthetic (AWS documentation account ID); run outputs live outside the repo; the PII and secret scans run on every commit | Done for this slice |
| **D**enial of service | Low | A huge or slow response stalls a run | 30 s timeout, 32 MB response cap; failures stop the run with a clear error | Done |
| **E**levation of privilege | Yes | Generated guardrails are too permissive (a missing exemption check, a wrong condition, an unresolved parameter), or the tool's own credentials are too broad | Containment is always Enforce; the matrix can't drop a mode as criticality rises; a missing parameter or decision fails the run; every generated guardrail has positive, negative and exemption vectors through the local evaluator, and mutation checks show the vectors catch broken exemptions and operator semantics. The evaluator isn't calibrated against the IAM policy simulator yet, so a pass means "as intended". No credentials in this slice; end-state tests will use credentials scoped to a disposable test account only | Partly done |

Agentic and LLM risks: no model is called yet. When reasoning stages arrive,
walk prompt injection (fetched docs steering mappings), excessive agency and
output handling before merge, as ADR-0001 requires.

## 3. Privacy

- No personal data is needed. Maker and checker are recorded as analyst
  identifiers; use role or employee IDs, not names or emails, in requests.
- Nothing is sent to a third party except fetches of public AWS documents.

## 4. What are we doing about it?

Mitigations are linked above. Open items: manifest hashing and approvals
(Validate), the threat-model update for reasoning stages, and the
credential scope for end-state tests.

## 5. Did we do a good job?

- [x] Abuse cases have tests (URL allowlist, redirected index entries, malformed sources, invalid requests)
- [ ] Reviewed by someone outside the implementing team
- [x] Revisit trigger defined: new source, credential, model call or deployment path
