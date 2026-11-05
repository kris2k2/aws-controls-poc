# ADR-0007: Assess from an organization baseline, the request and the AWS Control Catalog, with the analyst's judgment as an overlay

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

Assess is the stage between Resolve's API contract and Select. It was never
built: the Athena test case runs on 24 hand-written candidates, so the
pipeline can't start from a service name. That blocks packaging the pipeline
as one automated workflow from a service to a delivered policy set.

A candidate carries a class, a severity and its source, NIST SP 800-53
references, citations, the platforms that implement it and, for preventive
controls, a guardrail. Some of that is fact AWS publishes, and some is
judgment:

- **Shared organization controls** (`ORG-*`: regions, data and network
  perimeters, break-glass protection, logging tamper) don't depend on the
  service. They were written once, for Athena, and reviewed.
- **The preview restriction** is mechanical: the service's prefixes, denied
  outside the preview accounts until promotion.
- **Security Hub's controls** for the service are AWS's published detective
  checks, each with AWS's severity and AWS's framework mappings. The AWS
  Control Catalog serves them through an API: `ListControls` (filtered to
  `AWS::SecurityHub::SecurityControl`) and `ListControlMappings` (FRAMEWORK).
  The API needs SigV4-signed calls, so it needs AWS credentials. It is
  offered in `ca-central-1`.
- **The service's own containment** (which capabilities to deny, how to stop
  data egress, the network path) and rubric-rated supervision are judgment,
  checked by Verify against the service's security spec (ADR-0006).

The alternatives for the facts: parse the public Security Hub documentation
pages (no credentials, but brittle HTML and only publisher-mapped
references), or call a model (not deterministic; needs its own ADR). The
owner chose the Control Catalog.

## Decision

1. **A deterministic Assess stage, `onboard assess`** (`onboard/assess.py`).
   It reads the request, the run's `capability-profile.json` and the
   catalog, and writes `findings.json` (findings/v1, checked by
   `load_findings` like any findings file) and `assessment.json`, which
   records the source of every candidate and every skipped control. No model
   is called; the same inputs give the same findings (the SHA-256 is in the
   report).
2. **Four sources, in a fixed order; none overrides another.**
   1. *The organization baseline*, `onboard/baseline/organization.json`: the
      eight shared `ORG-*` candidates from the reviewed Athena case, with the
      Athena-specific text removed. It is reused through the control
      registry, so a change to it is a change to every service's
      organization policies, under CODEOWNERS. Only the baseline may define
      `ORG-*`.
   2. *Derived:* `<CODE>-C-01`, the service's actions denied outside the
      preview accounts until Private Preview ends. Its property stays in the
      service's spec. `<CODE>` is the service's first three letters
      (`ATH`), or an entry in `assess.CODES`.
   3. *The Control Catalog:* each Security Hub control that governs one of
      the service's CloudFormation resource types (`AWS::Athena::*`; the
      namespace is the service key unless `assess.CFN_NAMESPACES` says
      otherwise, and the Security Hub ID's prefix stands in when a control
      lists none) becomes `<CODE>-SH-<n>` for Security Hub `<Service>.<n>`:
      detective, Config planned, class Supervision for Medium and above,
      Hardening for Low, `severity_source: control-catalog`. Its NIST
      references are AWS's FRAMEWORK mappings to NIST SP 800-53 Rev 5,
      converted to catalog form (`AC-2(4)` → `ac-2.4`) and resolved in the
      pinned catalog (ADR-0002), as `aws-mapped`. A control with no
      resolvable NIST mapping, a non-detective behavior or an unknown
      severity isn't imported; it is listed in `assessment.json` with the
      reason for the analyst.
   4. *The analyst overlay* (`--overlay`, findings-overlay/v1): the
      service's judgment candidates and dependencies. It can add candidates,
      never replace or drop one from another source, and never define
      `ORG-*`.
3. **The catalog client is read-only, home-region and credential-safe**
   (`onboard/control_catalog.py`, standard library only):
   - only `ListControls` and `ListControlMappings`, POST to
     `controlcatalog.ca-central-1.amazonaws.com`; the host is checked before
     the call and after it, and redirects are refused;
   - SigV4 in the standard library, checked against vectors from botocore
     1.43.125 as an independent oracle;
   - credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
     `AWS_SESSION_TOKEN` at call time, never written to the run, a snapshot,
     a log line or an error, and kept out of `repr`; missing credentials fail
     the run before anything is written;
   - the IAM permissions needed are `controlcatalog:ListControls` and
     `controlcatalog:ListControlMappings` (List-level), so the role a run
     uses should allow only those;
   - responses are data: only the expected fields are read, pagination
     stops on a repeated token or after 100 pages, responses are capped at
     8 MB, and a 30 s timeout applies.
4. **Offline runs replay a snapshot** (`--control-catalog-snapshot`); a live
   run can record one (`--record-snapshot`). Snapshots hold requests and
   responses only. A snapshot marked `synthetic` makes every imported
   citation and mapping `unverifiable`, never `verified`.
5. **Assess is not reviewed by re-running it.** Review re-runs Select,
   Generate and Verify from `findings.json` (ADR-0005, ADR-0006); Verify's
   proofs are what catch weak findings for preventive controls. Assess's
   imports are detective and add no guardrail.

## What the test case shows

Athena from assessed findings (the baseline, the derived `ATH-C-01`, three
Security Hub controls from a synthetic snapshot and a 12-candidate overlay)
gives the hand-written journey's outcome at every tier: 10, 17 and 23
controls with the same modes, every proof passing, and organization policies
byte-identical to those of `tests/fixtures/athena/findings.json`.

## Consequences

- The pipeline can start from a service name: Resolve → Assess → Select →
  Generate → Verify → Review. The workflow and delivery come in the next
  change.
- The tool now holds AWS credentials during Assess, a new trust boundary.
  The threat model is updated. Nothing else in the tool reads them.
- A new service still needs its security spec (ADR-0006) and, for its own
  containment, an overlay. Assess lists what it leaves to the analyst.
- Security Hub IDs above 99 (EC2.172) need three digits: the control ID
  pattern now allows `\d{2,3}`.

## Open items

- **The framework name AWS uses for NIST SP 800-53 Rev 5 isn't documented.**
  `assess.NIST_R5` accepts the plausible spellings, and `assessment.json`
  records every framework name a run sees. The first live run must confirm
  it, and record a snapshot to replace the synthetic one.
- **Config-rule controls** (`AWS::Config::ConfigRule`) aren't imported: they
  have no stable number to build an ID from, and many duplicate a Security
  Hub control. Proactive controls (CloudFormation hooks) have no platform in
  the control model.
- **Not run against AWS.** The client follows the API reference and the
  botocore model and is tested against a fake transport; no signed call has
  been made yet.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Control Catalog API (chosen) | AWS's own severities and mappings; machine-readable; offered in `ca-central-1` | Needs AWS credentials (a new trust boundary); one call per control for mappings |
| Security Hub documentation pages | No credentials | HTML scraping breaks silently; publisher-mapped references only |
| A model writes the findings | Covers judgment controls too | Not deterministic; prompt injection from fetched pages; needs its own ADR |
| Keep findings hand-written | No new source | The pipeline can't start from a service name |
