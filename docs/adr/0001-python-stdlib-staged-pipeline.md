# ADR-0001: Build the onboarding tool as a standard-library Python pipeline of file-based stages

- **Status:** proposed
- **Date:** 2026-10-30
- **Deciders:** repository owner (pending review)

## Context

The *AWS Service Onboarding Tool Spec* (draft v0.1, kept outside this
repository) describes a tool that assesses one AWS service from its API
contract and generates a fact-checked control set: organization policies,
permission boundaries, Config rules, CloudTrail detections and Sentinel
policies, with test suites and validation reports. It runs six stages
(Resolve, Assess, Select, Generate, Compose, Validate). Each stage writes a
structured, versioned output that the next stage reads, so any stage can be
re-run or audited on its own. The tool only writes files: nothing is
deployed in this version.

Forces:

- It reads untrusted content (AWS docs, API responses) and writes security
  controls, so its supply chain should be as small as possible.
- Runs must be reproducible from pinned source versions.
- The spec's end-state tests use pytest with boto3; the governance tooling
  this repository already runs is Python.
- Some stages (inferred mappings, rubric severities) involve reasoning, which
  could mean calling a model.

## Decision

1. **Python, standard library only**, for as long as that stays practical.
   `requires-python >= 3.13`, with CI on 3.13 and the recommended 3.14.
   A dependency is added only through a later ADR (YAML output and boto3 for
   the end-state tests are the likely first ones), pinned with hashes.
2. **One module per stage, joined only through files.** A stage reads the
   previous stage's JSON from the run directory and writes its own. The
   `onboard` command runs one stage at a time (`onboard resolve ...`).
3. **Sources go through injectable fetchers** with a host allowlist. Every
   fetched document is recorded with its URL, version and retrieval time.
   A local snapshot can stand in for the network, which makes runs
   repeatable and keeps unit tests offline.
4. **No model calls in the first slices.** Deterministic stages come first:
   Resolve, the control model, and request validation. Reasoned steps will
   sit behind an interface that writes to `decision-log.jsonl`. They get
   their own ADR and threat-model update first, including where the model
   runs (the baseline requires Bedrock in `ca-central-1`; cross-Region
   inference needs an ADR).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| Python, stdlib only (chosen) | No supply chain to start with; matches the governance tooling and the spec's pytest/boto3 end-state tests | JSON instead of YAML until a dependency is accepted |
| Python with pydantic, PyYAML, requests | Less validation code; YAML from day one | Three dependencies before any need is proven |
| TypeScript (to match the CDK default) | One language with future infrastructure | The tool deploys nothing; IAM and Sentinel tooling and the test harness are more natural in Python |

## Consequences

- The control record and the outputs the spec shows as YAML are written as
  JSON for now. Switching later is a change in the output format only.
- Each stage can be tested and audited alone; a full run is a sequence of
  stage commands. A driver can come later.
- Reasoning stages are blocked on their own ADR, threat model and evals.
  That's deliberate.
- Revisit when a dependency would remove meaningful code or risk.
