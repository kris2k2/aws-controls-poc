# Agent instructions: aws-controls-poc

This repository follows the governance baseline in
[`.governance/AGENTS.md`](.governance/AGENTS.md). Read it first. It applies
unless a human working with you says otherwise. Paths it mentions
(`standards/`, `templates/`, `tools/`) are under `.governance/`.

`.governance/` is managed: never edit it. It's updated by pull requests from
the `governance-sync` workflow (or `python3 .governance/tools/governance.py sync`).

## Project specifics

<!-- Build, test and run commands; the layout; rules specific to this project. -->

- What it is: the AWS service onboarding tool (see `README.md`). Python,
  standard library only (ADR-0001); one module per pipeline stage under
  `onboard/`, joined only through files in the run directory.
- Test: `python3 -m unittest discover -s tests -t .` (offline, under 1 s).
  Run: `python3 -m onboard --help`.
- Tests never touch the network: inject a fetcher or use a snapshot. Fixtures
  are synthetic (account `111122223333`, analysts `analyst-a`/`analyst-b`),
  except snapshots of the public AWS service reference.
- Adding a dependency, a source host or a model call needs an ADR and a
  threat-model update (`docs/threat-models/onboarding-tool.md`) first.
- NIST SP 800-53 identifiers come only from the pinned index in `catalogs/`
  (ADR-0002), in catalog form (`ac-3`, `ac-2.1`) with `catalog_version`. Never
  write one from memory. Refreshing the index (`python3 -m onboard catalog`) is
  its own PR.
- Initial test case: Athena through all three tiers,
  `docs/simulations/athena-journey.md`, tested by `tests/test_athena_journey.py`
  with the fixtures in `tests/fixtures/athena/`. Keep it green; extend it when a
  stage is added.
- Proof of concept for AWS controls. Infrastructure follows the AWS defaults in
  the baseline: CDK (TypeScript) with `project-guardrails.ts`, home region
  `ca-central-1`, stacks named `aws-controls-poc` or `aws-controls-poc-*`, and
  CI access only through the project's bootstrap stack.
- Checks: `python3 .governance/tools/governance.py ci` and
  `pre-commit run --all-files`.
