# Agent instructions: aws-controls-poc

This repository follows the governance baseline in
[`.governance/AGENTS.md`](.governance/AGENTS.md). Read it first. It applies
unless a human working with you says otherwise. Paths it mentions
(`standards/`, `templates/`, `tools/`) are under `.governance/`.

`.governance/` is managed: never edit it. It's updated by pull requests from
the `governance-sync` workflow (or `python3 .governance/tools/governance.py sync`).

## Project specifics

<!-- Build, test and run commands; the layout; rules specific to this project. -->

- Status: new repository; only the governance baseline is in place. Add the
  build, test and run commands here with the first code.
- Proof of concept for AWS controls. Infrastructure follows the AWS defaults in
  the baseline: CDK (TypeScript) with `project-guardrails.ts`, home region
  `ca-central-1`, stacks named `aws-controls-poc` or `aws-controls-poc-*`, and
  CI access only through the project's bootstrap stack.
- Checks: `python3 .governance/tools/governance.py ci` and
  `pre-commit run --all-files`.
