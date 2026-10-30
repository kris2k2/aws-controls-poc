## What and why

<!-- What does this change do, and why is it needed? Link the issue. -->

## How it was tested

<!-- Commands run, tests added, manual checks. Be specific about what was NOT tested. -->

## Security checklist (`.governance/standards/security/owasp-top-10.md`)

- [ ] Authorization enforced server-side for any new endpoint, handler, or object access
- [ ] Untrusted input is validated; queries/commands are parameterized; output is encoded
- [ ] No secrets, keys, or tokens added (config reads from env/secret manager)
- [ ] New dependencies are justified below, pinned, and from a maintained source
- [ ] Errors fail closed and don't leak internals; security-relevant events are logged without sensitive data
- [ ] LLM/agent features reviewed against `.governance/standards/security/owasp-agentic-llm.md`
- [ ] AWS: CI uses the bootstrap OIDC role; new IAM roles/policies use the project path and permissions boundary
- [ ] Threat model added/updated (required for auth, payments, personal data, uploads, integrations)
- [ ] N/A: no security-relevant change (say why)

## Privacy checklist (`.governance/standards/privacy/pii.md`)

- [ ] No real personal data in code, tests, fixtures, screenshots, logs, or this description
- [ ] Any new personal-data field has a documented purpose, retention, and access control
- [ ] Any `pii-scan: allow` or `.piiignore` addition is justified here

## Cost and efficiency (`.governance/standards/efficiency/`)

- [ ] Infra changes: idle monthly cost (zero traffic) stated here; any always-on resource justified
- [ ] New log groups, buckets, and tables have retention or lifecycle rules, and resources carry cost tags
- [ ] CI changes: jobs have `timeout-minutes`, dependencies are cached, stale runs are cancelled
- [ ] N/A: no infrastructure, CI, or agent-configuration change

<!-- Idle monthly cost estimate and assumptions: -->

## SDLC

- [ ] Conventional Commit messages; one concern per PR
- [ ] Tests added/updated and passing; `pre-commit run --all-files` clean
- [ ] Docs / ADR updated where relevant

## New dependencies

<!-- Name, version, why it's needed, license. Delete if none. -->

## Agent involvement

<!-- If an AI agent authored or co-authored this PR, say which parts. A human must review. -->
