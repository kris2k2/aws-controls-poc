# SDLC Workflow Standard

Secure SDLC practices drawn from [OWASP SAMM](https://owaspsamm.org/) and
[NIST SSDF (SP 800-218)](https://csrc.nist.gov/projects/ssdf).

## Branching

- Trunk-based: short-lived branches off `main`, merged via PR, deleted after merge.
- Branch names: `<type>/<short-description>` (`feat/export-csv`,
  `fix/login-timeout`). Agents may use their own prefix (`claude/...`).
- No branch names, tags, or commit messages containing personal data, ticket
  text copied from customers, or secrets.

## `main` branch protection (configure on every repo)

- Require a pull request with at least one approving review from someone other
  than the author (an agent's human principal counts as a reviewer only if they
  didn't write the change themselves).
- Require status checks to pass (governance + project tests) and branches to be
  up to date.
- Require review from Code Owners.
- Block force-pushes and deletion. Apply rules to administrators.
- Require conversation resolution before merge.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <imperative summary, ≤ 72 chars>

<why this change is needed and what it does differently; wrap at 72>

<trailers: Refs: #123, Co-Authored-By: …>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`,
`build`, `sec` (security fix), `revert`. Mark breaking changes with `!` and a
`BREAKING CHANGE:` footer.

One logical change per commit; the tree builds and tests pass at each commit.

**No links to agent sessions or conversation transcripts** in commit
messages, PR titles, or PR descriptions: no `Claude-Session:` or similar
trailers, and no Claude, ChatGPT, Gemini, or Copilot chat/share URLs. A
transcript can contain secrets, personal data, proprietary code, and internal
discussion, and a link in Git history is permanent and widely copied. Put the
reasoning that matters into the commit body itself. Attribution trailers
(`Co-Authored-By:`) are fine.

Enforced by `tools/check_commit_msg.py`, which also rejects personal data in
messages. It runs as a `commit-msg` hook (`pre-commit install` sets it up)
and in CI over every commit in a PR. GitHub can build a squash-merge commit
message from the PR description, so keep that clean too.

## Pull requests

- Small: aim for under ~400 changed lines of hand-written code. Split
  refactors from behaviour changes.
- Fill in the PR template, including the security and privacy checklist.
- Link the issue or explain the motivation.
- Draft PRs for work in progress; mark ready only when CI is green.
- Authors respond to every review comment (fix or explain).

## Code review

Reviewers check, in order:

1. **Correctness:** does it do what it says, including edge and error cases?
2. **Security:** [OWASP Top 10 checklist](../security/owasp-top-10.md);
   for LLM features, the [agentic/LLM checklist](../security/owasp-agentic-llm.md).
3. **Privacy:** no real personal data in fixtures/screenshots/logs; new
   personal-data fields have purpose, retention, and access control.
4. **Tests:** meaningful assertions, cover the change, not just the happy path.
5. **Maintainability:** readable, consistent with the codebase, no dead code.

Approve only what you understand. "LGTM" on a diff you didn't read is a
control failure.

## Testing

- Every behaviour change ships with tests; bug fixes start with a failing test.
- Test pyramid: many fast unit tests, fewer integration tests, few end-to-end.
- Security-relevant code (authz, input validation, crypto use) has explicit
  negative tests (the request that must be rejected).
- Tests use synthetic data only (see [PII standard](../privacy/pii.md)).
- Never skip, disable, or loosen a test to get CI green. If a test is wrong,
  fix it in its own commit with an explanation.
- Flaky tests are bugs: file an issue and fix the root cause.

## Definition of done

- [ ] Acceptance criteria met; tests added and passing
- [ ] `pre-commit run --all-files` clean; CI green
- [ ] Security and privacy checklist in the PR answered
- [ ] Docs, changelog, and ADR updated where relevant
- [ ] No new warnings, TODOs without an issue link, or commented-out code
- [ ] Reviewed and approved by a code owner

## Releases

- Semantic Versioning, derived from Conventional Commits, with a generated
  changelog: see [versioning.md](versioning.md).
- Releases cut from `main` via tagged, signed commits.
- Rollback plan known before deploying anything with a migration.
