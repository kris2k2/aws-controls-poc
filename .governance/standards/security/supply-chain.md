# Software Supply Chain Standard

Covers OWASP Top 10:2025 **A03 Software Supply Chain Failures** and **A08
Software or Data Integrity Failures**. References:
[SLSA](https://slsa.dev/), [OpenSSF Scorecard](https://securityscorecards.dev/),
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

## Dependencies

- Commit lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`,
  `uv.lock`, `go.sum`, `Cargo.lock`, …). CI installs from the lockfile
  (`npm ci`, `pip install --require-hashes`, `uv sync --frozen`).
- Every new dependency is justified in the PR: why it's needed, maintenance
  activity, license, and download/popularity sanity check (typosquatting).
- Prefer the standard library and existing dependencies.
- Automated updates (Dependabot or Renovate) enabled; security updates merged
  within the SLA below.
- SCA scanning in CI (e.g. `npm audit`, `pip-audit`, `osv-scanner`, GitHub
  Dependency Review).

| Severity (CVSS) | Fix or mitigate within |
|---|---|
| Critical (9.0+) | 7 days |
| High (7.0–8.9) | 30 days |
| Medium | 90 days |
| Low | Next routine update |

## CI/CD

- Third-party GitHub Actions pinned to a full commit SHA, with the version in a
  trailing comment (`uses: org/action@<sha> # v1.2.3`). Dependabot keeps them
  current.
- Every workflow declares a top-level `permissions:` block, read-only by default.
- `actions/checkout` with `persist-credentials: false` unless the job pushes.
- No secrets in workflows triggered by `pull_request_target` or fork PRs.
- Never interpolate untrusted context (`${{ github.event.* }}`) directly into
  `run:` scripts; pass it through `env:`.
- Downloaded tools are verified against a pinned checksum.

## Releases

- Protected default branch: required PR review, required status checks, no
  force-push, no deletion.
- Signed tags for releases; generate an SBOM (CycloneDX or SPDX) for shipped
  artifacts; publish build provenance where the platform supports it.
