# Secrets Management Standard

Aligned with the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

## Rules

1. Secrets never enter a repository: not in code, config, tests, docs, commit
   messages, CI logs, or agent memory files.
2. Runtime secrets come from a secret manager (Vault, AWS Secrets Manager, GCP
   Secret Manager, Azure Key Vault, 1Password) or the platform's encrypted
   environment. Local development uses an untracked `.env` file.
3. Commit a `.env.example` with variable names and placeholder values only.
4. Prefer short-lived, scoped credentials (OIDC workload identity in CI instead
   of long-lived cloud keys). For AWS, use the
   [CI bootstrap](aws-ci-bootstrap.md).
5. Each secret has an owner and a rotation schedule.

## Enforcement

- `gitleaks` runs on every commit (pre-commit) and over full history in CI.
- GitHub secret scanning and push protection: **enable on every repo**
  (Settings → Code security).
- `.gitignore` covers `.env`, `.env.*` (except `.env.example`), `*.pem`, `*.key`,
  `*.p12`, `*.pfx`, credential JSON files.
- Agent settings deny reading these files.

## If a secret is committed

Treat it as compromised the moment it's pushed, even to a private repo or a
branch that is deleted a minute later.

1. **Revoke/rotate it first.** Removing it from the code does not un-leak it.
2. Check the provider's audit log for use since the commit time.
3. Remove it from the code and replace with a secret-manager lookup.
4. If the repo is public or widely cloned, purge history with
   `git filter-repo` and coordinate a force-push with the repo owner (this is
   one of the few accepted reasons to rewrite shared history).
5. Record it as a security incident (see [SECURITY.md](../../SECURITY.md)).
