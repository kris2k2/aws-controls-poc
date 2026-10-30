# OWASP Top 10:2025 — Engineering Standard

Source: [OWASP Top 10:2025](https://owasp.org/Top10/2025/). For depth beyond this
checklist, verify against [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
(Level 1 for every app, Level 2 for anything handling personal data or money)
and the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/).

Each section gives the rule to follow while writing code and the question a
reviewer (human or agent) must be able to answer "yes" to.

---

## A01 Broken Access Control (includes SSRF)

**Do**
- Deny by default. Every endpoint, handler, and job states who may call it.
- Enforce authorization server-side on each request, per object (check the
  record belongs to the caller, not just that the caller is logged in).
- Use one central authorization mechanism, not ad-hoc checks per route.
- For outbound requests built from user input, allowlist schemes, hosts, and
  ports; block link-local, loopback, and cloud metadata addresses
  (`169.254.169.254`); don't follow redirects blindly.
- Set CORS to explicit origins; never reflect `Origin` with credentials.

**Don't** rely on hidden fields, client-side checks, unguessable IDs, or the UI
hiding a button.

**Review:** Can a user read or modify another user's record by changing an ID?

## A02 Security Misconfiguration

**Do**
- Secure-by-default config; debug, verbose errors, admin consoles, and sample
  apps off in production.
- Set security headers (CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`).
- Infrastructure as code with the same review as application code; scan it
  (e.g. Checkov, tfsec, kube-linter).
- Least-privilege service accounts, storage buckets private by default.

**Review:** Is every new setting safe if someone deploys it unchanged?

## A03 Software Supply Chain Failures

See [supply-chain.md](supply-chain.md). In short: lockfiles committed, versions
pinned, CI actions pinned by SHA, dependency and SCA scanning in CI,
Dependabot/Renovate on, SBOM for released artifacts, and no new dependency
without a reason in the PR.

**Review:** Is each new dependency necessary, maintained, licensed compatibly,
and pinned?

## A04 Cryptographic Failures

**Do**
- TLS 1.2+ for all traffic, including internal.
- Passwords: Argon2id (preferred), scrypt, or bcrypt with a per-user salt.
- Symmetric: AES-256-GCM or ChaCha20-Poly1305 via a vetted library (libsodium,
  Tink, platform KMS). Keys live in a KMS/secret manager and rotate.
- Use a CSPRNG (`secrets` in Python, `crypto.randomBytes` in Node) for tokens.
- Classify data; encrypt sensitive personal data at rest.

**Don't** implement crypto primitives, use MD5/SHA-1 for security, use ECB,
reuse nonces, or hardcode keys/IVs.

**Review:** Is any sensitive data stored or sent in clear text?

## A05 Injection (SQL, NoSQL, OS command, LDAP, template, XSS)

**Do**
- Parameterized queries / ORM bind parameters always.
- Call processes with an argument array, never a shell string
  (`subprocess.run([...])`, not `shell=True`).
- Contextual output encoding; use the framework's auto-escaping templates.
- Validate input with allowlists (type, length, format, range) at trust
  boundaries.

**Don't** concatenate input into queries, commands, templates, file paths, or
regexes; never `eval`/`exec` untrusted data.

**Review:** Does any untrusted value reach an interpreter without parameterization or encoding?

## A06 Insecure Design

**Do**
- Threat-model features that touch authentication, payments, personal data,
  file upload, or external integrations ([template](../../templates/threat-model.md)).
- Write abuse cases next to use cases; add tests for them.
- Rate-limit and add business-logic limits (e.g. max transfers per day).
- Segregate tenants and trust tiers.

**Review:** Was the "how would someone misuse this?" question asked and answered in writing?

## A07 Authentication Failures

**Do**
- Use the platform IdP (OIDC/SAML) or a vetted library; support MFA/passkeys.
- Check new passwords against breached-password lists; no composition rules
  or forced rotation (NIST SP 800-63B).
- Rate-limit and progressively delay failed logins; generic error messages.
- Regenerate session IDs on login; secure, `HttpOnly`, `SameSite` cookies;
  server-side session invalidation on logout.

**Don't** ship default credentials, put credentials or tokens in URLs, or
build your own password reset token scheme.

**Review:** Can an attacker enumerate users, brute-force, or reuse a stolen session?

## A08 Software or Data Integrity Failures

**Do**
- Verify checksums/signatures of downloaded artifacts and updates.
- Protected branches, required review, and signed commits/tags for releases.
- Treat CI/CD as production: least-privilege tokens (`permissions:` blocks),
  no secrets exposed to fork PRs.

**Don't** deserialize untrusted data with native serializers (`pickle`,
Java `ObjectInputStream`, `yaml.load` without `SafeLoader`).

**Review:** Could tampered code, data, or build output reach production undetected?

## A09 Security Logging & Alerting Failures

**Do**
- Log authentication events, access-control failures, input-validation
  failures, and admin actions with timestamp, actor ID, and request ID.
- Structured logs, shipped off-host, tamper-evident, with retention defined.
- Alert on the events that matter, and make sure someone receives the alerts.

**Don't** log passwords, tokens, session IDs, full card numbers, or personal
data. Log a stable internal ID instead of an email or name.

**Review:** If this feature were abused, would we notice, and would the logs avoid leaking PII?

## A10 Mishandling of Exceptional Conditions

**Do**
- Fail closed: an error in an auth or validation path denies the request.
- Handle every error path explicitly; set timeouts and resource limits.
- Show users a generic message with a correlation ID; keep details in logs.
- Make operations atomic or roll back cleanly on partial failure.

**Don't** swallow exceptions (`except: pass`), return stack traces to clients,
or let a failed check default to "allowed".

**Review:** What happens to this code path when a dependency is slow, down, or returns garbage?
