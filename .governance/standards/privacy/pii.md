# Personal Data (PII) Standard

**Rule: real personal data never enters a repository.** Git history is
permanent, copied to every clone, and mirrored to CI logs, forks, caches, and
AI tooling. Once committed, PII is effectively published.

This supports obligations under PIPEDA, Québec Law 25, GDPR, and similar laws
(data minimization, purpose limitation, breach notification). This standard is
engineering guidance, not legal advice; privacy questions go to whoever owns
privacy for the project.

## What counts as personal data

Anything that identifies a person, alone or combined with other data:

- **Direct identifiers:** name, email, phone, postal address, photo, voice.
- **Government IDs:** SIN, SSN, passport, driver's licence, health card numbers.
- **Financial:** payment card numbers, bank account/IBAN, transaction history.
- **Sensitive categories:** health, biometrics, ethnicity, religion, sexual
  orientation, union membership, precise location, children's data.
- **Online identifiers:** IP addresses, device IDs, cookie IDs, user handles,
  when linkable to a person.
- **Credentials:** passwords and security answers (also covered by
  [Secrets](../security/secrets.md)).

Employee and contributor data counts too, including screenshots and logs from
internal tools.

## Where it must not appear

Source code, test fixtures, seed data, snapshots, sample files, docs, ADRs,
screenshots, notebooks and their outputs, log excerpts in issues or PRs, commit
messages, branch names, agent memory files, and prompts or transcripts saved
into the repo.

## Use synthetic data instead

| Need | Use |
|---|---|
| Email | `alice@example.com`, any `*.example`, `*.test`, `*.invalid` domain (RFC 2606) |
| Phone (NANP) | `555-0100` to `555-0199` (reserved for fiction) |
| Payment card | Processor test numbers, e.g. `4242 4242 4242 4242` |
| IP address | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737); `2001:db8::/32` (RFC 3849) |
| Domain | `example.com`, `example.org`, `example.net` |
| Names / addresses | A generator such as Faker with a fixed seed; obviously fake values ("Test User") |
| Production-shaped datasets | Generated data, or a de-identified extract approved by the data owner and kept **outside** the repo |

Never "anonymize" a production dump by hand and commit it. Re-identification
from supposedly anonymous data is routine.

## In application code

- Collect only what the feature needs; document why.
- Don't log personal data. Log internal IDs; mask where display is needed
  (`****1234`).
- Encrypt sensitive personal data at rest; restrict access by role.
- Store and process personal data in Canada (`ca-central-1`) by default; see
  the [AWS platform standard](../cloud/aws.md) before sending it elsewhere.
- Define retention and deletion for every personal-data field you add.
- New features that process personal data need a privacy review (the
  threat-model template has a privacy section) and, where required, a privacy
  impact assessment.
- Don't send personal data to third-party services, including LLM APIs, unless
  covered by an agreement and the privacy notice.

## Enforcement

| Layer | Control |
|---|---|
| Agent | `PreToolUse` hook blocks Write/Edit containing PII (`tools/pii_scan.py --claude-hook`) |
| Commit | `pii-scan` pre-commit hook on staged files |
| CI | `pii-scan` over the full tree plus every line added in the PR's commits (catches PII added then deleted) |
| Review | PR template privacy checklist; reviewers check fixtures and screenshots |

The scanner detects emails, phone numbers, Canadian SINs, US SSNs, payment
cards (Luhn-checked), and IBANs (checksum-validated). It **cannot** detect
names, addresses, free-text health information, or data inside images. Human
review covers those.

### Organization contact details

An organization's published contact details are not personal data and
may appear in a site or app:

- **Role addresses** (`info@`, `privacy@`, `support@`, `security@`,
  `sales@`, …) pass the scanner automatically. They name a function, not a
  person. A named person's address (`jane.doe@` at the company's domain) is
  personal data even on the company's own domain.
- **Other published values** (a main switchboard number, a company IBAN on
  an invoice template): list each exact value in `.pii-allowlist` at the repo
  root, one per line, with a comment saying where it's published.

### False positives

Add `pii-scan: allow` to the line with a short reason, add the exact value to
`.pii-allowlist`, or add a path glob to `.piiignore`. All three show up in
review; justify them in the PR.

## If personal data is committed

1. **Stop and tell the repo owner immediately.** Don't quietly delete it; a
   follow-up commit leaves it in history.
2. If the branch hasn't been pushed: amend or rebase it out locally.
3. If it has been pushed: the owner decides on purging history
   (`git filter-repo`, then force-push and ask GitHub Support to purge cached
   views and PR refs), and notifies anyone who cloned.
4. Assess the exposure (who could access the repo, for how long, whether it was
   public or forked) and log it as a privacy incident. The privacy owner
   decides whether breach-notification obligations apply (e.g. PIPEDA's "real
   risk of significant harm" test, Law 25's confidentiality-incident register).
