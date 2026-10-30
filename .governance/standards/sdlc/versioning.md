# Versioning Standard

Every repository versions its releases with [Semantic Versioning](https://semver.org/)
(`MAJOR.MINOR.PATCH`), derived from [Conventional Commits](https://www.conventionalcommits.org/).
The commit history says what changed; tooling turns that into the version
and the changelog, so nobody has to guess.

## Commit types decide the version

| Commit | Example | Release |
|---|---|---|
| `!` after the type, or a `BREAKING CHANGE:` footer | `feat(bootstrap)!: require immutable OIDC subjects` | **major** (minor while the version is `0.y.z`) |
| `feat` | `feat(pii): detect IBANs` | **minor** |
| `fix`, `perf`, `sec` | `fix: handle empty files` | **patch** |
| `docs`, `test`, `refactor`, `style`, `build`, `ci`, `chore`, `revert` | `docs: explain the allowlist` | none on its own |

- `check_commit_msg.py` enforces the header format in the `commit-msg` hook
  and in CI. Squash merges use the **PR title** as the commit message, so CI
  checks the PR title too.
- Describe breaking changes in the commit body or footer, including what users
  of the code must do (the migration). That text goes into the changelog.
- `0.y.z` means initial development: anything may change, and breaking
  changes bump the minor version. Release `1.0.0` once the public surface
  (APIs, files, behaviour others rely on) is stable and in real use.

## Releasing

1. On a branch: `python3 tools/release.py prepare`. It computes the next
   version from commits since the last `v*` tag, writes `VERSION`, and adds a
   `CHANGELOG.md` section grouped as Breaking changes / Added / Security /
   Fixed / Performance. Anything written by hand under `## [Unreleased]`
   (migration notes, context) moves into the new section.
2. Review and edit the changelog in a PR titled `chore(release): X.Y.Z`; merge it.
3. The `release` workflow tags `vX.Y.Z` on the merge commit and publishes a
   GitHub release with that changelog section.

Tags are immutable: never move or delete a release tag. A bad release is
fixed by a new release. Protect `v*` tags with a tag ruleset and turn on
immutable releases in the repository settings.

`release.py` lives in `.governance/tools/` in every governed project, so
projects can use the same flow. Projects with an ecosystem-specific
release tool (e.g. `npm version`) may use it instead, as long as versions
follow these rules.

## What counts as breaking in the governance baseline

Projects consume this repository through `.governance/` (see
[governance-adoption.md](governance-adoption.md)), so its version tells them
how risky an update is. A change is **breaking (major)** when it can turn a
project's previously green CI red, or requires the project to change
something:

- a new blocking check, or an existing warning becoming an error;
- a rule that rejects something it used to accept (stricter PII detection,
  new commit-message requirements, a narrower bootstrap boundary);
- removing or renaming a managed file, tool option, exit code, or bootstrap
  parameter, or changing a default in a way that changes behaviour;
- a starter-file change that projects must apply by hand.

**Minor:** new standards or guidance, new warnings, new optional tools,
options or parameters with backward-compatible defaults.
**Patch:** fixes to false positives or wording, documentation, and anything
else that only makes CI greener.

Deprecation path for new rules: ship them as **warnings in a minor release**,
then make them **errors in the next major**, so projects see them coming and
no sync PR turns every repository red at once. Security fixes may ship as a
patch even when they tighten something, with the reason in the changelog.
