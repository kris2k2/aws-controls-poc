# Changelog

All notable changes to the governance baseline, newest first. Versions
follow [Semantic Versioning](https://semver.org/) and are derived from
Conventional Commits (see `standards/sdlc/versioning.md`). Projects receive
these through `governance-sync` pull requests.

## [Unreleased]

## [0.1.0] - 2026-10-11

First release. Initial development (0.y.z): rules may still change between
minor versions; read each release's notes before syncing. Not yet proven by
a real AWS deployment (see todo.md).

### Breaking changes

- require Conventional Commits headers (commit-msg) (788ed3d)

### Added

- init, sync, check and ci for governed projects (governance) (1a70b92)
- derive versions and changelog from Conventional Commits (release) (42ef805)
- CDK-first AWS with ca-central-1 as home region (c264b58)
- check runtime, runner and action versions against live data (1e14821)
- deploy through a CloudFormation execution role; immutable OIDC subjects (2194f51)
- let published role addresses and allowlisted values pass pii-scan (a4e6ccd)
- add AWS CI bootstrap template with self-protecting boundary (edfc5b5)
- forbid agent session links in commit messages (aeb16d8)
- add cost and runtime efficiency standards (a855168)
- add agentic governance baseline (OWASP, SDLC, PII) (fa0470d)

### Fixed

- store manifest hashes so secret scanners don't flag them (governance) (3f718de)
