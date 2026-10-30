# CI Efficiency Standard: GitHub Actions

**Goal: fast feedback on every PR, no wasted minutes.** Aim for PR checks
under 10 minutes at p95 (under 5 is better). Slow CI costs money and pushes
people, and agents, toward skipping checks.

The security rules in [supply-chain.md](../security/supply-chain.md) still
apply (pinned SHAs, least-privilege `permissions`). Efficiency never justifies
weakening them.

## Required in every workflow

```yaml
on:
  pull_request:
  push:
    branches: [main]          # push only on main; PR branches are covered by pull_request

permissions:
  contents: read

concurrency:                  # a new push cancels the now-stale run
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15       # the default is 360; a hung job burns 6 hours
```

- Don't cancel in-progress runs on `main` or for deployments, where a partial
  run can leave things half-applied. That's why the expression above limits
  cancellation to PRs.
- Every job sets `timeout-minutes` to about 2–3× its normal duration.

## Don't run what you don't need

- **Path filters** for workflows that only matter for part of the repo
  (`paths:` / `paths-ignore:`, e.g. skip the test suite for docs-only changes).
  If the workflow provides a **required** status check, a filtered-out run
  leaves the check pending forever. In that case filter at the job level
  (a changes-detection step) and keep a small always-running gate job as the
  required check.
- **Draft PRs:** run lint and unit tests; save expensive suites (e2e, full
  matrix, performance) for `ready_for_review` and `main`.
- **Matrices:** test the versions you support, not every combination.
  Run the full matrix on `main` or nightly and a representative subset on PRs.
- **Monorepos:** run only affected projects (Nx, Turborepo, Bazel, or a
  changed-files step).
- **Scheduled workflows:** only where they produce something someone acts
  on. Scheduled runs on idle repos are pure waste.
- Don't trigger the same checks on both `push` and `pull_request` for the same
  branch.

## Make what runs fast

- **Cache dependencies**, keyed on the lockfile hash:
  - use the built-in cache in `actions/setup-node`, `setup-python`,
    `setup-go`, and `setup-java` (`cache:` input) first;
  - use `actions/cache` for tool caches (pre-commit environments, build
    outputs), with `restore-keys` for partial hits;
  - Docker: `docker/build-push-action` with `cache-from/cache-to: type=gha`.
- **Order steps cheapest first** so failures surface early: format/lint and
  unit tests before builds, integration, and e2e.
- **Job granularity:** each job pays runner startup, checkout, and setup (often
  20–60 s). Split work into parallel jobs when each part runs for minutes;
  keep quick steps together in one job.
- **Checkout:** default `fetch-depth: 1`. Use full history only where it's
  needed (secret scanning history, changelog generation); use sparse checkout
  in large monorepos.
- **Test sharding** for suites over ~5 minutes (Jest `--shard`, pytest-xdist,
  Playwright shards across matrix jobs).
- **Pin tool versions** so caches stay valid and runs are reproducible.

## Runner choice and cost

Which labels and runtime versions are current is decided by GitHub and the
runtime maintainers, not by memory: see
[runtime-versions.md](../sdlc/runtime-versions.md) and run
`tools/check_runtimes.py --report`.

- Linux runners are the default. On private repositories, macOS and Windows
  minutes cost several times more than Linux; use them only for
  platform-specific builds and tests.
- Arm64 Linux runners (`ubuntu-24.04-arm`) are cheaper per minute than x64
  and fast for most workloads. Prefer them when the toolchain supports arm64.
- Larger runners cut wall-clock time for heavy builds; use them when the
  saved developer time is worth the higher per-minute rate. Measure first.
- Self-hosted runners only on private repos, never for untrusted fork PRs,
  and preferably ephemeral (one job per runner).

## Artifacts and storage

- Set `retention-days` on `actions/upload-artifact` (e.g. 3–7 for PR
  artifacts); the default is 90 days and storage is billed.
- Upload only what someone will download (test reports on failure, release
  builds). Don't upload `node_modules` or whole workspaces.

## Agents in CI

When Claude Code or another agent runs in Actions:

- trigger on explicit intent (a label, an `@mention`, `workflow_dispatch`),
  not on every push;
- cap turns, runtime, and spend (`--max-turns`, `--max-budget-usd`, and
  `timeout-minutes`);
- use `concurrency` so overlapping triggers don't start parallel agent runs;
- see [claude-code.md](claude-code.md) for model and context choices.

## Measure it

- Track workflow duration (p50/p95) and queue time from the Actions usage and
  performance metrics. Look at the slowest job first.
- Treat a CI slowdown or a flaky test as a bug with an owner.

## Review questions

1. Does every job have `timeout-minutes`, and does the workflow cancel stale PR runs?
2. Are dependencies cached on the lockfile hash?
3. Does a docs-only or unrelated change skip work it doesn't need?
4. Is any matrix, runner OS, or scheduled trigger more expensive than it needs to be?
5. Do artifacts have a short retention period?
