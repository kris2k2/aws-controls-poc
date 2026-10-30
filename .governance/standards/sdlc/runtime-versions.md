# Runtime Versions Standard

**Rule: CI and deployments use runtime versions that are currently supported,
as published by their maintainers and by GitHub, looked up when you write
the config, not recalled from memory.**

Agents in particular tend to write the versions they saw most in training
data. Those are often a year or more out of date, and GitHub then flags them
with deprecation annotations or removes them outright. Runtimes age out on a
calendar, without any code change, so a version that was correct last month
can be wrong today.

## Sources of truth

| What | Authority | How to look it up |
|---|---|---|
| Node.js, Python support phases | Release maintainers, via [endoflife.date](https://endoflife.date) | `tools/check_runtimes.py --report` |
| GitHub-hosted runner labels | [actions/runner-images](https://github.com/actions/runner-images#available-images) | `tools/check_runtimes.py --report` |
| Action versions and their runtime | Each action's releases and `action.yml` (`runs.using`) | `tools/check_runtimes.py --pin owner/repo` |

**Before writing or changing any workflow, version file, or runtime
setting, run `python3 tools/check_runtimes.py --report`** and use what it
prints. Use `--pin owner/repo` to get an action's latest release already
pinned by SHA.

## Policy

| Runtime | Use | Warning | Error |
|---|---|---|---|
| **Node.js** | The current **Active LTS** line (`--report` names it). | Maintenance LTS (security fixes only); a non-LTS line (odd-numbered, or an even line before its LTS date). | End of life; not yet released. |
| **Python** | The newest minor in active (bug-fix) support, or the one before it until your dependencies publish wheels for the newest. | Security-fixes-only minor. | End of life; not yet released. |
| **Runner labels** | `ubuntu-latest` (or `-arm`/`-slim` variants) unless the job needs a specific image; then a label GitHub lists as GA. | Preview/beta labels; labels that aren't GitHub-hosted images. | Labels GitHub marks deprecated. |
| **Actions** | The latest major, pinned by full commit SHA with a `# vX.Y.Z` comment. | Behind the latest major. | Not SHA-pinned; runs on an end-of-life Node runtime (`runs.using`). |

Notes:

- Dynamic specs such as `lts/*` or `3.x` always resolve to current versions
  and pass, but they make builds less reproducible. Prefer an explicit major
  in a version file (`.nvmrc`, `.python-version`) that both local
  development and CI read (`node-version-file`, `python-version-file`).
- Version files are the single source of truth: don't repeat the version
  in workflow `with:` inputs when a version file exists.
- When GitHub announces an image migration (for example `ubuntu-latest`
  moving to a new Ubuntu release), test on the new label during the
  migration window. Pin to the older label only temporarily, with an issue
  to unpin.
- A deprecation annotation in a CI run is a defect: fix it in the next PR
  that touches the workflow, or open an issue.
- Packaging-level ranges (`engines.node`, `requires-python`) state
  compatibility; they don't choose the runtime and aren't checked.

## Enforcement

`tools/check_runtimes.py`:

- **Offline** (every PR, deterministic): actions pinned by SHA with a
  version comment; every job has `timeout-minutes`.
- **Online** (every PR and weekly): runtime versions in workflows and
  version files, runner labels, action runtimes and majors against live
  data. If a data source can't be reached, the check warns instead of
  failing, so an outage elsewhere doesn't block merges. The weekly run
  catches versions that age out while nobody is changing code.
- Dependabot (`github-actions` ecosystem) proposes action updates; this
  check catches what Dependabot doesn't cover: runtime versions, version
  files, and runner labels.

Not yet covered, and to be checked by hand: container base images
(`FROM node:…`), AWS Lambda runtimes (`Runtime: nodejs…`), and other
languages.
