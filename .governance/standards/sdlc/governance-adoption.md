# Governance Adoption and Updates

How a project gets this governance baseline, keeps it current, and proves it
hasn't drifted. One tool does all of it:
[`tools/governance.py`](../../tools/governance.py) (`init`, `sync`, `check`,
`ci`).

## The model

```
kris2k2/agents  ── release vX.Y.Z (tag + CHANGELOG) ──►  project/.governance/   (managed, read-only copy)
                                                         project/AGENTS.md      (starter: thin, project-owned)
                                                         project/CLAUDE.md      (imports .governance/AGENTS.md)
                                                         project/.github/workflows/governance.yml       (runs governance.py ci)
                                                         project/.github/workflows/governance-sync.yml  (weekly sync PR)
```

| Part | Owned by | Changed how |
|---|---|---|
| `.governance/` (rules, standards, templates, tools, `VERSION`, `CHANGELOG.md`, `MANIFEST.json`) | the governance repository | **only** by `governance.py sync`; never edited by hand |
| Starter files (`AGENTS.md`, `CLAUDE.md`, the two workflows, `.pre-commit-config.yaml`, `.claude/settings.json`, PR template, `CODEOWNERS`, `dependabot.yml`) | the project | created by `init`; `sync` updates a file only while the project hasn't modified it, and otherwise lists it for review |
| Extension points (`.pii-allowlist`, `.piiignore`, bootstrap parameters, ADRs) | the project | normal PRs |

Why a copy in each project, and not a link to this repository: agents
(cloud sessions, Copilot, Cursor) only see files inside the repository they
work in, and a pinned copy means a project changes rules only when someone
merges a reviewed sync PR.

## Adopting (new or existing repository)

```sh
git clone https://github.com/kris2k2/agents /tmp/governance   # or --ref latest with GOVERNANCE_TOKEN set
cd my-project && git switch -c chore/adopt-governance
python3 /tmp/governance/tools/governance.py init --ref latest --project my-project
```

`init` installs the latest release into `.governance/`, creates the starter
files that don't exist yet (existing ones are kept and listed for manual
merge), and adds secret and local-settings patterns to `.gitignore`. Then:

1. Fill in "Project specifics" in `AGENTS.md`; commit with
   `chore(governance): adopt vX.Y.Z`; open a PR. Fix what CI finds.
2. `pip install pre-commit && pre-commit install` on each developer machine.
3. Repository settings (not files, so `init` can't do them):
   - branch protection or a ruleset on `main`: PRs required, code-owner
     review, the `governance` check required, no force-push;
   - secret scanning and push protection on;
   - Actions → "Allow GitHub Actions to create and approve pull requests" on
     (for governance-sync);
   - while the governance repository is private: a fine-grained token with
     read-only access to it, stored as the `GOVERNANCE_READ_TOKEN` secret.
4. Before the first adoption, audit the existing history:
   `python3 .governance/tools/pii_scan.py --git-range HEAD` (every commit)
   and gitleaks. Adoption only checks new changes; what's already committed
   stays in history until it's removed and any leaked secrets are rotated.

## Updating

- The `governance-sync` workflow runs weekly. It moves `.governance/` to the
  newest release **in the same major version**, updates unmodified starter
  files, and opens (or updates) one PR, `chore(governance): sync to vX.Y.Z`,
  whose description lists the changelog entries since the installed version
  and any starter files to review. It then starts CI on that PR (pushes made
  with `GITHUB_TOKEN` don't trigger workflows on their own).
- **Major versions** are never taken automatically. Read the breaking changes
  and migration notes, then run the workflow by hand with "allow-major", or
  run `governance.py sync --ref latest --allow-major` locally.
- Urgent fixes (e.g. a security patch release) don't wait for Monday: run
  `governance-sync` by hand.

## Verifying

`governance.py check` (part of `governance.py ci`, so it runs on every PR):

- every file in `.governance/` matches the hash in `MANIFEST.json`, nothing
  was added or removed: catches hand edits;
- with network access (and `GOVERNANCE_TOKEN` while private), the manifest
  matches the published release: catches a hand edit that also rewrote the
  manifest;
- starter files still wire the baseline in (warnings).

`CODEOWNERS` puts `.governance/` and the agent configuration under the
owner's review, so an agent can't change its own rules unreviewed.

## Forks of other people's projects

Don't add `.governance/` to forks you contribute upstream from; upstream has
its own conventions, and governance files shouldn't appear in your PRs to
them. Run the secret and PII scans on your branches locally instead.
