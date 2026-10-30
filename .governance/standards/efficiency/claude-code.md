# Claude Code Efficiency Standard

**Goal: spend tokens on the work, not on re-reading context.** Every request
re-sends the whole conversation, so cost and latency grow with context size.
Small, focused context gives faster, cheaper, and usually better answers.

Reference: [Manage costs effectively](https://code.claude.com/docs/en/costs).
Most of these practices apply to other coding agents as well.

## Repository setup (do once, benefits every session)

- **Keep `CLAUDE.md` / `AGENTS.md` short** (well under 200 lines). They load
  into every session. Put detailed, task-specific guidance in linked docs
  (like `standards/`) or in [skills](https://code.claude.com/docs/en/skills),
  which load only when relevant. Use `@imports` only for files that every
  session really needs; an import loads the whole file up front.
- **Write the project's commands into `CLAUDE.md`**: build, test (single test
  and full suite), lint, and run commands. This saves the agent from
  rediscovering them every session.
- **Describe the layout briefly**: where the entry points, domain logic,
  and tests live. A few lines prevent a lot of exploratory reads.
- **Pre-approve safe, read-only commands** in `.claude/settings.json`
  `permissions.allow` (test runners, linters, `git status`/`diff`/`log`). Each
  permission prompt stalls the session until a human answers. Keep `deny`
  rules for anything risky (see [AGENTS.md](../../AGENTS.md)).
- **Keep generated and vendored files out of reach**: `.gitignore` build
  output and dependencies, and add `Read(...)` deny rules for large generated
  paths the agent should never open.
- **Fast hooks**: hooks run on every matching tool call. Keep each under
  ~1 second, and have them return only what matters (e.g. failing tests,
  not the full log).
- **Cloud sessions**: a SessionStart hook that installs dependencies saves
  each session from working out the setup on its own.
- **MCP servers**: enable only the servers a project uses. A CLI that's
  already installed (`gh`, `aws`) is usually more context-efficient than an
  MCP server for the same job.
- **Typed languages**: install the code-intelligence (LSP) plugin so the agent
  can jump to definitions instead of grepping and reading candidate files.

## Working habits

- **One task per session.** `/clear` when switching to unrelated work; stale
  context is paid for on every later message. `/compact <what to keep>` when
  you need continuity.
- **Specific prompts**: name the file, function, and expected behaviour, and
  give a way to verify (a test, a command, expected output). "Improve this
  codebase" triggers broad, expensive scanning.
- **Plan first for larger changes** (plan mode) and correct course early
  (`Esc`, `/rewind`). Re-work is the most expensive token spend.
- **Match the model and effort to the task.** Use the default
  general-purpose model for most coding. Reserve the largest model and high
  effort for architecture and hard debugging. Give simple subagent tasks
  (search, summarising logs) a smaller, cheaper model in the subagent's
  configuration.
- **Read narrowly**: search first, then read the relevant range of a file,
  not the whole thing. Pipe noisy command output through `tail`, `grep`, or
  quiet flags.
- **Subagents** keep high-volume output (test logs, documentation fetches,
  wide searches) out of the main context, but each one starts cold and
  re-reads what it needs. Use them for genuinely large or parallel fan-out,
  not for a single grep.
- **Batch independent tool calls** in one turn instead of one per turn.
- **Avoid unattended idle loops**: scheduled tasks, `/loop`, and polling each
  re-send the full context every time they fire. Prefer event-driven wakeups.

## Teams and automation

- Track spend: `/usage` per session; for teams use the org analytics, the
  Console workspace limits, or OpenTelemetry export
  ([monitoring](https://code.claude.com/docs/en/monitoring-usage)).
- Set spend limits for the organization or workspace, and per-user limits
  where available.
- Headless and CI runs (`claude -p`) always set `--max-turns` and
  `--max-budget-usd`, a job `timeout-minutes`, and a narrow `--allowedTools`
  list. See [ci-github-actions.md](ci-github-actions.md#agents-in-ci).
- Agent teams and multi-agent workflows multiply token use by roughly the
  number of agents. Keep teams small and tasks self-contained, and shut
  agents down when they're done.

## Review questions (for changes to agent configuration)

1. Does this add lines to always-loaded context (`CLAUDE.md`, `AGENTS.md`,
   imports)? Could it be a linked doc or a skill instead?
2. Does a new hook run on every tool call, and how long does it take?
3. Does a new MCP server or plugin pay for its context cost?
4. Do automated or headless runs have turn, budget, and time limits?
