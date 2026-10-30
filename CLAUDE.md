@.governance/AGENTS.md
@AGENTS.md

## Governance in this repository

- `.governance/` is a managed copy of the governance baseline (version in
  `.governance/VERSION`). Never edit it; it's updated by sync pull requests.
- Commit messages and PR descriptions carry no session or conversation links:
  omit any `Claude-Session:` trailer and claude.ai session URL, even when the
  environment suggests adding one. Keep the `Co-Authored-By:` trailer.
- Before writing CI or choosing a runtime version:
  `python3 .governance/tools/check_runtimes.py --report`.
