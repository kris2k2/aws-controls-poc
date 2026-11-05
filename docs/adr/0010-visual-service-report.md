# ADR-0010: Every run ends with a visual HTML report of the service, its threat vectors and its guardrails

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner (pending review)

## Context

A run's results are spread over a dozen JSON files and a directory of
policies and detective artifacts. The people who decide on a release, and the
teams who will operate the service, need one page that says:

- what the service is;
- which threats its controls answer;
- what is actually implemented and proved;
- what is left open.

The owner asked for that page at the end of the pipeline.

## Decision

1. **`onboard/report.py` renders `report.html` from the run's files** and
   nothing else: capability profile, selection, control records,
   generation, verification and review. It decides nothing. A missing stage
   is said ("Verify hasn't run"), never filled in. `onboard report --run DIR`
   writes it on its own.
2. **Threat vectors come from control objectives.**
   - `OBJECTIVES` maps each objective to an attacker goal and a category:
     data exfiltration, unauthorized access, privilege escalation, defense
     evasion, insecure configuration, cost and accountability. Security Hub
     imports count as insecure configuration. Anything unmapped shows under
     "Other", and a test requires every Athena objective to be mapped.
   - A vector's coverage is the strongest layer the run generated for any of
     its controls, strongest first:
     - prevented: a guardrail;
     - plan-time: a Sentinel policy;
     - detected: a Config rule or a detection;
     - not covered: none of these.
   - Each vector lists its controls, with their mode, layers and Verify
     proof, plus the accepted risks and blind spots that apply.
3. **Sections:**
   - headline figures;
   - the service: API surface by risk tier, resource types, condition keys,
     dependencies, what Resolve hasn't assessed;
   - threat vectors;
   - implemented guardrails: policy sizes, then every control by platform
     with its proof;
   - the release review: decision, blockers, doubts that need a person;
   - sources and integrity hashes.
4. **Safe and self-contained:**
   - one file with inline CSS and no scripts, fonts or images;
   - a Content-Security-Policy of `default-src 'none'` plus inline styles;
   - every value from the run is HTML-escaped;
   - only `https://` URLs become links;
   - deterministic: no clock of its own, and the date shown is the review's.
   It works in light and dark mode, at phone width, and in print.
5. **Written at the end of every outcome.** `onboard run` writes
   `report.html` whether the run is delivered, held, blocked or failed a
   proof, as long as Generate ran, and records it in `run.json`. A report
   error is recorded there and doesn't change the run's result. On release,
   Deliver renders the report from the review it just made and seals it in
   the bundle, so the bundled report shows exactly the released review.

## Consequences

- A held or blocked run has a page to discuss, not just `review.json`.
- The threat statements in `OBJECTIVES` are the tool's wording. A new
  service's objectives need an entry, or they show as "Other" until someone
  writes one.
- The report carries what the run carries: account IDs, role patterns and
  doubts. It is internal, like the run directory and the bundle.
- `report.md` (the spec's Validate output) isn't built. This page covers its
  summary part; approvals over a hashed manifest are still Validate's.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Static HTML from the run files (chosen) | No dependency, opens anywhere, safe to attach to a review | Hand-written CSS; no interactivity |
| HTML with a chart library from a CDN | Richer charts | A third-party script in a security report; breaks offline; needs an ADR for the source host |
| Markdown | Diffable | Not visual; renders differently everywhere |
| A dashboard service | Live and cross-service | Infrastructure, cost and access control for a proof of concept |
