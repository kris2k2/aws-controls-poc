# ADR-0005: Release policy sets on a risk-based review, with doubts named for a person

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)
- **Amended by:** [ADR-0006](0006-verify-stage.md): the reviewer now proves each run itself
  with Verify, takes no proofs from outside evidence, and raises doubts for an
  unsigned security spec and for each accepted risk.

## Context

The pipeline now generates policy sets with evidence behind them: reproducible
stages, gates, and a bounded proof against an attacker model (ADR-0003). The
next step is releasing them to production without a person reading every
statement on every run. The spec's maker/checker model asks a checker to
approve each run, which doesn't scale across services and promotions, and
makes the checker approve the same unchanged statements again and again.

The aim: when the evidence is strong enough, a run releases on its own; when
it isn't, the gaps are named in advance as specific doubts for a person to
accept, not discovered in a free-form review.

Two kinds of failure matter for organization policies, and the existing
evidence covers only one:

- **Too permissive** (a security gap): covered by the bounded proof and
  mutation testing, in the local evaluator's model of IAM.
- **Too restrictive** (an outage): an SCP deny at the root reaches every
  account. Nothing yet shows which running workloads a new deny would break.

## Decision

1. **A deterministic Review stage, `onboard review`** (`onboard/review.py`).
   Its decision is a function of the run directory, verification evidence,
   recorded acceptances, the request and the date. It writes `review.json`
   and deploys nothing; a deployment pipeline reads it. No model is called.
2. **It trusts nothing the earlier stages say about themselves.** It re-runs
   Select and Generate from the run's findings and request and requires every
   file to match, then checks the documents to be released on their own
   terms: size, unresolved parameters, every deny traces to an enforcing
   control, and no Allow other than the service allow-list and the endpoint
   base allow.
3. **Three outcomes.**
   - **Blocked:** something no person may wave through: an edited or missing
     file, a failed proof, impact replay or calibration, an unexpected Allow.
     Fix the run.
   - **Hold:** no blockers, but doubts above the auto-accept ceiling await a
     person. The review lists each doubt with the question a person answers
     by accepting it (`accept_means`), plus a ready-to-fill acceptance file.
   - **Release:** no blockers and every doubt accepted, by the reviewer or by
     a person.
4. **Doubts carry an ordinal risk, not a confidence percentage.** Risk is the
   impact of being wrong:

   | Doubt | Risk |
   |---|---|
   | No proof, or no impact replay, for an organization-wide deny | High |
   | The decision matrix differs from the default | High |
   | No proof, or no impact replay, for a service's own deny | Medium |
   | Inferred severity of High or above | Medium |
   | Evaluator not calibrated against AWS | Medium |
   | Break-glass exemption (trust policies unchecked, AR-04) | Medium |
   | Trusted resource accounts (data may leave to them) | Medium |
   | An approved exception | Medium |
   | A control retired on promotion (a deny is lifted) | Medium |
   | A control left out by an analyst decision | Medium |
   | An enforcing control with nothing deployed for it (F11) | Medium |
   | Enforcing on inferred framework mappings only | Low |
   | Detective artifacts not generated yet | Low |

   Impact replays are required where a deny can reach running workloads:
   every organization-wide deny, and a service's own denies on a promotion
   (on a new service nobody can use it yet).
5. **The threshold is an auto-accept ceiling set by criticality:** Low
   accepts up to Medium, Moderate up to Low, High nothing. It is a constant
   in the code; changing it needs an ADR, not a flag, so a maker can't lower
   the bar for their own run.
6. **Acceptances are bound to what was doubted.** Each doubt has a
   fingerprint: the SHA-256 of its kind, subject and the material it is
   about (the statement, the control's severity and mode, the exception, the
   break-glass list). An acceptance names the fingerprint, who accepted it,
   an expiry and a rationale. It carries over to later runs while the
   material is unchanged and lapses the moment it changes, so a person
   reviews each change once and the reviewer re-checks it on every run. The
   maker can't accept doubts about their own run.
7. **Evidence is bound to the exact statement** by the SHA-256 of its
   canonical JSON (`evidence/v1`: kind `proof`, `impact` or `calibration`,
   `result`, `source`). Calibration evidence is bound to the hash of the
   evaluator's source. Evidence for a statement that has since changed is
   reported as stale and not used.
8. **The release binds to content.** `review.json` records the SHA-256 of
   each policy and of the whole set. A deployment must release exactly that
   set, and only on `release`.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| Deterministic reviewer, ordinal risk, fingerprinted acceptances (chosen) | Same inputs, same answer; every decision traces to a named rule; offline and fast; no new dependency | Only finds the doubts it has rules for; the rules need review |
| An LLM reviewer judging the policy set | Can notice things nobody wrote a rule for | Not reproducible; open to prompt injection from the content it reads (control titles, rationales); a confident wrong "approve" is the worst failure; a model call needs its own ADR and threat-model update |
| A weighted confidence score (e.g. release above 0.9) | One number to report | The weights are made up and uncalibrated; many small doubts can hide one large one; easy to tune until it passes |
| Keep a person approving every run | Simple; matches the spec today | Doesn't scale; reviewers rubber-stamp unchanged statements, which is how changed ones slip through |

A model can be added later as a **critic that only adds doubts**: it can
raise a question for a person, never accept one or lower a risk. That needs
its own ADR first (AGENTS.md).

## Consequences

- Today no run releases on its own: no stage produces proof, impact or
  calibration evidence yet, so every deny is a doubt, and the organization-
  wide ones are High. The Athena Private Preview run holds with 27 doubts for
  a person and 11 accepted by the reviewer. That is the honest result.
- To reach unattended release, the next pieces are:
  1. **Verify stage** (done, ADR-0006): move the attacker model and bounded proof from
     `tests/` into the tool, with per-service security specs, so a run writes
     its own `proof` evidence.
  2. **Impact replay:** replay recent CloudTrail activity (or IAM Access
     Analyzer checks) through the evaluator to show which existing calls a
     deny would block. Needs AWS access and its own ADR.
  3. **Calibration:** replay the proofs through the IAM policy simulator in a
     sandbox account (ADR-0003).
  4. **Authenticated acceptances:** this slice checks an acceptance's
     content, not who wrote it. Acceptances must come from a system that
     authenticates the person, such as a reviewed pull request to a protected
     acceptances file with CODEOWNERS.
  5. **Deployment:** a pipeline that deploys only on `release`, checks
     `policy_set_sha256`, and goes through the project's bootstrap stack.
- This changes the spec's maker/checker model: doubts within the ceiling are
  accepted without a checker. The security team needs to agree to that, and
  to the risk table and the ceiling.
- The accepted risks AR-01 to AR-05 live in the test suite's security spec;
  only AR-04 is raised as a doubt. They become doubts once the spec moves
  into the tool with Verify.
