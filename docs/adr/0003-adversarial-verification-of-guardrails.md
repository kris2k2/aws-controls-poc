# ADR-0003: Verify generated guardrails against an attacker model

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)
- **Amended by:** [ADR-0006](0006-verify-stage.md): the spec and the attacker model moved
  from `tests/` to `onboard/specs/` and `onboard/adversary.py`, and the Verify
  stage runs the proof and the mutation testing on every run.

## Context

The security team's concern is that the generated organization policies are
not shown to be robust against adversarial use. Until now each guardrail had
three hand-written request vectors (positive, negative, break-glass), which
show it works for the requests its author thought of. Nothing tested what an
attacker could do. Probing the generated Athena policies with the local
evaluator found three gaps:

- The break-glass exemption `arn:aws:iam::*:role/BreakGlass-*` matched a role
  of that name in any account, so a principal outside the organization named
  `BreakGlass-x` passed the S3/KMS identity perimeter (RCP ORG-C-03).
- Nothing stopped a member account creating a `BreakGlass-*` role, or
  rewriting the trust policy of an existing one, and so skipping every
  guardrail.
- ATH-C-03's Spark deny list was hand-picked and missed `UpdateNotebook` and
  `UpdateNotebookMetadata`.

The threat model also claimed "mutation checks" that did not exist in the
repository.

## Decision

1. **A security spec, separate from the generated JSON.** Each preventive
   control has a property saying what it must deny, written from the
   control's objective (`tests/athena_security_spec.py`). The security team
   reviews the spec; the tests compare the generator's output to it.
2. **An explicit attacker model** (`tests/adversary.py`): the dimensions an
   attacker can vary, and which are set by AWS. Each takes every value the
   request names plus values it names nowhere (another organization account,
   an external account, the attacker's own VPC endpoint, regions outside the
   allow-list).
3. **Bounded proof, statement by statement.** Each generated statement must
   deny exactly what its property denies, over every combination of the
   dimensions either side reads; actions and resources are grouped into
   classes every pattern treats alike. A statement only reads its action,
   resource and the condition keys it names, and a property only the
   dimensions it declares (enforced), so the check is exhaustive over the
   model. Deny-overrides plus allow-list equivalence lifts it to whole-policy
   decisions under the SCP and RCP scoping rules.
4. **Contract completeness.** Every action in the API contract is listed in a
   reviewed file, and every action of an excluded capability is either denied
   or allowed with a reason. A contract refresh fails until new actions are
   reviewed.
5. **Exemptions are pinned and protected.** Break-glass principals must be IAM
   role ARNs in a 12-digit account, optionally ending in one `*` after a
   literal name; exception principals name exactly one role. A new shared
   containment control, ORG-C-04, denies the IAM role changes and
   `iam:PassRole` on every exempt role to everyone but break-glass. Guardrails
   can now name `resources`, including the `${protected_roles}` parameter.
   A guardrail can set `break_glass_exempt: false`; the data perimeter
   (ORG-C-02, ORG-C-03) does, so break-glass can't move data out of the
   organization (amended 2026-11-05, after reviewing how far each accepted
   risk reaches).
6. **Mutation testing.** The generated statements are mutated the ways a
   generator bug would break them; every mutant must be caught. Mutants that
   are equivalent in the model are listed with the reason, and the test fails
   if one of them starts being caught, so the list stays accurate.
7. **An accepted-risk register.** Deliberate gaps are pinned by requests that
   must stay allowed, each with an owner, a reason, a sign-off status, its
   reach (who can use it and from where), and boundary requests that must
   stay denied.

Everything stays standard library and offline (ADR-0001). The whole suite runs
in about a second.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| Spec + bounded model check + mutation, stdlib (chosen) | Offline, fast, reviewable; finds counterexamples; no new dependency | Proof is relative to the local evaluator and to the attacker model's dimensions |
| More hand-written vectors | Simple | Still only the requests someone thought of; no evidence of completeness |
| Random or property-based fuzzing (e.g. Hypothesis) | Finds surprises | A new dependency; samples, so passing proves little; flaky shrinking |
| SMT solving (z3, in the manner of Zelkova) | A real proof over all strings | A new native dependency needing an ADR and threat-model update; the policy semantics still have to be encoded by hand |
| IAM Access Analyzer custom policy checks | AWS's own reasoning engine | Needs AWS credentials and network in every test run, which the offline test rule excludes; a candidate for the calibration step instead |

## Consequences

- A guardrail change that denies too much or too little fails with a concrete
  request. Adding a guardrail without a property fails too.
- Requests with wildcard break-glass accounts now fail validation. Real
  requests must list the accounts holding break-glass roles.
- Whenever exemptions exist, an extra SCP statement (ORG-C-04) is deployed.
  It also stops ordinary pipelines from changing exception roles, which is
  intended.
- Break-glass can no longer write to, or read from, S3 outside the
  organization. Recovering from a data-perimeter mistake needs a policy
  change, not a break-glass session.
- Who can become break-glass is set by the break-glass roles' trust policies,
  which the tool neither generates nor checks. Until it does, AR-04 reaches
  whoever those policies admit.
- The proof means "holds in our model of AWS". Calibrating the evaluator
  against the IAM policy simulator and live calls in a sandbox account is
  still required before it is a claim about AWS. The attacker model must be
  extended before a guardrail can use a condition key it doesn't vary; the
  check fails until then.
- The spec, the action review and the accepted risks need security team
  review and sign-off; they are marked as proposed.
