# ADR-0006: A Verify stage that proves every run's guardrails, and a reviewer that trusts only its own proofs

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

ADR-0003 built the bounded proof and mutation testing, but only in the test
suite: they ran on the Athena fixtures, never on a real run. ADR-0005's
reviewer needs a proof for every deny it releases. Since nothing produced
one, every deny was a doubt and no run could release unattended.

The proof needs three things: the security spec (what each control must
deny), the attacker model, and the run's API contract. All three lived in
`tests/`.

## Decision

1. **The attacker model and the security specs move into the tool.**
   `tests/adversary.py` becomes `onboard/adversary.py`, unchanged in method.
   Its Athena-shaped sample resource and action are now derived from the
   service, and a statement or property that steps outside the model raises
   `ModelError` rather than `AssertionError`. The spec becomes a package,
   `onboard/specs/`: `organization.py` holds the shared `ORG-*` properties,
   one module per service holds its own (`athena.py`, with its action review
   `athena-action-review.json`), and `SERVICES` registers them. Each spec
   module carries its properties, its accepted risks and its equivalent
   mutants, each with a reason, and a status (`proposed` until the security
   team signs it off).
2. **A Verify stage, `onboard verify`** (`onboard/verify.py`), writes
   `verification.json`. For every deny the run deploys:
   - it checks the deny against its property over every combination of the
     attacker model (ADR-0003);
   - it mutates the statement and requires every mutant the spec doesn't list
     as equivalent to be caught;
   - it fails a capability control while the contract has actions the action
     review doesn't classify.

   A deny with no property, an active property with no deny, a deny for a
   control that isn't preventive, or a deny in the wrong kind of policy all
   fail. Each proof is bound to the SHA-256 of its statement. The report also
   records the spec's and the attacker model's hashes and the accepted risks
   that apply. Exit 0 on pass, 4 on fail.
3. **The reviewer proves the run itself.** Review re-runs Verify, as it
   re-runs Select and Generate, and blocks if a `verification.json` in the run
   differs from the result. **Proofs come only from that run;** outside
   evidence may supply impact replays and calibration, never proofs. Without
   the run's capability profile, nothing is proved and every deny stays a
   doubt.
4. **What the proofs rest on becomes doubts.** Two new doubts are added to
   ADR-0005's table:

   | Doubt | Risk |
   |---|---|
   | The security spec the proofs are against isn't signed off | Medium |
   | Each accepted risk whose controls are preventive in the run, until signed off | Medium |

   Both are fingerprinted by content, so a sign-off in the spec, or a
   person's acceptance, holds until the spec or the risk changes.
5. **Accepted risks are pinned in the tests, not in the tool.** The register
   (what the gap is, why, its reach, its owner and status) is in the spec.
   The requests that show each gap is open exactly as wide as registered
   depend on an existing allow-list, so they stay in
   `tests/test_athena_adversarial.py` as `RISK_PINS`. The tests check that
   every risk has a pin, and that the tiers each pin covers are the ones
   where Verify reports the risk.

Still standard library and offline (ADR-0001). One run verifies in about
0.15 s.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| Specs as Python modules in the tool; reviewer re-runs Verify (chosen) | No new format to design; properties stay readable code next to the model they use; nothing to forge | Specs are code, so reviewing one means reading Python; a new service needs a module, not a file |
| Specs as JSON or YAML with a small expression language | Reviewable by people who don't read Python; could live outside the tool | A language to design, document and get right; its interpreter becomes part of every proof |
| Verify writes evidence; reviewer trusts it | Review stays fast | Anyone who can write the run directory can forge a proof, which is exactly what the reviewer exists to stop |
| Leave the proofs in the test suite | No change | Real runs are never proved; the reviewer can't release anything |

## Consequences

- Athena's runs now come out of Verify with every deny proved: 10 at Private
  Preview, 11 at Contained and Hardened (12 with an exception at High
  criticality), and 150 to 190 mutants caught per run. The Private Preview review still holds, with 22 doubts for a person
  (down from 27) and 11 accepted by the reviewer. What is left is no longer
  "is it proved" but:
  - impact replays for the 6 organization-wide denies (High);
  - calibration of the evaluator;
  - sign-off of the spec and of 4 accepted risks;
  - the inferred severities;
  - break-glass.
- Assess producing weak findings is now caught. If findings drop a Spark
  action from ATH-C-03, Select and Generate faithfully reproduce the
  weakened guardrail, and the proof against the reviewed spec blocks it.
- Releasing for a service with no spec is impossible: it holds on proof
  doubts. Onboarding a new service now includes writing its spec module,
  which the security team reviews (CODEOWNERS covers `onboard/specs/`, the
  attacker model, the evaluator, Verify and Review).
- The test suite takes a few seconds rather than about one, because the
  review tests prove each run they build.
- The proofs still mean "holds in the local evaluator's model of IAM";
  calibration (ADR-0003) is unchanged and still a doubt.
- The tests' pinning of accepted risks, and the named attacks, still use the
  test organization's allow-list. Verify can pin risks itself once Compose
  reads the organization's existing policies from `org_state`.
