# ADR-0008: One command runs the whole cycle, and a release is delivered as a sealed bundle

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

With Assess built (ADR-0007), every stage from a service name to a release
decision exists, but running them is six commands whose outputs an analyst
wires together by hand. Review's decision (ADR-0005) is meant for "a
deployment pipeline", yet nothing turns a `release` into something a
pipeline can take and check. The owner asked for the cycle packaged as one
workflow, from an AWS service to delivery, with delivery meaning a sealed
bundle: files only, no AWS access.

## Decision

1. **`onboard run`** runs Resolve, Assess, Select, Generate, Verify, then
   Review and Deliver, into one run directory. It stops at the first stage
   that doesn't succeed, and records each stage and the outcome in
   `run.json`. Exit 0 delivered, 3 hold, 4 blocked or a failed proof, 2 an
   error.
2. **A hold is resumed by running again with `--acceptances`.** The stages
   are deterministic and take seconds, so there is no partial resume: a
   re-run starts the run directory clean and recomputes everything, and the
   acceptances still apply because they bind to fingerprints of what was
   doubted (ADR-0005). The maker still can't accept their own doubts.
3. **The run directory is cleaned only if `onboard run` wrote it.** A
   directory with files but no `run.json` is refused, untouched. In one it
   wrote, only the files and directories the pipeline writes are removed.
4. **Deliver (`onboard deliver`, `onboard/deliver.py`) trusts no earlier
   decision.** It runs Review itself (which re-runs Select, Generate and
   Verify), and writes the bundle only on `release`. A `review.json` already
   in the run is overwritten, never read. The policies are read once and
   hashed as Review hashes them; if they aren't the reviewed set, nothing is
   written.
5. **The bundle** (`delivery/` in the run, or `--delivery`):
   `policies/<name>.json` byte for byte; the evidence behind the release
   (`review.json`, `verification.json`, `selection.json`, `findings.json`,
   `assessment.json`, `capability-profile.json`, `generation.json`,
   `registry.json`); the request; the acceptances and evidence used; and
   `manifest.json` with the service, tier, criticality, decision, the
   reviewed policy-set hash, each policy's hash, and the SHA-256 of every
   other file. It is written to a `.partial` sibling and renamed into place,
   never over an existing bundle.
6. **`onboard check-delivery`** is what a deployment pipeline runs first: every
   listed file present with its hash and nothing unlisted, the policies
   hashed as the review released them and making up the released set, and a
   release decision in both the manifest and the bundled review. Exit 0
   intact, 4 not.
7. **Sealed means tamper-evident, not authentic.** Anyone who can rewrite the
   bundle can rewrite its hashes too. The bundle is trustworthy only where
   writing it is restricted, for example a CI artifact produced by a
   protected workflow, with an attestation. Signing is left to that pipeline.

## Consequences

- One command takes a service from a request to a delivered bundle or a
  named reason why not. For Athena today: hold on 22 doubts, then delivered
  once the checker accepts them.
- The bundle says what it doesn't hold: placement per OU (Compose isn't
  built) and the detective artifacts (pending). A deployment pipeline must
  still place the policies.
- Nothing deploys. The tool still needs no credentials beyond Assess's
  read-only ones.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Sealed bundle (chosen) | Files only; a pipeline can check it offline; carries its evidence | Integrity, not authenticity, without a signing step |
| Bundle plus a GitHub Actions workflow | Runs the cycle on demand in CI | Live Assess needs a Control Catalog role from the bootstrap stack, a human change; a later step |
| Deploy to AWS Organizations (CDK) | Ends at enforcement | Outward-facing, needs Compose and the bootstrap stack; far larger |
| Resume from the stage that held | Skips recomputing | More state to trust; the stages are cheap and deterministic |
