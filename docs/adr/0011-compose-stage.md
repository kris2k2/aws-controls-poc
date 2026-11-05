# ADR-0011: Compose places the policies in the organization, checks its quotas and diffs it

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

Generate writes organization policies but not where they go. The tests
assumed organization policies at the root and the service's at the account,
and the delivery bundle said placement was left to the deployment pipeline
(ADR-0008). Three things were open:

- placement per OU level;
- budgets across every service in the organization;
- the diff against what the organization already has (`org_state`).

## Decision

1. **`org_state` describes the organization.**
   - `ous` lists OU paths, parents first, at most 5 levels deep.
   - `accounts` places each account in an OU.
   - `policies` lists every attached SCP and RCP, with its targets and its
     document or SHA-256.
   - Targets are `Root`, an OU path or an account ID. Compose validates all of
     it and fails on anything it can't place.
2. **Placement rules.**
   - The organization's guardrails go on the root.
   - The service's targets are its preview accounts at Private Preview, and
     `target_scope` after that.
   - In an allow-list organization (no `FullAWSAccess` on the root), an SCP
     allows an action only with an Allow at every level from the root to the
     account, the account included (AWS's SCP evaluation page). So the
     allow-list goes on the path to each target and on every OU and account
     under it. The service's denies go on the targets, which covers
     everywhere it is reachable.
   - In a deny-list organization, the service is reachable everywhere, so
     its denies go on the root and the allow-list isn't attached.
   - Endpoint policies go on every listed endpoint.
   - Detections are scoped to the root for shared controls and to the
     targets for the service's own, in every enabled Region. Config rules run
     in the allowed Regions. Sentinel policies go to the organization's
     Terraform policy sets.
3. **Budgets** use AWS Organizations' quotas, checked on 2026-11-05:
   - 10 SCPs and 5 RCPs attached directly to each root, OU or account;
   - `RCPFullAWSAccess` is on every node, can't be detached, and counts;
   - 10,240 characters per SCP and 5,120 per RCP.
   Every policy already attached counts, other services' included.
   Over budget is a result, not an error: `compose` exits 4, `onboard run`
   stops, and Review blocks. Compose never drops a guardrail to fit.
4. **The diff** covers only the policies this run manages
   (`*-org-guardrails` and `<type>-<service>-*`): each one is created,
   updated, unchanged or deleted, and every attachment is added or removed.
   Attachments are listed in the order to apply them: guardrails attached,
   allows attached, allows detached, guardrails detached. The service is
   never allowed anywhere without its guardrails in between. Detaching the
   allow-list from a node is listed under `removes_service_from`, and Review
   raises it as a Medium doubt.
5. **It is part of the release.** Compose is a pure function of the request
   and Generate's output.
   - Review re-runs it, blocks on a difference, a missing `composition.json`
     or an over-budget result, and records its hash.
   - Deliver requires it in the bundle.
   - The report shows it.
   - `onboard run` runs it after Verify.

## Consequences

- At Private Preview, Athena's allow-list goes on `Root`, `Sandbox`,
  `Sandbox/Preview` and the preview account, and its guardrails on that
  account.
- On promotion to Contained, both move to `Workloads/Analytics` and its
  account. The diff detaches them from the preview account, and Review asks
  whether removing Athena there is intended.
- The tests apply each composition through the local SCP evaluator. Athena
  is allowed exactly where it was placed, and the organization's guardrails
  hold in the preview account.
- An account added under a target later needs the allow-list too. The next
  run's diff shows it; nothing watches for it in between.
- `org_state` is what the analyst says the organization holds. Reading it
  from AWS Organizations (`ListPoliciesForTarget` and the OU tree) needs
  credentials and an ADR. Until then, a wrong `org_state` gives a wrong diff.
- Generate still caps SCPs at 5,120 characters, stricter than AWS's current
  10,240. That is safe; relaxing it is its own change.
- A mixed tree (`FullAWSAccess` on some OUs only) is treated by what is on
  the root, and isn't analysed per subtree.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Pure placement over a declared `org_state` (chosen) | Reproducible, testable offline, reviewed with the policies | Only as true as `org_state` |
| Read the organization live | Always current | Credentials and an outward call in a stage Review must reproduce |
| Service denies on the root in every organization | Survives a misplaced allow | A policy per service on the root runs into the quota after a few services |
| Leave placement to the deployment pipeline | Nothing to build | The released bundle doesn't say where its guardrails hold |
