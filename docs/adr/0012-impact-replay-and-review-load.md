# ADR-0012: Replace review questions with checks: impact replay, trust policies, documented calibration

- **Status:** proposed
- **Date:** 2026-11-06
- **Deciders:** repository owner and security team (pending review)

## Context

Too many release questions went to people. Running Athena through all three
tiers took 43 human decisions, even with acceptances carried forward as
ADR-0005 intends: 22 at Private Preview, 20 at Contained, 1 at Hardened.
Three kinds of question didn't need a person:

- **Moot severities (9 at Private Preview).** Review asked a person to
  confirm every inferred High or Critical severity. On a containment
  control, the tier floor makes the mode Enforce whatever the severity, so
  the answer could change nothing.
- **A repeated retirement (1 at Hardened).** ATH-C-01's retirement was asked
  again at Hardened, after it had been lifted, and accepted, at Contained.
- **Impact questions (13).** "Does this deny break a running workload?" was
  asked of every organization-wide deny, and of a service's denies on a
  promotion. Review accepts impact evidence (ADR-0005), but nothing produced
  it, so a person had to answer from memory. These were the High-risk ones.

## Decision

1. **An inferred severity is asked only when it matters.** Review skips the
   question when every severity gives the control the same mode at every
   criticality. Select still lists it for the checker.
2. **A retirement is asked once**, on the promotion right after the
   control's `until_tier`.
3. **`onboard impact` replays CloudTrail** (`onboard/impact.py`). It takes
   CloudTrail log files and runs every successful call through every deny
   the run would deploy, where Compose attaches it: SCPs bind the accounts
   under their targets, RCPs bind organization resources, and endpoint
   policies bind calls through the endpoints. It writes `impact.json`
   (evidence/v1, bound to each statement's hash):
   - `pass` when no call in scope would be denied;
   - `fail`, listing the calls, when some would be. Review blocks, as
     ADR-0005 says for a failed replay;
   - no item when a call lacks a field the deny's conditions read. That
     question stays with a person.
4. **What the replay knows comes only from CloudTrail and `org_state`.**
   - Organization membership comes from `org_state`'s accounts; any other
     account is outside the organization. That can only make a replay fail,
     never pass.
   - The resource owner comes from `resources`, or else `recipientAccountId`.
   - Assumed roles come from their session issuer, the endpoint from
     `vpcEndpointId`, a service call from `invokedBy`, request tags from
     `requestParameters.tags`.
   - A call whose action the deny doesn't cover is out of scope.
   - IAM action names are taken as `<eventSource prefix>:<eventName>`.
5. **Review needs 30 days of history.** An impact item must carry its
   window, and Review ignores one under 30 days, saying so.
6. `onboard run --cloudtrail FILE` runs the replay after Compose. Review
   reads `impact.json` from the run, and Deliver bundles it with the other
   evidence.

The owner then set a target of fewer than 5 human decisions for the whole
journey. Each remaining question was checked for a test that answers it:

7. **The spec is one sign-off.** The spec and every accepted risk in it,
   whichever tier it applies from, are one question, fingerprinted on the
   spec. One acceptance covers the journey until the spec changes. Once the
   spec is approved, any accepted risk still unapproved is asked on its own,
   as before.
8. **Break-glass trust policies are checked, not asked.**
   - `org_state.roles` gives each role's trust policy. Every role matching a
     break-glass pattern may trust only principals in the organization's
     accounts: IAM principals with `aws:MultiFactorAuthPresent` required, or
     identity providers in those accounts.
   - A wildcard principal, a service, an outside account or a missing MFA
     condition blocks.
   - A pattern with no role in `org_state` is still asked.
9. **A severity at Enforce isn't asked.** At the strictest mode, an
   overstated severity can only over-enforce, which is an outage, and the
   impact replay (or its question) covers outages. It can't leave anything
   under-enforced.
10. **Enforced as far as AWS allows (decides F11).** An enforcing control
    with no guardrail isn't asked about when all of these hold:
    - no guardrail platform is planned;
    - where the control says no condition key exists, the API contract
      confirms the service offers only global keys;
    - every planned Config rule, detection and Sentinel policy is
      generated;
    - none of them is vacuous: an empty resource fails it, and an empty event
      doesn't match it.
    Then nothing more can enforce it. Enforce with override, for such a
    control, means its soft-mandatory Sentinel policy plus its detection.
11. **A retirement covered by placement isn't asked.** In an allow-list
    organization, a retired deny over the service's own actions is replaced
    by Compose: the allow-list confines the service to the request's
    targets. A deny-list organization is still asked.
12. **Calibration against AWS's documentation.**
    - `onboard/calibration.py` holds 18 cases, each quoted from an AWS
      documentation page (checked 2026-11-06). They cover SCP levels, deny
      precedence, RCP scope, condition operators with absent keys, IfExists,
      Null, NotAction and the default endpoint policy.
    - Review runs it itself. A failing case blocks. All passing lowers the
      calibration question to Low: accepted automatically at Moderate, still a
      person at High. Only replaying live calls closes it.
    - Assumptions the pages don't state are listed in the question.
    - A test mutates the evaluator three ways and the suite catches each.

## Consequences

- Athena's journey, with 40 days of synthetic activity and acceptances
  carried forward, needs 4 human decisions instead of 43:
  - the spec sign-off at Private Preview;
  - the trusted resource account, removing Athena from the preview account,
    and ATH-S-04 (its Config rule isn't defined yet) at Contained;
  - nothing at Hardened.
  At High criticality calibration is asked too: High accepts nothing
  automatically.
- What is left is judgement no test answers: whether the spec and its
  risks are right, whether an outside account may receive data, and whether
  taking the service from an account is intended. A Config definition for
  ATH-S-04 would remove a fourth question.
- `org_state.roles` is declared, like the rest of `org_state`: a wrong trust
  policy there gives a wrong answer. Reading the roles from IAM needs
  credentials and an ADR.
- F11 is decided by rule 10. A control whose guardrail is possible but not
  deployed (Enforce with override with no exception) is still asked.
- The replay sees only what was logged. Read-only calls appear only if the
  trail records them, and S3 object calls only with data events. An API
  whose name differs from its IAM action can be missed (finding F3). The
  window shows only the past: a rarely-run job outside it isn't covered.
- The evidence is checked for content, not authorship (ADR-0005). The
  replay records the SHA-256 of its input, but a forged log yields forged
  evidence. In a pipeline, the replay should read the organization trail's
  bucket directly, which needs read-only credentials and its own ADR.

## Alternatives considered

| Option | Pros | Cons |
|---|---|---|
| Replay CloudTrail through the denies (chosen) | Evidence from the organization's own activity; fails loudly when a deny would break something | Only as complete as the log and the window |
| Raise the auto-accept ceiling | One constant | Lets High-risk impact questions through unanswered; ADR-0005 makes the ceiling a reviewed decision |
| Group doubts of a kind into one question | Fewer clicks | The same number of decisions, with coarser acceptances that lapse together |
| IAM Access Analyzer's policy checks or last-accessed data | AWS-run | Needs credentials; last-accessed data is per service, not per statement and condition |
