# ADR-0012: Replay CloudTrail for impact evidence, and stop asking people what can't change the outcome

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

## Consequences

- Athena's journey, with 40 days of synthetic activity and acceptances
  carried forward, needs 20 human decisions instead of 43: 7 at Private
  Preview, 13 at Contained, none at Hardened.
- What is left is judgement no evidence answers:
  - the spec and its accepted risks (6);
  - F11, whether Enforce with override may rest on a Sentinel policy (6);
  - calibration (1), break-glass trust policies (1), the trusted resource
    account (1), retiring the preview restriction (1), removing Athena from
    the preview account (1);
  - three supervision severities that do change a mode (3).
  Signing off the spec, and deciding F11, would remove 12 of the 20 for
  every later run.
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
