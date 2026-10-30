# aws-controls-poc

A tool that takes one AWS service, assesses it from its API contract alone,
and produces a fact-checked control set: organization policies, IAM
permission boundaries, AWS Config rules, CloudTrail detections and Sentinel
policies, each with tests and traceability to frameworks. The tool writes
files only; it deploys nothing.

Design: the *AWS Service Onboarding Tool Spec* (draft v0.1).
Decisions: [`docs/adr/`](docs/adr/). Threat model:
[`docs/threat-models/onboarding-tool.md`](docs/threat-models/onboarding-tool.md).

## Status

| Pipeline stage | State |
|---|---|
| Request validation | Done: inputs, defaults, tier rules, maker/checker, exceptions, analyst decisions |
| Control model | Done: decision matrix, tier floors, escalation |
| 1. Resolve | Partial: prefixes, actions by risk tier, resources, condition keys, SDK operations. Crosswalk, dependencies, availability and capability flags are still to do |
| 2. Assess | Not started (the Athena test case uses hand-written findings) |
| 3. Select | Done: tier scope, modes, retirement on promotion, registry reuse and escalation, checker items, next tier; every NIST SP 800-53 identifier resolved in the pinned OSCAL catalog |
| 4. Generate | Partial: SCP and RCP guardrails and the allow-list; Config, CloudTrail and Sentinel are reported as pending |
| 5. Compose · 6. Validate | Not started; a local SCP/RCP evaluator backs the Level 1 guardrail tests |

Initial test case: [Athena from Private Preview to Hardened](docs/simulations/athena-journey.md).

## Usage

Requires Python 3.13 or later. There are no third-party dependencies.

```sh
python3 -m onboard check-request request.json
python3 -m onboard resolve request.json --out runs/bedrock
python3 -m onboard resolve request.json --out runs/bedrock --snapshot snapshots/2026-10-30  # offline
python3 -m onboard select request.json --findings findings.json --out runs/bedrock
python3 -m onboard generate request.json --run runs/bedrock
python3 -m onboard catalog --out catalogs/nist-sp-800-53-rev5.json  # refresh the pinned NIST catalog index
```

A minimal request (synthetic values):

```json
{
  "service": "Amazon Bedrock",
  "maturity_tier": "Private Preview",
  "preview_accounts": ["111122223333"],
  "non_production_attested": true,
  "org_state": {},
  "maker": "analyst-a",
  "checker": "analyst-b"
}
```

Keep real requests, org state and run outputs out of the repository.

## Development

```sh
python3 -m unittest discover -s tests -t .
```
