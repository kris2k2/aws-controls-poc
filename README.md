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
| Request validation | Done: inputs, defaults, tier rules, maker/checker, exceptions |
| Control model | Done: decision matrix, tier floors, escalation |
| 1. Resolve | Partial: prefixes, actions by risk tier, resources, condition keys, SDK operations. Crosswalk, dependencies, availability and capability flags are still to do |
| 2. Assess · 3. Select · 4. Generate · 5. Compose · 6. Validate | Not started |

## Usage

Requires Python 3.13 or later. There are no third-party dependencies.

```sh
python3 -m onboard check-request request.json
python3 -m onboard resolve request.json --out runs/bedrock
python3 -m onboard resolve request.json --out runs/bedrock --snapshot snapshots/2026-10-30  # offline
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
