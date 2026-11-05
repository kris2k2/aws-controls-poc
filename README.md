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
| 2. Assess | Partial: the shared organization baseline, the derived preview restriction, and the service's Security Hub controls from the AWS Control Catalog with AWS's severities and NIST mappings; the analyst adds the judgment controls as an overlay ([ADR-0007](docs/adr/0007-assess-from-the-control-catalog.md)). Not yet run against AWS; Config-rule and proactive controls aren't imported |
| 3. Select | Done: tier scope, modes, retirement on promotion, registry reuse and escalation, checker items, next tier; every NIST SP 800-53 identifier resolved in the pinned OSCAL catalog |
| 4. Generate | Partial: SCP and RCP guardrails, the allow-list, and the baseline VPC endpoint policy ([ADR-0004](docs/adr/0004-baseline-vpc-endpoint-policy.md)); Config rules, EventBridge detections of CloudTrail events and Sentinel policies from each control's structured definition ([ADR-0009](docs/adr/0009-detective-and-plan-time-artifacts.md)), checked by a local evaluator but not yet run in AWS Config, EventBridge or Sentinel. Permissions boundaries, and implementations with no structured definition, are reported as pending |
| Verify | Done for Athena: each generated deny proved against its security property over the attacker model, with mutation testing; writes `verification.json` ([ADR-0006](docs/adr/0006-verify-stage.md)). A new service needs its own spec in `onboard/specs/` |
| Review | Partial: a deterministic release decision (release, hold or blocked) from a reproduction check, its own run of Verify, checks on the policies, statement-bound impact and calibration evidence, and fingerprinted human acceptances ([ADR-0005](docs/adr/0005-risk-based-release-review.md)). No stage produces impact or calibration evidence yet, so runs hold |
| Run · Deliver | Done: `onboard run` takes a request through every stage; on release, Deliver re-runs Review and writes a sealed bundle (the reviewed policies and detective artifacts, their evidence and a hashed manifest) that `onboard check-delivery` checks ([ADR-0008](docs/adr/0008-run-and-sealed-delivery.md)). Deploys nothing |
| Report | Done: `report.html` at the end of every run, held and blocked included: the service, its threat vectors with their coverage, accepted risks and blind spots, the implemented guardrails with their proofs, and the release review; self-contained, no scripts, sealed in the delivery bundle ([ADR-0010](docs/adr/0010-visual-service-report.md)) |
| 5. Compose | Done: places every policy in the OU tree from `org_state` (allow-list on every level to each target and below it, guardrails on the targets, organization guardrails on the root), checks AWS Organizations' quotas across every service's attachments, and diffs against `org_state` in a safe apply order; Review reproduces it and blocks over budget ([ADR-0011](docs/adr/0011-compose-stage.md)). `org_state` is declared, not read from AWS |
| 6. Validate | Not started; a local SCP/RCP evaluator backs the Level 1 guardrail tests, including the adversarial suite: a bounded proof of each guardrail against a reviewed security spec, plus mutation testing ([ADR-0003](docs/adr/0003-adversarial-verification-of-guardrails.md)) |

Initial test case: [Athena from Private Preview to Hardened](docs/simulations/athena-journey.md).

## Usage

Requires Python 3.13 or later. There are no third-party dependencies.

The whole cycle, from a service to a delivery bundle:

```sh
python3 -m onboard run request.json --out runs/bedrock --overlay overlay.json  # exit 0 delivered, 3 hold, 4 blocked
# On hold: a checker (not the maker) fills in acceptance_template from runs/bedrock/review.json, then
python3 -m onboard run request.json --out runs/bedrock --overlay overlay.json --acceptances acceptances.json
python3 -m onboard check-delivery runs/bedrock/delivery  # what a deployment pipeline runs first
```

Every run ends with `runs/bedrock/report.html`, a visual summary of the
service, its threat vectors and its implemented guardrails (also in the
bundle on delivery).

Or stage by stage:

```sh
python3 -m onboard check-request request.json
python3 -m onboard resolve request.json --out runs/bedrock
python3 -m onboard resolve request.json --out runs/bedrock --snapshot snapshots/2026-10-30  # offline
python3 -m onboard assess request.json --run runs/bedrock --overlay overlay.json  # Control Catalog, read-only: needs AWS credentials in the environment
python3 -m onboard assess request.json --run runs/bedrock --control-catalog-snapshot snapshots/control-catalog  # offline
python3 -m onboard select request.json --findings runs/bedrock/findings.json --out runs/bedrock
python3 -m onboard generate request.json --run runs/bedrock  # org-policies/ and detective/ (Config, EventBridge, Sentinel)
python3 -m onboard compose request.json --run runs/bedrock  # composition.json: placement, quotas, diff against org_state; exit 0 fits, 4 over budget
python3 -m onboard verify request.json --run runs/bedrock  # needs the service's spec in onboard/specs/ (Athena so far) and resolve's output in the run; exit 0 pass, 4 fail
python3 -m onboard review request.json --run runs/bedrock --acceptances acceptances.json  # exit 0 release, 3 hold, 4 blocked
python3 -m onboard deliver request.json --run runs/bedrock --acceptances acceptances.json  # reviews again; on release writes runs/bedrock/delivery
python3 -m onboard report --run runs/bedrock  # report.html: service, threat vectors, guardrails, review
python3 -m onboard catalog --out catalogs/nist-sp-800-53-rev5.json  # refresh the pinned NIST catalog index
```

A minimal request (synthetic values):

```json
{
  "service": "Amazon Bedrock",
  "maturity_tier": "Private Preview",
  "preview_accounts": ["111122223333"],
  "non_production_attested": true,
  "org_state": {"organization_id": "o-exampleorgid", "ous": [{"path": "Sandbox"}],
                "accounts": [{"id": "111122223333", "ou": "Sandbox"}], "policies": []},
  "maker": "analyst-a",
  "checker": "analyst-b"
}
```

Assess calls the AWS Control Catalog in `ca-central-1` with the credentials in
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Use a role
that allows only `controlcatalog:ListControls` and
`controlcatalog:ListControlMappings`. The overlay (`findings-overlay/v1`) holds
the analyst's candidates for the service; `assessment.json` lists what Assess
left to the analyst.

`org_state` is the organization as it stands: OU paths (parents first),
accounts and their OU, and every attached SCP and RCP with its targets
(`Root`, an OU path or an account ID) and its document or SHA-256. Compose
places the policies in it and diffs against it ([ADR-0011](docs/adr/0011-compose-stage.md)).

Keep real requests, org state and run outputs out of the repository.

## Development

```sh
python3 -m unittest discover -s tests -t .
```

A guardrail change also needs its security property in the service's spec
under `onboard/specs/` (what the control must deny); Verify and the
adversarial tests compare the generated statement with it. A Config rule,
detection or Sentinel policy is a structured definition on the control's
implementation ([ADR-0009](docs/adr/0009-detective-and-plan-time-artifacts.md));
`tests/test_detective.py` checks what it catches. See
[section 5 of the Athena journey](docs/simulations/athena-journey.md#5-adversarial-verification).
