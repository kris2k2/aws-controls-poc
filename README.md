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
| 4. Generate | Partial: SCP and RCP guardrails, the allow-list, and the baseline VPC endpoint policy ([ADR-0004](docs/adr/0004-baseline-vpc-endpoint-policy.md)); Config, CloudTrail and Sentinel are reported as pending |
| Verify | Done for Athena: each generated deny proved against its security property over the attacker model, with mutation testing; writes `verification.json` ([ADR-0006](docs/adr/0006-verify-stage.md)). A new service needs its own spec in `onboard/specs/` |
| Review | Partial: a deterministic release decision (release, hold or blocked) from a reproduction check, its own run of Verify, checks on the policies, statement-bound impact and calibration evidence, and fingerprinted human acceptances ([ADR-0005](docs/adr/0005-risk-based-release-review.md)). No stage produces impact or calibration evidence yet, so runs hold |
| 5. Compose · 6. Validate | Not started; a local SCP/RCP evaluator backs the Level 1 guardrail tests, including the adversarial suite: a bounded proof of each guardrail against a reviewed security spec, plus mutation testing ([ADR-0003](docs/adr/0003-adversarial-verification-of-guardrails.md)) |

Initial test case: [Athena from Private Preview to Hardened](docs/simulations/athena-journey.md).

## Usage

Requires Python 3.13 or later. There are no third-party dependencies.

```sh
python3 -m onboard check-request request.json
python3 -m onboard resolve request.json --out runs/bedrock
python3 -m onboard resolve request.json --out runs/bedrock --snapshot snapshots/2026-10-30  # offline
python3 -m onboard assess request.json --run runs/bedrock --overlay overlay.json  # Control Catalog, read-only: needs AWS credentials in the environment
python3 -m onboard assess request.json --run runs/bedrock --control-catalog-snapshot snapshots/control-catalog  # offline
python3 -m onboard select request.json --findings runs/bedrock/findings.json --out runs/bedrock
python3 -m onboard generate request.json --run runs/bedrock
python3 -m onboard verify request.json --run runs/bedrock  # needs the service's spec in onboard/specs/ (Athena so far) and resolve's output in the run; exit 0 pass, 4 fail
python3 -m onboard review request.json --run runs/bedrock --acceptances acceptances.json  # exit 0 release, 3 hold, 4 blocked
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

Assess calls the AWS Control Catalog in `ca-central-1` with the credentials in
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Use a role
that allows only `controlcatalog:ListControls` and
`controlcatalog:ListControlMappings`. The overlay (`findings-overlay/v1`) holds
the analyst's candidates for the service; `assessment.json` lists what Assess
left to the analyst.

Keep real requests, org state and run outputs out of the repository.

## Development

```sh
python3 -m unittest discover -s tests -t .
```

A guardrail change also needs its security property in the service's spec
under `onboard/specs/` (what the control must deny); Verify and the
adversarial tests compare the generated statement with it. See
[section 5 of the Athena journey](docs/simulations/athena-journey.md#5-adversarial-verification).
