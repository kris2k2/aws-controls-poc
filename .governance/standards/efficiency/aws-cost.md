# AWS Cost Standard: Idle Costs Near Zero

**Principle: an environment nobody is using should cost close to nothing.**
Pay for requests, not for capacity waiting for requests. Anything with an
hourly charge that runs whether or not there's traffic needs a written reason.

Aligned with the [AWS Well-Architected Cost Optimization pillar](https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar/welcome.html).
Cost controls double as security controls: budgets and concurrency caps limit
the damage from runaway loops, abuse, and denial-of-wallet attacks (OWASP LLM10).

## Default architecture choices

Choose from the left column first. Using the right column needs the
justification described under [Exceptions](#exceptions).

| Need | Default: near-zero when idle | Avoid unless justified: billed while idle |
|---|---|---|
| Compute | Lambda (arm64); ECS Fargate scaled to 0 tasks | Always-on EC2, EKS control plane, ECS on EC2 |
| HTTP entry | API Gateway HTTP API, Lambda function URL, CloudFront | Application/Network Load Balancer |
| Static site | S3 + CloudFront | EC2/containers serving files |
| Key-value / document data | DynamoDB on-demand | Provisioned-capacity tables sized for peak |
| Relational data | Aurora Serverless v2 with **minimum 0 ACU** (auto-pause); RDS stopped outside working hours for non-prod | Provisioned RDS/Aurora instances running 24/7 in non-prod |
| Cache | Skip it until measured; DynamoDB or CloudFront caching | Provisioned ElastiCache nodes |
| Queues and events | SQS, SNS, EventBridge, Step Functions (Standard for long, Express for high volume) | Self-managed brokers, provisioned MSK |
| Search | Managed DB query features first | OpenSearch domains (and Serverless, which has a minimum capacity charge) |
| Config and secrets | SSM Parameter Store (standard tier), Secrets Manager for secrets that rotate | Secrets Manager for plain config values |
| Outbound internet from private subnets | Run Lambda outside a VPC; VPC **gateway** endpoints for S3 and DynamoDB (free); IPv6 with egress-only internet gateway | NAT Gateway (billed per hour per AZ plus per GB), interface endpoints in every AZ |
| Scheduled jobs | EventBridge Scheduler → Lambda / Fargate task | Instances kept running to run cron |

Storage, minimum fees, and per-request charges still apply. "Near zero" means
the idle bill is dominated by stored data, not by running capacity.

## Rules

### Compute
- Lambda: `arm64` architecture by default; right-size memory with measurement
  (e.g. AWS Lambda Power Tuning); set a timeout matched to the work; set
  reserved concurrency as a cost ceiling on anything internet-facing.
- No provisioned concurrency, SnapStart priming, or warmers unless an SLO
  requires it and the PR says which one.
- Fargate: Graviton (`ARM64`), Fargate Spot for interruptible work, scheduled
  scale-to-zero for non-prod services.

### Networking
- Every NAT Gateway, load balancer, interface endpoint, and public IPv4
  address is billed hourly. Each one in a PR needs a reason.
- Non-prod shares one NAT Gateway at most, or has none.
- Put CloudFront in front of S3 and APIs serving the internet (lower egress
  cost, caching, and WAF in one place).
- Keep chatty traffic within one AZ and region where availability allows.

### Data and storage
- S3: lifecycle rules on every bucket (transition or expire); abort incomplete
  multipart uploads after 7 days; Intelligent-Tiering for unknown access patterns.
- DynamoDB: on-demand by default; TTL on transient items.
- CloudWatch Logs: **every log group has a retention period.** The default is
  never expire. Non-prod: 7–30 days. Prod: per the logging/compliance
  requirement (see OWASP A09). Debug-level logging off in prod.
- Delete unattached EBS volumes, old snapshots, and unused AMIs and ECR images
  (ECR lifecycle policy).

### Environments
- Non-prod is **ephemeral or scheduled**: per-PR preview stacks destroyed when
  the PR closes; shared dev/test scaled to zero or stopped outside working
  hours (Instance Scheduler on AWS, or EventBridge Scheduler).
- Everything is defined in IaC (CDK, Terraform, SAM, CloudFormation). If it
  isn't in code, it can't be torn down reliably.
- Separate AWS accounts per environment (AWS Organizations), so costs and
  blast radius are isolated and a sandbox can be closed by deleting the account.

### Guardrails (per account)
- **AWS Budgets** with alerts at 50%, 80%, and 100% of forecast, sent to a
  monitored channel.
- **Cost Anomaly Detection** monitor on, with alerts.
- **Mandatory cost allocation tags** on every resource: `project`, `env`,
  `owner`, and for non-prod `expires` (date). Enforce with tag policies and
  IaC linting; activate them as cost allocation tags in Billing.
- Service control policies in sandbox/dev accounts: deny unused regions,
  deny large or GPU instance families unless allowlisted.
- Review Cost Explorer, Compute Optimizer, and Trusted Advisor findings monthly.

### Pull requests that change infrastructure
- State the **idle monthly cost** (zero traffic) and the expected cost at
  normal load. Use an estimator such as Infracost or the AWS Pricing
  Calculator; a rough number with its assumptions beats none.
- Any new always-on resource names the exception it falls under.

## Exceptions

Always-on capacity is fine when the data says so, for example:

- sustained load where provisioned capacity is cheaper than per-request
  pricing (then buy Savings Plans or reserved capacity for it);
- latency SLOs that cold starts break;
- compliance or network-isolation requirements that need NAT or endpoints.

Record the reason in the PR (or an ADR for anything lasting), with the
monthly cost and the trigger for revisiting it.

## Review questions

1. What does this cost per month with zero traffic?
2. Which resources bill by the hour, and why does each one need to exist?
3. Does every log group, bucket, and table have retention or lifecycle rules?
4. Is there a hard ceiling (concurrency, throttling, budget alarm) if usage spikes or something loops?
5. Can this environment be torn down and recreated from code?
