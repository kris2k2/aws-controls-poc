# ADR-0004: Generate a baseline VPC endpoint policy for the data perimeter

- **Status:** proposed
- **Date:** 2026-11-05
- **Deciders:** repository owner and security team (pending review)

## Context

The generated guardrails were SCPs and RCPs. SCPs bind only the
organization's principals, and RCPs only its resources. A request by an
outside principal for an outside resource is bound by neither. So someone
inside the network holding credentials for an account they own (or none, for
a public bucket) could send data out through the organization's own VPC
endpoints, which carried AWS's default full-access policy. In the attacker
model, that upload was allowed with no policy involved.

Only a VPC endpoint policy binds every caller that comes through the
endpoint, whatever its credentials. The repository owner asked for this to be
contained as part of the baseline.

## Decision

1. **A new guardrail type and platform, `vpce`.** Its statements form one
   baseline policy, `vpce-org-guardrails`, for every VPC endpoint the
   organization runs. The policy starts with a base allow
   (`AllowUnlessDenied`), so the endpoint stops only what its guardrails deny
   and every deny traces to a control, followed by those denies. The
   generation report lists the endpoints in `org_state` to attach it to.
2. **ORG-C-05: only organization principals use the endpoints.** It denies a
   request whose `aws:PrincipalOrgID` isn't the organization's. Unsigned
   requests and standalone accounts have no such key; the negated operator
   denies them too.
3. **ORG-C-06: the endpoints reach only organization resources and named
   trusted accounts.** It denies a request whose `aws:ResourceOrgID` isn't the
   organization's, unless `aws:ResourceAccount` is in the request's new
   `trusted_resource_accounts`. It fails closed: a resource in a standalone
   account has no `aws:ResourceOrgID` and is denied.
4. **ORG-C-02 honours the same trusted accounts**, so naming a vendor works
   for S3 from organization principals too, not only at the endpoint.
5. **Optional parameters.** A guardrail can declare `optional_parameters`; a
   condition on one the request leaves empty is dropped, so an empty
   exception list means no exception rather than a failed run.
6. **Break-glass is held to both**, as to the rest of the data perimeter.
7. **Traffic that never reaches an endpoint is a registered risk (AR-05)**,
   pinned so that the same request through an endpoint stays denied.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| One baseline endpoint policy, base allow plus denies (chosen) | Reuses the guardrail generator and the adversarial checks; each deny traces to a control; one document to attach everywhere | Same policy on every endpoint, so service-specific needs mean exceptions |
| Allow-only endpoint policy (allow organization principals to organization resources) | The shape AWS uses in its data-perimeter examples | No deny to trace to a control; exceptions mean editing the one allow; mutants harder to tell apart from availability bugs |
| Per-service endpoint policies | Tighter per service | Many documents to keep in step; no service needs it yet |
| SCP on `aws:SourceVpce` alone (as ATH-C-04) | Already exists | Binds only organization principals: the gap is outside credentials |
| Network controls (no NAT/internet gateway, egress filtering) | Closes traffic around the endpoints | Infrastructure, not organization policy; outside this tool, so recorded as AR-05 |

## Consequences

- Through the organization's endpoints, outside credentials, unsigned
  requests and standalone accounts are denied, and organization principals
  reach only organization resources and named trusted accounts.
- **Availability:** calls with no resource, which carry neither
  `aws:ResourceOrgID` nor `aws:ResourceAccount` (for example
  `s3:ListAllMyBuckets`), are denied through the endpoints. So are AWS-owned
  resources such as package repositories and container image layers unless
  their accounts are named. This is deliberate fail-closed behaviour; it has
  to be checked against AWS before rollout, and exceptions named per
  organization.
- Endpoint support differs by service: whether each service's endpoint takes
  a policy, and supports these condition keys, has to be verified per service
  before attaching the baseline.
- Endpoints created later need the policy too; the Config rule and Sentinel
  policy declared on ORG-C-05 and ORG-C-06 are meant to catch one without it
  (both pending).
- Traffic that bypasses the endpoints still needs network controls (AR-05).
- All of this holds in the local evaluator's model until it is calibrated
  against AWS.
