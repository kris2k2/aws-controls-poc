# Threat Model: <feature name>

> Copy into the project's `docs/threat-models/` and fill in. Required for
> features touching authentication, authorization, payments, personal data,
> file upload, external integrations, or LLM/agent capabilities.
> Method: [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
> four questions with STRIDE.

| | |
|---|---|
| Author | |
| Date | |
| Reviewers | |
| Related PR / ADR | |

## 1. What are we building?

Short description, plus a data-flow sketch: actors, components, data stores,
and the **trust boundaries** between them.

```
[User browser] --HTTPS--> [API] --SQL--> [DB]
                   |
                   +--HTTPS--> [Third-party / LLM provider]
```

### Data handled

| Data | Classification (public / internal / confidential / personal / sensitive personal) | Stored where | Retention |
|---|---|---|---|
| | | | |

## 2. What can go wrong? (STRIDE)

| Threat | Applies? | Scenario | Mitigation | Status |
|---|---|---|---|---|
| **S**poofing identity | | | | |
| **T**ampering with data | | | | |
| **R**epudiation | | | | |
| **I**nformation disclosure | | | | |
| **D**enial of service | | | | |
| **E**levation of privilege | | | | |

For LLM/agent features, also walk the
[agentic & LLM risks](../standards/security/owasp-agentic-llm.md)
(prompt injection, excessive agency, output handling, unbounded consumption).

## 3. Privacy

- What personal data is collected, and why is each field necessary?
- Who can access it (roles), and how is that enforced?
- Is it sent to any third party (including LLM APIs)? Under what agreement?
- Retention and deletion: how does a user's deletion request reach this data?
- Is a privacy impact assessment required?

## 4. What are we doing about it?

List the mitigations with owners and links to the code or tickets. Note any
accepted risks and who accepted them.

## 5. Did we do a good job?

- [ ] Abuse cases have tests
- [ ] Reviewed by someone outside the implementing team
- [ ] Revisit trigger defined (e.g. new data type, new integration)
