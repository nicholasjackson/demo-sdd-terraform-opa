---
name: rego-domain-reference
description: Reference material for writing Rego/OPA policies in a specific domain — Kubernetes admission control, Terraform/CloudFormation infrastructure-as-code validation, HTTP API authorization (request body validation, rate limiting), RBAC/ABAC access control models, metadata annotations, or Regal linter compliance by rule category. Load this when rules.md's general Rego style rules aren't enough and you need worked examples or domain-specific patterns for one of these areas.
---

# Rego domain reference

`rules.md` covers language-wide style and correctness rules. This skill indexes
deeper, domain-specific reference material — worked examples and patterns for
particular OPA use cases. Read the file for the domain you're working in
before writing policy code in that area.

## Domains

- **Kubernetes admission control** — webhook policies and OPA Gatekeeper
  `ConstraintTemplate` policies. Image registry validation, resource
  requirements, label enforcement, security standards, hostname conflict
  prevention.
  → [references/kubernetes-admission-control.md](references/kubernetes-admission-control.md)

- **Infrastructure as code** — Terraform plan validation (raw Terraform and
  HCP Terraform/Enterprise input structures) and AWS CloudFormation hook
  policies. Encryption requirements, required tags, security group
  validation, multi-region compliance.
  → [references/infrastructure-as-code.md](references/infrastructure-as-code.md)

- **HTTP API authorization** — JWT-authenticated API gateway policies.
  Hierarchical authorization, method-based permissions, path-based
  authorization.
  → [references/http-api-authorization.md](references/http-api-authorization.md)
  - Request body validation (set subtraction for unknown fields, explicit
    iteration for required fields) →
    [references/http-api-body-validation.md](references/http-api-body-validation.md)
  - Rate limiting (`default rule := value` tier-based fallbacks) →
    [references/http-api-rate-limiting.md](references/http-api-rate-limiting.md)

- **Access control models** — RBAC, ABAC, separation of duty, time-based and
  location-based access.
  → [references/access-control-models.md](references/access-control-models.md)

- **Metadata annotations** — `# METADATA` blocks, entrypoints, severity
  classification, schema validation, `opa inspect`.
  → [references/metadata-annotations.md](references/metadata-annotations.md)

- **Regal linter compliance** — focused guides per Regal rule category, for
  when a specific lint rule needs more context than `rules.md` gives:
  - Naming conventions (`prefer-snake-case`, `avoid-get-and-list-prefix`,
    `rule-name-repeats-package`) →
    [references/regal-naming-conventions.md](references/regal-naming-conventions.md)
  - Iteration style (`prefer-some-in-iteration`, `mixed-iteration`) →
    [references/regal-iteration-style.md](references/regal-iteration-style.md)
  - Membership operators (`use-in-operator`) →
    [references/regal-membership-operators.md](references/regal-membership-operators.md)
  - Function style (`external-reference`, `zero-arity-function`) →
    [references/regal-function-style.md](references/regal-function-style.md)
  - Default rules (`trailing-default-rule`, `default-over-else`) →
    [references/regal-defaults.md](references/regal-defaults.md)
  - Boolean and rule structure (`prefer-set-or-object-rule`,
    `boolean-assignment`) →
    [references/regal-boolean-structure.md](references/regal-boolean-structure.md)
  - Comprehension patterns (`object.keys`, `comprehension-term-assignment`) →
    [references/regal-comprehensions.md](references/regal-comprehensions.md)
  - Bug avoidance (`not-equals-in-loop`, `sprintf-arguments-mismatch`) →
    [references/regal-bugs.md](references/regal-bugs.md)
  - Testing style (`file-missing-test-suffix`, `test-outside-test-package`) →
    [references/regal-testing-style.md](references/regal-testing-style.md)
  - Import conventions (`prefer-package-imports`, `redundant-alias`) →
    [references/regal-imports.md](references/regal-imports.md)
  - Annotations (`missing-metadata`, `detached-metadata`,
    `no-defined-entrypoint`) →
    [references/regal-annotations.md](references/regal-annotations.md)

## Additional resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [Styra Academy](https://academy.styra.com/)
- [Policy Library](https://github.com/open-policy-agent/library)
