# OPA / Rego Language Plugin

## Description

This plugin teaches AI agents how to write correct, idiomatic [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/). It covers the full range of OPA use cases and enforces best practices through steering rules (`rules.md`) and a curated reference skill (`skills/rego-domain-reference`).

### What AI agents learn from this plugin

**Policy domains covered:**
- **Kubernetes admission control** — OPA webhook policies and OPA Gatekeeper `ConstraintTemplate` policies
- **Infrastructure-as-Code validation** — Terraform plan validation (raw Terraform and HCP Terraform/Enterprise input structures), AWS CloudFormation hook policies
- **Container security** — Docker daemon authorization with `opa-docker-authz`
- **HTTP API authorization** — JWT-authenticated API gateway policies driven by OpenAPI specs
- **RBAC / access control** — Role-based and attribute-based access control patterns
- **Policy testing** — Test-driven development with `opa test`, mocking with `with`, parameterised tests
- **Metadata annotations** — `# METADATA` blocks, entrypoints, severity classification, `opa inspect`

**Key patterns enforced:**
- Write tests first (TDD) before implementing policies
- Use `import rego.v1` and OPA 1.0 syntax (`if`, `contains`, `some...in`, `every`)
- Normalize Terraform plan input with `tfplan := object.get(input, "plan", input)` for HCP Terraform compatibility
- Default-deny security posture
- Structured violation messages via `deny contains msg if { ... }`
- `object.get` for safe field access with defaults
- Check both `create` and `update` actions in IaC policies

## Running Evals

This plugin's evals live in [evals/](evals/) (31 scenarios covering the domains above). They're run with the [Tessl CLI](https://docs.tessl.io).

**1. Install and authenticate**

```
npm install -g tessl
tessl login
```

**2. Link this directory to a Tessl project** (eval runs need a project to save results to)

```
tessl project create tessl-tile-opa-rego-language --workspace <your-workspace>
```

If this directory is already linked but the link is stale, run `tessl project repair` instead.

**3. Run the evals**

```
tessl eval .
```

This reads scenarios from `evals/` and uses the plugin's rules and skills as injected context automatically.

Useful flags:
- `--agent` / `--model` — choose the agent under test (run `tessl eval --list-agents` for the current list)
- `--runs <count>` — repeat each scenario N times
- `--skip-baseline` — skip the always-on baseline (control) variant
- `--label <text>` — tag the run for easier lookup later

**4. View results**

```
tessl eval list
tessl eval view <run-id>
```