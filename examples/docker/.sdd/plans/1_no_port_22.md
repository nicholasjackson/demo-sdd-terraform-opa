# Plan: Security Hardening for Docker Containers

**Spec:** `specs/1_no_port_22.md`
**Target Terraform:** `examples/docker/terraform/`
**Policy location:** `examples/docker/policy/`

---

## Context

The Terraform code uses the `kreuzwerker/docker` provider to deploy a HashiCorp Vault container. The Terraform plan JSON shows `docker_container` resources with fields including `ports`, `privileged`, `read_only`, `capabilities`, and `image` (via `docker_image`). The policy must evaluate `resource_changes` from a Terraform plan JSON to enforce five security rules.

### Key Terraform Plan Structure (docker_container)

From the plan JSON, the relevant fields in `resource_changes[].change.after` for a `docker_container` are:

- `ports[].internal` / `ports[].external` — port mappings
- `privileged` — boolean or null (null means not set, treated as false)
- `read_only` — boolean (false by default)
- `capabilities[].add` / `capabilities[].drop` — Linux capability lists
- `image` — image ID reference (not the image name)

For `docker_image` resources:
- `name` — the full image string (e.g. `hashicorp/vault:1.15`)

---

## Phase 1: Project Setup and Deny SSH Port Exposure

### Goal
Create the policy package, write tests for SSH port denial, then implement the rule.

### Files to Create

1. **`examples/docker/policy/docker_security_test.rego`** — Test file (written first per TDD)
2. **`examples/docker/policy/docker_security.rego`** — Policy file

### Test Cases (Phase 1)

| Test Name | Scenario | Expected |
|---|---|---|
| `test_deny_port_22_mapped_to_standard_port` | Container with `internal: 22, external: 22` | deny message |
| `test_deny_port_22_mapped_to_nonstandard_port` | Container with `internal: 22, external: 2222` | deny message |
| `test_allow_non_ssh_ports` | Container with `internal: 8200, external: 8200` | no deny |
| `test_allow_no_port_mappings` | Container with empty `ports` array | no deny |

### Policy Rule Design

```
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_container"
    some action in r.change.actions
    action in {"create", "update"}
    some port in r.change.after.ports
    port.internal == 22
    msg := sprintf("Container %v exposes SSH port 22", [r.address])
}
```

The rule checks `internal` port (the container port), not `external`. A container listening on port 22 internally is the security concern regardless of which host port it maps to.

### Verification
```bash
cd examples/docker/policy
opa test . -v
```

### Acceptance Criteria Covered
- Port 22 mapped to standard host port is rejected
- Port 22 mapped to a non-standard host port is rejected
- Container exposing only non-SSH ports is allowed
- Container with no port mappings is allowed

---

## Phase 2: Deny Privileged Mode

### Test Cases

| Test Name | Scenario | Expected |
|---|---|---|
| `test_deny_privileged_container` | `privileged: true` | deny message |
| `test_allow_non_privileged_container` | `privileged: false` | no deny |
| `test_allow_privileged_null` | `privileged: null` (unset) | no deny |

### Policy Rule Design

```
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_container"
    some action in r.change.actions
    action in {"create", "update"}
    r.change.after.privileged == true
    msg := sprintf("Container %v runs in privileged mode", [r.address])
}
```

Note: In the plan JSON, `privileged` is `null` when not explicitly set. The `== true` comparison naturally handles this — `null == true` is false in Rego.

### Acceptance Criteria Covered
- Privileged container is rejected
- Non-privileged container is allowed

---

## Phase 3: Enforce Read-Only Filesystem

### Test Cases

| Test Name | Scenario | Expected |
|---|---|---|
| `test_deny_writable_filesystem` | `read_only: false` | deny message |
| `test_allow_readonly_filesystem` | `read_only: true` | no deny |

### Policy Rule Design

```
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_container"
    some action in r.change.actions
    action in {"create", "update"}
    r.change.after.read_only == false
    msg := sprintf("Container %v does not have a read-only root filesystem", [r.address])
}
```

### Acceptance Criteria Covered
- Writable root filesystem is rejected
- Read-only root filesystem is allowed

---

## Phase 4: Enforce Minimal Capabilities

### Test Cases

| Test Name | Scenario | Expected |
|---|---|---|
| `test_deny_no_cap_drop_all` | `capabilities: [{"add": ["IPC_LOCK"], "drop": []}]` | deny message |
| `test_deny_missing_capabilities_block` | No capabilities block at all | deny message |
| `test_allow_cap_drop_all_add_specific` | `capabilities: [{"add": ["IPC_LOCK"], "drop": ["ALL"]}]` | no deny |
| `test_allow_cap_drop_all_add_none` | `capabilities: [{"add": [], "drop": ["ALL"]}]` | no deny |

### Policy Rule Design

```
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_container"
    some action in r.change.actions
    action in {"create", "update"}
    not _drops_all_capabilities(r)
    msg := sprintf("Container %v does not drop all capabilities (must use --cap-drop=ALL)", [r.address])
}

_drops_all_capabilities(r) if {
    some cap in r.change.after.capabilities
    "ALL" in cap.drop
}
```

The helper `_drops_all_capabilities` checks that at least one capabilities block has `"ALL"` in the `drop` list. The leading underscore signals this is an internal helper.

### Acceptance Criteria Covered
- Container that has not dropped all capabilities is rejected
- Container that drops all capabilities and adds a specific one is allowed
- Container that drops all capabilities and adds none is allowed

---

## Phase 5: Enforce Approved Image Namespace

### Context

Image names live on `docker_image` resources (`name` field), not on `docker_container`. The policy must correlate `docker_image` resource changes to check image names.

### Test Cases

| Test Name | Scenario | Expected |
|---|---|---|
| `test_deny_unapproved_image` | `docker_image` with `name: "nginx:latest"` | deny message |
| `test_allow_hashicorp_image` | `docker_image` with `name: "hashicorp/vault:1.15"` | no deny |
| `test_deny_hashicorp_image_no_tag` | `docker_image` with `name: "hashicorp/vault"` | deny message |
| `test_deny_hashicorp_image_latest_tag` | `docker_image` with `name: "hashicorp/vault:latest"` | deny message |
| `test_allow_hashicorp_image_explicit_tag` | `docker_image` with `name: "hashicorp/vault:1.15"` | no deny |

### Policy Rule Design

```
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_image"
    some action in r.change.actions
    action in {"create", "update"}
    name := r.change.after.name
    not startswith(name, "hashicorp/")
    msg := sprintf("Image %v is not from the hashicorp namespace", [r.address])
}

deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "docker_image"
    some action in r.change.actions
    action in {"create", "update"}
    name := r.change.after.name
    startswith(name, "hashicorp/")
    not _has_explicit_version_tag(name)
    msg := sprintf("Image %v must have an explicit version tag (not 'latest' or untagged)", [r.address])
}

_has_explicit_version_tag(name) if {
    contains(name, ":")
    tag := split(name, ":")[1]
    tag != "latest"
}
```

Two separate deny rules: one for namespace validation, one for tag validation. This keeps error messages specific to the violation.

### Acceptance Criteria Covered
- Container using an image from an unknown publisher is rejected
- Container using a hashicorp-namespaced image is allowed
- Container using a hashicorp image with no explicit tag is rejected
- Container using a hashicorp image with `latest` is rejected (combined with above)
- Container using a hashicorp image with an explicit tag is allowed

---

## Phase 6: Integration Validation

### Goal
Run the full policy against the actual `tfplan.json` to verify it works end-to-end.

### Current Terraform State vs. Policy

Evaluating the existing `tfplan.json` against the policy:

| Rule | Current State | Result |
|---|---|---|
| No SSH port | `internal: 8200` — no port 22 | PASS |
| No privileged | `privileged: null` | PASS |
| Read-only FS | `read_only: false` | **FAIL** — will produce deny |
| Cap drop ALL | `drop: []` — no ALL | **FAIL** — will produce deny |
| Approved image | `hashicorp/vault:1.15` | PASS |

The existing Terraform code will trigger two violations, which is correct — the Terraform code does not currently comply with the full security policy. This validates the policy is working.

### Verification Commands
```bash
# Run all tests
opa test examples/docker/policy/ -v

# Evaluate against the real plan
opa exec --decision docker/security/deny --bundle examples/docker/policy/ examples/docker/terraform/tfplan.json
```

---

## File Summary

| File | Purpose |
|---|---|
| `examples/docker/policy/docker_security_test.rego` | All test cases (written first) |
| `examples/docker/policy/docker_security.rego` | All policy rules |

### Package Structure

- Package: `docker.security`
- Test package: `docker.security_test`
- Input normalization: `tfplan := object.get(input, "plan", input)`

### Policy Module Layout

1. METADATA annotations (title, description, severity)
2. `package docker.security`
3. `import rego.v1`
4. Input normalization (`tfplan`)
5. Helper rules (`_drops_all_capabilities`, `_has_explicit_version_tag`)
6. Deny rules (SSH port, privileged, read-only, capabilities, image namespace, image tag)

---

## Implementation Order

Each phase follows strict TDD: write `_test.rego` cases first, confirm they fail, implement the rule, confirm they pass.

1. Phase 1 — SSH port denial (4 tests)
2. Phase 2 — Privileged mode denial (3 tests)
3. Phase 3 — Read-only filesystem (2 tests)
4. Phase 4 — Minimal capabilities (4 tests)
5. Phase 5 — Approved image namespace and tags (5 tests)
6. Phase 6 — Integration validation against `tfplan.json`

**Total: 18 test cases across 5 deny rules and 2 helper rules.**
