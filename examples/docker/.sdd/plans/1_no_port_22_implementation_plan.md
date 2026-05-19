# Implementation Plan: Docker Container Security Policy

## Overview
This plan outlines the implementation of an OPA Rego policy to enforce security hardening requirements for Docker containers provisioned via Terraform. The policy will validate Terraform plans before infrastructure deployment, ensuring containers meet security baselines for port exposure, privilege escalation, filesystem permissions, Linux capabilities, and image provenance.

## Policy Architecture

### Package Structure
```
package docker.security

import rego.v1
```

**Rationale:**
- Package name `docker.security` follows the domain-based naming convention
- `import rego.v1` ensures OPA 1.0 compatibility and enables modern syntax
- Policy will be evaluated using OPA CLI, requiring `entrypoint: true` annotation on the main deny rule for query discovery

### Input Structure Analysis
The policy will evaluate Terraform plan JSON with the following relevant structure:

```json
{
  "resource_changes": [
    {
      "type": "docker_container",
      "change": {
        "actions": ["create", "update"],
        "after": {
          "name": "vault",
          "image": "sha256:...",
          "ports": [{"internal": 8200, "external": 8200}],
          "privileged": false,
          "read_only": true,
          "capabilities": {
            "add": ["IPC_LOCK"],
            "drop": ["ALL"]
          }
        }
      }
    },
    {
      "type": "docker_image",
      "change": {
        "after": {
          "name": "hashicorp/vault:1.15"
        }
      }
    }
  ]
}
```

**Key observations:**
- Container resources are in `resource_changes` array
- Filter by `type == "docker_container"` and actions containing "create" or "update"
- Image name is in separate `docker_image` resource, linked via `image_id`
- Need to normalize input to handle both raw Terraform and HCP Terraform formats

### Input Normalization
```rego
# Normalize input to handle both raw Terraform and HCP Terraform formats
tfplan := object.get(input, "plan", input)

# Extract docker_container resources being created or updated
docker_containers contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_container"
    some action in resource.change.actions
    action in ["create", "update"]
}

# Extract docker_image resources for image name lookup
docker_images contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_image"
}
```

## Test-Driven Development Approach

Following the mandatory TDD requirement from the Rego best practices, we will:

1. **Create `docker_security_test.rego` FIRST** with all test cases
2. **Run `opa test` to confirm tests fail** (no policy exists yet)
3. **Implement `docker_security.rego` incrementally** by requirement
4. **Run `opa test` after each requirement** to verify tests pass
5. **Iterate until all tests pass**

### Test File Structure
```rego
package docker.security_test

import rego.v1
import data.docker.security

# Test data helpers
mock_container(overrides) := object.union(base_container, overrides)

base_container := {
    "type": "docker_container",
    "change": {
        "actions": ["create"],
        "after": {
            "name": "test-container",
            "image": "sha256:abc123",
            "read_only": true,
            "capabilities": {
                "drop": ["ALL"],
                "add": ["IPC_LOCK"]
            }
        }
    }
}

# Test cases for each requirement...
```

## Implementation Steps

### Step 1: Create Test File Structure
**File:** `examples/docker/policy/docker_security_test.rego`

Create the test package with:
- Package declaration: `package docker.security_test`
- Import statements: `import rego.v1`, `import data.docker.security`
- Mock data helpers for creating test containers
- Test cases for all 7 requirements (detailed below)

**Verification:** Run `opa test examples/docker/policy/` - should fail with "undefined ref: data.docker.security"

### Step 2: Create Policy File Skeleton
**File:** `examples/docker/policy/docker_security.rego`

Create basic structure:
```rego
package docker.security

import rego.v1

# Input normalization
tfplan := object.get(input, "plan", input)

# Helper: Extract docker_container resources
docker_containers contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_container"
    some action in resource.change.actions
    action in ["create", "update"]
}

# Helper: Extract docker_image resources
docker_images contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_image"
}
```

**Verification:** Run `opa test examples/docker/policy/` - tests should still fail but policy loads

### Step 3: Implement Requirement 1 - SSH Port Blocking

#### Test Cases (in `docker_security_test.rego`):
```rego
# METADATA
# title: SSH port exposure is blocked
# description: Containers must not expose port 22
# custom:
#   severity: HIGH

test_deny_ssh_port_22_exposed if {
    container := mock_container({"change": {"after": {"ports": [{"internal": 22, "external": 2222}]}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    count(result) > 0
    some msg in result
    contains(msg, "port 22")
}

test_allow_non_ssh_ports if {
    container := mock_container({"change": {"after": {"ports": [{"internal": 8200, "external": 8200}]}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "port 22") | some msg in result])
}

test_allow_no_ports if {
    container := mock_container({"change": {"after": {}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "port 22") | some msg in result])
}
```

#### Policy Implementation (in `docker_security.rego`):
```rego
# METADATA
# title: SSH port exposure is blocked
# description: Deny containers that expose port 22
# entrypoint: true
# custom:
#   severity: HIGH

deny contains msg if {
    some container in docker_containers
    some port in container.change.after.ports
    port.internal == 22
    msg := sprintf(
        "Container '%s' exposes SSH port 22 (mapped to host port %d). SSH access to containers is prohibited.",
        [container.change.after.name, port.external]
    )
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - SSH port tests should pass

### Step 4: Implement Requirement 2 - Privileged Mode Blocking

#### Test Cases:
```rego
# METADATA
# title: Privileged mode is blocked
# description: Containers must not run in privileged mode
# custom:
#   severity: HIGH

test_deny_privileged_container if {
    container := mock_container({"change": {"after": {"privileged": true}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "privileged")
}

test_allow_non_privileged_container if {
    container := mock_container({"change": {"after": {"privileged": false}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "privileged") | some msg in result])
}

test_allow_privileged_unset if {
    container := mock_container({"change": {"after": {}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "privileged") | some msg in result])
}
```

#### Policy Implementation:
```rego
# METADATA
# title: Privileged mode is blocked
# description: Deny containers running in privileged mode
# custom:
#   severity: HIGH

deny contains msg if {
    some container in docker_containers
    container.change.after.privileged == true
    msg := sprintf(
        "Container '%s' is configured to run in privileged mode. Privileged containers have unrestricted access to host resources.",
        [container.change.after.name]
    )
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Privileged mode tests should pass

### Step 5: Implement Requirement 3 - Read-Only Root Filesystem

#### Test Cases:
```rego
# METADATA
# title: Writable root filesystems are blocked
# description: Containers must have read-only root filesystems
# custom:
#   severity: HIGH

test_deny_writable_root_filesystem if {
    container := mock_container({"change": {"after": {"read_only": false}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "read-only")
}

test_deny_read_only_unset if {
    container := mock_container({"change": {"after": {}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "read-only")
}

test_allow_read_only_filesystem if {
    container := mock_container({"change": {"after": {"read_only": true}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "read-only") | some msg in result])
}
```

#### Policy Implementation:
```rego
# METADATA
# title: Writable root filesystems are blocked
# description: Deny containers without read-only root filesystems
# custom:
#   severity: HIGH

deny contains msg if {
    some container in docker_containers
    not container.change.after.read_only == true
    msg := sprintf(
        "Container '%s' does not have a read-only root filesystem. Set read_only = true to prevent runtime modifications.",
        [container.change.after.name]
    )
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Read-only filesystem tests should pass

### Step 6: Implement Requirement 4 - Drop All Capabilities

#### Test Cases:
```rego
# METADATA
# title: Containers must drop all Linux capabilities
# description: Containers must explicitly drop all capabilities
# custom:
#   severity: HIGH

test_deny_missing_capabilities_block if {
    container := mock_container({"change": {"after": {}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "capabilities")
    contains(msg, "drop")
}

test_deny_missing_drop_all if {
    container := mock_container({"change": {"after": {"capabilities": {"add": ["IPC_LOCK"]}}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "ALL")
}

test_deny_drop_all_not_present if {
    container := mock_container({"change": {"after": {"capabilities": {"drop": ["NET_RAW"]}}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "ALL")
}

test_allow_drop_all_capabilities if {
    container := mock_container({"change": {"after": {"capabilities": {"drop": ["ALL"]}}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "drop") | some msg in result; contains(msg, "capabilities")])
}
```

#### Policy Implementation:
```rego
# METADATA
# title: Containers must drop all Linux capabilities
# description: Deny containers that do not drop all capabilities
# custom:
#   severity: HIGH

deny contains msg if {
    some container in docker_containers
    not has_capabilities_block(container)
    msg := sprintf(
        "Container '%s' does not define a capabilities block. Containers must explicitly drop all capabilities.",
        [container.change.after.name]
    )
}

deny contains msg if {
    some container in docker_containers
    has_capabilities_block(container)
    not drops_all_capabilities(container)
    msg := sprintf(
        "Container '%s' does not drop all capabilities. Add cap_drop = [\"ALL\"] to the capabilities block.",
        [container.change.after.name]
    )
}

# Helper: Check if capabilities block exists
has_capabilities_block(container) if {
    container.change.after.capabilities
}

# Helper: Check if ALL capabilities are dropped
drops_all_capabilities(container) if {
    some cap in container.change.after.capabilities.drop
    cap == "ALL"
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Drop capabilities tests should pass

### Step 7: Implement Requirement 5 - Allowed Capability Additions

#### Test Cases:
```rego
# METADATA
# title: Containers may only add explicitly required capabilities
# description: Only specific capabilities may be added after dropping all
# custom:
#   severity: MEDIUM

test_allow_drop_all_with_specific_add if {
    container := mock_container({"change": {"after": {"capabilities": {"drop": ["ALL"], "add": ["IPC_LOCK"]}}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "cap_add") | some msg in result])
}

test_allow_drop_all_with_no_add if {
    container := mock_container({"change": {"after": {"capabilities": {"drop": ["ALL"]}}}})
    plan := {"resource_changes": [container]}
    
    result := security.deny with input as plan
    not any([contains(msg, "cap_add") | some msg in result])
}
```

#### Policy Implementation:
```rego
# Note: This requirement is informational - the policy allows adding capabilities
# after dropping all. No deny rule needed unless specific capabilities are prohibited.
# The test cases verify that adding capabilities doesn't trigger false positives.
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Capability addition tests should pass

### Step 8: Implement Requirement 6 - HashiCorp Namespace Enforcement

#### Test Cases:
```rego
# METADATA
# title: Images must use the hashicorp namespace
# description: Only images from hashicorp/ namespace are allowed
# custom:
#   severity: HIGH

test_deny_non_hashicorp_image if {
    image := {"type": "docker_image", "change": {"after": {"name": "nginx:1.21"}}}
    container := mock_container({})
    plan := {"resource_changes": [container, image]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "hashicorp")
}

test_allow_hashicorp_image if {
    image := {"type": "docker_image", "change": {"after": {"name": "hashicorp/vault:1.15"}}}
    container := mock_container({})
    plan := {"resource_changes": [container, image]}
    
    result := security.deny with input as plan
    not any([contains(msg, "namespace") | some msg in result])
}
```

#### Policy Implementation:
```rego
# METADATA
# title: Images must use the hashicorp namespace
# description: Deny images not from hashicorp/ namespace
# custom:
#   severity: HIGH

deny contains msg if {
    some image in docker_images
    not startswith(image.change.after.name, "hashicorp/")
    msg := sprintf(
        "Image '%s' is not from the hashicorp namespace. Only hashicorp/* images are permitted.",
        [image.change.after.name]
    )
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Namespace tests should pass

### Step 9: Implement Requirement 7 - Explicit Version Tags

#### Test Cases:
```rego
# METADATA
# title: Images must specify an explicit version tag
# description: Images must not use 'latest' or omit version tags
# custom:
#   severity: MEDIUM

test_deny_latest_tag if {
    image := {"type": "docker_image", "change": {"after": {"name": "hashicorp/vault:latest"}}}
    container := mock_container({})
    plan := {"resource_changes": [container, image]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "latest")
}

test_deny_no_tag if {
    image := {"type": "docker_image", "change": {"after": {"name": "hashicorp/vault"}}}
    container := mock_container({})
    plan := {"resource_changes": [container, image]}
    
    result := security.deny with input as plan
    some msg in result
    contains(msg, "version tag")
}

test_allow_explicit_version if {
    image := {"type": "docker_image", "change": {"after": {"name": "hashicorp/vault:1.15"}}}
    container := mock_container({})
    plan := {"resource_changes": [container, image]}
    
    result := security.deny with input as plan
    not any([contains(msg, "version") | some msg in result; contains(msg, "tag")])
}
```

#### Policy Implementation:
```rego
# METADATA
# title: Images must specify an explicit version tag
# description: Deny images using 'latest' or no tag
# custom:
#   severity: MEDIUM

deny contains msg if {
    some image in docker_images
    endswith(image.change.after.name, ":latest")
    msg := sprintf(
        "Image '%s' uses the 'latest' tag. Specify an explicit version tag for reproducible deployments.",
        [image.change.after.name]
    )
}

deny contains msg if {
    some image in docker_images
    not contains(image.change.after.name, ":")
    msg := sprintf(
        "Image '%s' does not specify a version tag. Specify an explicit version tag for reproducible deployments.",
        [image.change.after.name]
    )
}
```

**Verification:** Run `opa test examples/docker/policy/ -v` - Version tag tests should pass

### Step 10: Integration Testing with Real Terraform Plan

#### Generate Terraform Plan JSON:
```bash
cd examples/docker/terraform
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

#### Test Policy Against Real Plan:
```bash
cd examples/docker
opa eval --data policy/ --input terraform/tfplan.json "data.docker.security.deny"
```

**Expected Result:** Empty set or undefined (the Vault container configuration complies with all requirements)

Alternative using `opa exec`:
```bash
opa exec --decision docker/security/deny --bundle policy/ terraform/tfplan.json
```

#### Create Non-Compliant Test Cases:
Create additional test Terraform configurations that violate each requirement to verify deny rules trigger correctly.

## File Structure

```
examples/docker/
├── .sdd/
│   ├── specs/
│   │   └── 1_no_port_22.md
│   └── plans/
│       └── 1_no_port_22_implementation_plan.md (this file)
├── policy/
│   ├── docker_security.rego          # Main policy (to be created)
│   └── docker_security_test.rego     # Test suite (to be created)
└── terraform/
    ├── main.tf                        # Existing Terraform config
    ├── variables.tf
    ├── outputs.tf
    └── tfplan.json                    # Generated plan (to be created)
```

## Success Criteria Mapping

| Acceptance Criterion | Test Case(s) | Policy Rule |
|---------------------|--------------|-------------|
| Port 22 mapped to host port is denied | `test_deny_ssh_port_22_exposed` | `deny contains msg if { port.internal == 22 }` |
| Non-SSH ports allowed | `test_allow_non_ssh_ports` | (no deny triggered) |
| No port mappings allowed | `test_allow_no_ports` | (no deny triggered) |
| Privileged container denied | `test_deny_privileged_container` | `deny contains msg if { privileged == true }` |
| Non-privileged container allowed | `test_allow_non_privileged_container` | (no deny triggered) |
| Writable root filesystem denied | `test_deny_writable_root_filesystem` | `deny contains msg if { not read_only == true }` |
| Read-only root filesystem allowed | `test_allow_read_only_filesystem` | (no deny triggered) |
| Missing capabilities block denied | `test_deny_missing_capabilities_block` | `deny contains msg if { not has_capabilities_block }` |
| Missing drop ALL denied | `test_deny_missing_drop_all` | `deny contains msg if { not drops_all_capabilities }` |
| Drop ALL with specific add allowed | `test_allow_drop_all_with_specific_add` | (no deny triggered) |
| Drop ALL with no add allowed | `test_allow_drop_all_with_no_add` | (no deny triggered) |
| Non-hashicorp image denied | `test_deny_non_hashicorp_image` | `deny contains msg if { not startswith(..., "hashicorp/") }` |
| HashiCorp image allowed | `test_allow_hashicorp_image` | (no deny triggered) |
| No tag denied | `test_deny_no_tag` | `deny contains msg if { not contains(..., ":") }` |
| Latest tag denied | `test_deny_latest_tag` | `deny contains msg if { endswith(..., ":latest") }` |
| Explicit version allowed | `test_allow_explicit_version` | (no deny triggered) |

## Risk Mitigation

### Risk: Terraform Plan JSON Structure Variations
**Mitigation:** Use input normalization pattern `tfplan := object.get(input, "plan", input)` to handle both raw Terraform and HCP Terraform formats.

### Risk: Missing or Null Fields
**Mitigation:** Use explicit checks like `not container.change.after.read_only == true` which handles both `false` and `null`/undefined cases.

### Risk: Test Coverage Gaps
**Mitigation:** Follow TDD strictly - write tests first, ensure they fail, then implement. Use `opa test --coverage` to verify 100% coverage.

### Risk: Policy Performance with Large Plans
**Mitigation:** Use set comprehensions for filtering (`docker_containers contains resource if ...`) which are optimized by OPA. Avoid nested loops where possible.

## Validation Checklist

- [ ] All test files created with `_test.rego` suffix
- [ ] All tests use `import rego.v1` for OPA 1.0 compatibility
- [ ] Tests written BEFORE policy implementation
- [ ] Each acceptance criterion has corresponding test case(s)
- [ ] All tests pass with `opa test examples/docker/policy/ -v`
- [ ] Policy tested against real Terraform plan JSON
- [ ] No deny messages for compliant configuration
- [ ] Deny messages are clear and actionable
- [ ] All deny rules have METADATA annotations with severity
- [ ] Main deny rule has `entrypoint: true` annotation for OPA CLI discovery
- [ ] Code formatted with `opa fmt --write`
- [ ] No unused imports or variables (`opa check --strict`)

## Timeline Estimate

- **Step 1-2:** Test file structure and policy skeleton - 30 minutes
- **Step 3:** SSH port blocking - 20 minutes
- **Step 4:** Privileged mode blocking - 15 minutes
- **Step 5:** Read-only filesystem - 15 minutes
- **Step 6:** Drop all capabilities - 25 minutes
- **Step 7:** Capability additions - 10 minutes
- **Step 8:** HashiCorp namespace - 20 minutes
- **Step 9:** Version tags - 20 minutes
- **Step 10:** Integration testing - 30 minutes

**Total Estimated Time:** 3 hours

## Next Steps

1. Review this plan with stakeholders
2. Begin implementation following TDD workflow
3. Create test file first (`docker_security_test.rego`)
4. Implement policy incrementally, verifying tests after each requirement
5. Perform integration testing with real Terraform plan
6. Document any deviations or additional findings
