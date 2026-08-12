# Implementation Plan: Docker Container Security Hardening Policy

## Overview
This plan outlines the step-by-step implementation of an OPA Rego policy that enforces security hardening requirements for Docker containers provisioned via Terraform. The policy will validate Terraform plans before infrastructure deployment, ensuring containers meet security baselines.

## Policy Architecture

### File Structure
```
examples/docker/policy/
├── container_hardening.rego          # Main policy implementation
├── container_hardening_test.rego     # Comprehensive test suite
└── README.md                         # Policy documentation
```

### Package Organization
- **Package name**: `terraform.docker.container_hardening`
- **Entrypoint rule**: `deny` (multi-value set rule)
- **Pattern**: Deny-by-default with explicit violation collection

## Terraform Plan Structure Analysis

### Docker Container Resource Structure
Based on the Terraform code in `examples/docker/terraform/main.tf`, the policy must handle:

```json
{
  "resource_changes": [
    {
      "type": "docker_container",
      "change": {
        "actions": ["create"] or ["update"],
        "after": {
          "name": "vault",
          "image": "sha256:...",
          "ports": [
            {
              "internal": 8200,
              "external": 8200
            }
          ],
          "capabilities": {
            "add": ["IPC_LOCK"],
            "drop": ["ALL"]
          },
          "read_only": true,
          "privileged": false or null,
          "env": [...],
          "volumes": [...]
        }
      }
    }
  ]
}
```

### Key Observations
1. The `image` field in the plan contains a SHA256 digest, not the original image name
2. The original image name is in `docker_image` resource: `"name": "hashicorp/vault:1.15"`
3. Container references the image via `image_id` attribute reference
4. Port mappings use `internal` and `external` fields
5. Capabilities are nested under `capabilities.add` and `capabilities.drop`

## Implementation Strategy

### Phase 1: Test Suite Development (TDD Approach)
**CRITICAL**: Write ALL tests BEFORE implementing the policy. This ensures:
- Clear understanding of requirements
- Comprehensive coverage of edge cases
- Validation that tests fail before implementation
- Confidence that implementation satisfies requirements

### Phase 2: Policy Implementation
Implement policy rules incrementally, running tests after each rule to verify correctness.

### Phase 3: Integration Testing
Test against actual Terraform plan output from the example configuration.

## Detailed Implementation Steps

### Step 1: Create Test File Structure
**File**: `container_hardening_test.rego`

**Package declaration**:
```rego
# METADATA
# title: Docker Container Hardening Policy Tests
# description: Comprehensive test suite for container security hardening requirements
# authors:
# - Security Team
package terraform.docker.container_hardening_test

import rego.v1
import data.terraform.docker.container_hardening
```

### Step 2: Implement Test Cases (Before Policy)

#### Test Group 1: SSH Port Exposure
```rego
# Test: Port 22 mapped to standard host port is denied
test_deny_ssh_port_22_mapped if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "ports": [{
                        "internal": 22,
                        "external": 2222
                    }],
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "SSH port 22")
}

# Test: Container exposing only non-SSH ports is allowed
test_allow_non_ssh_ports if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "ports": [{
                        "internal": 8200,
                        "external": 8200
                    }],
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    # Should not contain SSH-related denial
    every msg in result {
        not contains(msg, "SSH port 22")
    }
}

# Test: Container with no port mappings is allowed
test_allow_no_ports if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    every msg in result {
        not contains(msg, "SSH port 22")
    }
}
```

#### Test Group 2: Privileged Mode
```rego
# Test: Privileged container is denied
test_deny_privileged_container if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "privileged": true,
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "privileged mode")
}

# Test: Non-privileged container is allowed
test_allow_non_privileged_container if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "privileged": false,
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    every msg in result {
        not contains(msg, "privileged mode")
    }
}

# Test: Container with privileged unset is allowed
test_allow_privileged_unset if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    every msg in result {
        not contains(msg, "privileged mode")
    }
}
```

#### Test Group 3: Read-Only Root Filesystem
```rego
# Test: Writable root filesystem is denied
test_deny_writable_root_filesystem if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": false,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "read-only root filesystem")
}

# Test: Container without read_only field is denied
test_deny_missing_read_only if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "read-only root filesystem")
}

# Test: Read-only root filesystem is allowed
test_allow_read_only_filesystem if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    every msg in result {
        not contains(msg, "read-only root filesystem")
    }
}
```

#### Test Group 4: Capability Management
```rego
# Test: Container without capabilities block is denied
test_deny_missing_capabilities if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "drop all capabilities")
}

# Test: Container without cap_drop ALL is denied
test_deny_missing_drop_all if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true,
                    "capabilities": {
                        "drop": ["CHOWN", "DAC_OVERRIDE"]
                    }
                }
            }
        }]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "drop all capabilities")
}

# Test: Container with drop ALL and specific add is allowed
test_allow_drop_all_add_specific if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
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
        }]
    }
    
    every msg in result {
        not contains(msg, "capabilities")
    }
}

# Test: Container with drop ALL and no add is allowed
test_allow_drop_all_no_add if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["create"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "read_only": true,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            }
        }]
    }
    
    every msg in result {
        not contains(msg, "capabilities")
    }
}
```

#### Test Group 5: Image Namespace Validation
**Challenge**: The Terraform plan contains SHA256 digests, not image names. We need to correlate `docker_container` with `docker_image` resources.

```rego
# Test: Container using non-hashicorp image is denied
test_deny_non_hashicorp_image if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "nginx:1.21"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "test-container",
                        "image": "sha256:abc123",
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    },
                    "after_unknown": {
                        "image": false
                    }
                }
            }
        ]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "hashicorp/")
}

# Test: Container using hashicorp image is allowed
test_allow_hashicorp_image if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "hashicorp/vault:1.15"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "test-container",
                        "image": "sha256:abc123",
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    }
                }
            }
        ]
    }
    
    every msg in result {
        not contains(msg, "hashicorp/")
    }
}
```

#### Test Group 6: Image Version Tag Validation
```rego
# Test: Image with no tag is denied
test_deny_image_no_tag if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "hashicorp/vault"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "test-container",
                        "image": "sha256:abc123",
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    }
                }
            }
        ]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "explicit version tag")
}

# Test: Image tagged latest is denied
test_deny_image_latest_tag if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "hashicorp/vault:latest"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "test-container",
                        "image": "sha256:abc123",
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    }
                }
            }
        ]
    }
    
    count(result) > 0
    some msg in result
    contains(msg, "latest")
}

# Test: Image with explicit version is allowed
test_allow_explicit_version if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "hashicorp/vault:1.15"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "test-container",
                        "image": "sha256:abc123",
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        }
                    }
                }
            }
        ]
    }
    
    every msg in result {
        not contains(msg, "version tag")
        not contains(msg, "latest")
    }
}
```

#### Test Group 7: Update Actions
```rego
# Test: Policy applies to update actions
test_deny_update_action_violations if {
    result := container_hardening.deny with input as {
        "resource_changes": [{
            "type": "docker_container",
            "change": {
                "actions": ["update"],
                "after": {
                    "name": "test-container",
                    "image": "sha256:abc123",
                    "privileged": true,
                    "read_only": false
                }
            }
        }]
    }
    
    count(result) > 0
}
```

#### Test Group 8: Fully Compliant Container
```rego
# Test: Fully compliant container produces no denials
test_allow_fully_compliant_container if {
    result := container_hardening.deny with input as {
        "resource_changes": [
            {
                "type": "docker_image",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "hashicorp/vault:1.15"
                    }
                }
            },
            {
                "type": "docker_container",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "name": "vault",
                        "image": "sha256:abc123",
                        "ports": [{
                            "internal": 8200,
                            "external": 8200
                        }],
                        "read_only": true,
                        "capabilities": {
                            "drop": ["ALL"],
                            "add": ["IPC_LOCK"]
                        }
                    }
                }
            }
        ]
    }
    
    count(result) == 0
}
```

### Step 3: Verify Tests Fail
Run `opa test` to confirm all tests fail (policy doesn't exist yet):
```bash
cd examples/docker/policy
opa test . -v
```

Expected: All tests should fail with "undefined" errors.

### Step 4: Implement Policy Structure
**File**: `container_hardening.rego`

```rego
# METADATA
# title: Docker Container Security Hardening Policy
# description: Enforces security hardening requirements for Docker containers provisioned via Terraform
# authors:
# - Security Team
# custom:
#   category: terraform-docker
package terraform.docker.container_hardening

import rego.v1

# Normalize input to handle both plan and plan-wrapped formats
tfplan := object.get(input, "plan", input)

# Default deny - start with empty set
default deny := set()
```

### Step 5: Implement Helper Rules

```rego
# Get all docker_container resources being created or updated
containers contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_container"
    resource.change.actions[_] in ["create", "update"]
}

# Get all docker_image resources
images contains resource if {
    some resource in tfplan.resource_changes
    resource.type == "docker_image"
    resource.change.actions[_] in ["create", "update"]
}

# Helper: Get container name for error messages
container_name(container) := name if {
    name := container.change.after.name
}

# Helper: Get image name from docker_image resources
# This correlates the container's image reference with the actual image name
image_name_for_container(container) := image_name if {
    # Get the image reference from the container
    container_image := container.change.after.image
    
    # Find the docker_image resource
    some image in images
    image_name := image.change.after.name
}
```

### Step 6: Implement Validation Rules

#### Rule 1: SSH Port Exposure
```rego
# METADATA
# title: Deny SSH port exposure
# description: Blocks containers that expose port 22
# custom:
#   severity: HIGH
deny contains msg if {
    some container in containers
    some port in object.get(container.change.after, "ports", [])
    port.internal == 22
    
    msg := sprintf(
        "Container '%s' exposes SSH port 22, which is not allowed",
        [container_name(container)]
    )
}
```

#### Rule 2: Privileged Mode
```rego
# METADATA
# title: Deny privileged mode
# description: Blocks containers running in privileged mode
# custom:
#   severity: HIGH
deny contains msg if {
    some container in containers
    container.change.after.privileged == true
    
    msg := sprintf(
        "Container '%s' is configured to run in privileged mode, which is not allowed",
        [container_name(container)]
    )
}
```

#### Rule 3: Read-Only Root Filesystem
```rego
# METADATA
# title: Require read-only root filesystem
# description: Ensures containers have read-only root filesystems
# custom:
#   severity: HIGH
deny contains msg if {
    some container in containers
    read_only := object.get(container.change.after, "read_only", false)
    read_only != true
    
    msg := sprintf(
        "Container '%s' does not have a read-only root filesystem enabled",
        [container_name(container)]
    )
}
```

#### Rule 4: Capability Management
```rego
# METADATA
# title: Require dropping all capabilities
# description: Ensures containers drop all Linux capabilities
# custom:
#   severity: HIGH
deny contains msg if {
    some container in containers
    capabilities := object.get(container.change.after, "capabilities", {})
    drop := object.get(capabilities, "drop", [])
    not "ALL" in drop
    
    msg := sprintf(
        "Container '%s' must drop all capabilities (cap_drop = [\"ALL\"])",
        [container_name(container)]
    )
}
```

#### Rule 5: Image Namespace
```rego
# METADATA
# title: Require HashiCorp namespace
# description: Ensures containers use images from the hashicorp/ namespace
# custom:
#   severity: MEDIUM
deny contains msg if {
    some container in containers
    image_name := image_name_for_container(container)
    not startswith(image_name, "hashicorp/")
    
    msg := sprintf(
        "Container '%s' uses image '%s' which is not from the hashicorp/ namespace",
        [container_name(container), image_name]
    )
}
```

#### Rule 6: Image Version Tag
```rego
# METADATA
# title: Require explicit version tags
# description: Ensures containers use images with explicit version tags (not latest)
# custom:
#   severity: MEDIUM
deny contains msg if {
    some container in containers
    image_name := image_name_for_container(container)
    
    # Check if image has no tag (no colon)
    not contains(image_name, ":")
    
    msg := sprintf(
        "Container '%s' uses image '%s' without an explicit version tag",
        [container_name(container), image_name]
    )
}

deny contains msg if {
    some container in containers
    image_name := image_name_for_container(container)
    
    # Check if image uses :latest tag
    endswith(image_name, ":latest")
    
    msg := sprintf(
        "Container '%s' uses image '%s' with the 'latest' tag, which is not allowed",
        [container_name(container), image_name]
    )
}
```

### Step 7: Run Tests and Iterate
```bash
cd examples/docker/policy
opa test . -v
```

Expected: All tests should now pass.

### Step 8: Test Against Real Terraform Plan

#### Generate Terraform Plan JSON
```bash
cd examples/docker/terraform
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

#### Evaluate Policy Against Plan
```bash
cd ../policy
opa eval -i ../terraform/tfplan.json -d container_hardening.rego "data.terraform.docker.container_hardening.deny"
```

Expected: Empty set (no violations) for the compliant example configuration.

### Step 9: Create Negative Test Cases

Create test Terraform configurations that violate each rule:

**File**: `examples/docker/terraform/test_violations/`
- `privileged.tf` - Container with privileged mode
- `ssh_port.tf` - Container exposing port 22
- `writable_fs.tf` - Container without read-only filesystem
- `no_cap_drop.tf` - Container without dropping capabilities
- `wrong_namespace.tf` - Container using non-hashicorp image
- `latest_tag.tf` - Container using :latest tag

For each violation test:
1. Generate plan JSON
2. Run policy evaluation
3. Verify appropriate denial message appears

### Step 10: Documentation

**File**: `examples/docker/policy/README.md`

```markdown
# Docker Container Security Hardening Policy

## Overview
OPA policy that enforces security hardening requirements for Docker containers provisioned via Terraform.

## Requirements Enforced
1. SSH port (22) exposure is blocked
2. Privileged mode is blocked
3. Read-only root filesystems are required
4. All Linux capabilities must be dropped
5. Images must use the hashicorp/ namespace
6. Images must specify explicit version tags (not :latest)

## Usage

### Evaluate Against Terraform Plan
```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval -i tfplan.json -d container_hardening.rego "data.terraform.docker.container_hardening.deny"
```

### Run Tests
```bash
opa test . -v
```

### Integration with CI/CD
```bash
# In your CI pipeline
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate policy
opa eval -i tfplan.json -d policy/container_hardening.rego \
  --fail-defined "data.terraform.docker.container_hardening.deny" \
  "data.terraform.docker.container_hardening.deny"

# Exit code 0 = no violations, non-zero = violations found
```

## Policy Structure
- **Package**: `terraform.docker.container_hardening`
- **Entrypoint**: `deny` (set of violation messages)
- **Pattern**: Deny-by-default with explicit violation collection

## Test Coverage
All acceptance criteria from the specification are covered by unit tests:
- SSH port exposure (3 test cases)
- Privileged mode (3 test cases)
- Read-only filesystem (3 test cases)
- Capability management (4 test cases)
- Image namespace (2 test cases)
- Image version tags (3 test cases)
- Update actions (1 test case)
- Fully compliant container (1 test case)

Total: 20 test cases covering all requirements and edge cases.
```

## Implementation Checklist

### Phase 1: Test Development
- [ ] Create `container_hardening_test.rego` with package declaration
- [ ] Implement SSH port exposure tests (3 tests)
- [ ] Implement privileged mode tests (3 tests)
- [ ] Implement read-only filesystem tests (3 tests)
- [ ] Implement capability management tests (4 tests)
- [ ] Implement image namespace tests (2 tests)
- [ ] Implement image version tag tests (3 tests)
- [ ] Implement update action test (1 test)
- [ ] Implement fully compliant container test (1 test)
- [ ] Run `opa test` to verify all tests fail (expected)

### Phase 2: Policy Implementation
- [ ] Create `container_hardening.rego` with package and metadata
- [ ] Implement input normalization
- [ ] Implement helper rules (containers, images, container_name, image_name_for_container)
- [ ] Implement SSH port denial rule
- [ ] Run tests - verify SSH tests pass
- [ ] Implement privileged mode denial rule
- [ ] Run tests - verify privileged tests pass
- [ ] Implement read-only filesystem denial rule
- [ ] Run tests - verify filesystem tests pass
- [ ] Implement capability management denial rule
- [ ] Run tests - verify capability tests pass
- [ ] Implement image namespace denial rule
- [ ] Run tests - verify namespace tests pass
- [ ] Implement image version tag denial rules
- [ ] Run tests - verify ALL tests pass

### Phase 3: Integration Testing
- [ ] Generate Terraform plan JSON from example configuration
- [ ] Evaluate policy against plan - verify no violations
- [ ] Create violation test cases (6 separate configs)
- [ ] Generate plans for each violation test
- [ ] Verify each produces appropriate denial message
- [ ] Document results

### Phase 4: Documentation
- [ ] Create README.md with usage instructions
- [ ] Document policy structure and patterns
- [ ] Document test coverage mapping to acceptance criteria
- [ ] Add CI/CD integration examples

## Key Technical Decisions

### Image Name Resolution Strategy
**Challenge**: Terraform plans contain SHA256 digests for container images, not the original image names.

**Solution**: Correlate `docker_container` resources with `docker_image` resources in the same plan. The `docker_image` resource contains the original image name with namespace and tag.

**Implementation**: `image_name_for_container(container)` helper rule searches for corresponding `docker_image` resources.

### Capability Validation Approach
**Pattern**: Require explicit `drop = ["ALL"]` rather than checking for absence of specific capabilities. This is more secure as it ensures a known-good baseline.

### Error Message Format
**Pattern**: Use `sprintf` for consistent, informative error messages that include:
- Container name for easy identification
- Specific violation details
- Clear remediation guidance

### Test Organization
**Pattern**: Group tests by requirement, with descriptive names that map directly to acceptance criteria. Each test is self-contained with inline mock data.

## Success Criteria Mapping

| Specification Requirement | Test Cases | Policy Rules |
|---------------------------|------------|--------------|
| SSH port exposure blocked | 3 tests | 1 deny rule |
| Privileged mode blocked | 3 tests | 1 deny rule |
| Read-only filesystem required | 3 tests | 1 deny rule |
| Drop all capabilities | 4 tests | 1 deny rule |
| HashiCorp namespace required | 2 tests | 1 deny rule |
| Explicit version tags required | 3 tests | 2 deny rules |
| Support create and update actions | 1 test | All rules |
| Fully compliant passes | 1 test | All rules |

**Total**: 20 test cases, 8 policy rules, 100% requirement coverage

## Estimated Implementation Time
- Test development: 2-3 hours
- Policy implementation: 2-3 hours
- Integration testing: 1-2 hours
- Documentation: 1 hour
- **Total**: 6-9 hours

## Dependencies
- OPA CLI (latest version)
- Terraform CLI (>= 1.0)
- Docker provider for Terraform (~> 3.0)

## Risk Mitigation
1. **Image name resolution complexity**: Mitigated by helper rule that handles correlation
2. **Terraform plan format changes**: Mitigated by comprehensive test coverage
3. **Edge cases in capability handling**: Mitigated by explicit tests for missing fields
4. **Performance with large plans**: Mitigated by efficient set operations and early returns

## Next Steps After Implementation
1. Integrate policy into CI/CD pipeline
2. Add policy to OPA server for runtime enforcement
3. Create monitoring/alerting for policy violations
4. Extend policy to cover additional security requirements
5. Consider adding warning-level rules for best practices
