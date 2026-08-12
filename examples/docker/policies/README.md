# Docker Container Security Hardening Policy

## Overview
OPA policy that enforces security hardening requirements for Docker containers provisioned via Terraform. This policy validates Terraform plans before infrastructure deployment to ensure containers meet security baselines.

## Requirements Enforced

1. **SSH Port Exposure**: Port 22 (SSH) must not be exposed
2. **Privileged Mode**: Containers must not run in privileged mode
3. **Read-Only Root Filesystem**: Containers must have read-only root filesystems enabled
4. **Capability Management**: All Linux capabilities must be dropped (`cap_drop = ["ALL"]`)
5. **Image Namespace**: Images must use the `hashicorp/` namespace
6. **Image Version Tags**: Images must specify explicit version tags (not `:latest` or no tag)

## Policy Structure

- **Package**: `terraform.docker.container_hardening`
- **Entrypoint**: `deny` (set of violation messages)
- **Pattern**: Deny-by-default with explicit violation collection
- **File**: `container_hardening.rego`
- **Tests**: `container_hardening_test.rego`

## Usage

### Evaluate Against Terraform Plan

```bash
# Generate Terraform plan
cd examples/docker/terraform
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate policy
cd ../policies
opa eval -i ../terraform/tfplan.json -d container_hardening.rego \
  "data.terraform.docker.container_hardening.deny"
```

**Expected output for compliant configuration:**
```json
{
  "result": [
    {
      "expressions": [
        {
          "value": [],
          "text": "data.terraform.docker.container_hardening.deny",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

An empty array `[]` means no violations were found.

### Run Tests

```bash
cd examples/docker/policies
opa test . -v
```

**Expected output:**
```
PASS: 20/20
```

### Integration with CI/CD

```bash
#!/bin/bash
# In your CI pipeline

cd terraform
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate policy - exit with error if violations found
cd ../policies
opa eval -i ../terraform/tfplan.json -d container_hardening.rego \
  --fail-defined "data.terraform.docker.container_hardening.deny" \
  "data.terraform.docker.container_hardening.deny"

# Exit code 0 = no violations, non-zero = violations found
if [ $? -ne 0 ]; then
  echo "Policy violations detected!"
  exit 1
fi
```

### Using with Conftest

```bash
# Install conftest
# https://www.conftest.dev/install/

# Evaluate policy
conftest test tfplan.json -p container_hardening.rego
```

## Test Coverage

All acceptance criteria from the specification are covered by comprehensive unit tests:

| Requirement | Test Cases | Policy Rules |
|-------------|------------|--------------|
| SSH port exposure blocked | 3 tests | 1 deny rule |
| Privileged mode blocked | 3 tests | 1 deny rule |
| Read-only filesystem required | 3 tests | 1 deny rule |
| Drop all capabilities | 4 tests | 1 deny rule |
| HashiCorp namespace required | 2 tests | 1 deny rule |
| Explicit version tags required | 3 tests | 2 deny rules |
| Support create and update actions | 1 test | All rules |
| Fully compliant passes | 1 test | All rules |

**Total**: 20 test cases, 8 policy rules, 100% requirement coverage

### Test Cases

#### SSH Port Exposure (3 tests)
- `test_deny_ssh_port_22_mapped` - Denies containers exposing port 22
- `test_allow_non_ssh_ports` - Allows containers with non-SSH ports
- `test_allow_no_ports` - Allows containers without port mappings

#### Privileged Mode (3 tests)
- `test_deny_privileged_container` - Denies privileged containers
- `test_allow_non_privileged_container` - Allows explicitly non-privileged containers
- `test_allow_privileged_unset` - Allows containers where privileged is not set

#### Read-Only Filesystem (3 tests)
- `test_deny_writable_root_filesystem` - Denies writable root filesystems
- `test_deny_missing_read_only` - Denies when read_only field is missing
- `test_allow_read_only_filesystem` - Allows read-only root filesystems

#### Capability Management (4 tests)
- `test_deny_missing_capabilities` - Denies when capabilities block is missing
- `test_deny_missing_drop_all` - Denies when ALL is not in drop list
- `test_allow_drop_all_add_specific` - Allows drop ALL with specific capabilities added
- `test_allow_drop_all_no_add` - Allows drop ALL without adding capabilities

#### Image Namespace (2 tests)
- `test_deny_non_hashicorp_image` - Denies non-hashicorp namespace images
- `test_allow_hashicorp_image` - Allows hashicorp namespace images

#### Image Version Tags (3 tests)
- `test_deny_image_no_tag` - Denies images without version tags
- `test_deny_image_latest_tag` - Denies images with :latest tag
- `test_allow_explicit_version` - Allows images with explicit version tags

#### Update Actions (1 test)
- `test_deny_update_action_violations` - Ensures policy applies to update actions

#### Fully Compliant (1 test)
- `test_allow_fully_compliant_container` - Validates that a fully compliant container passes all checks

## Example Violations

### SSH Port Exposure
```
Container 'my-container' exposes SSH port 22, which is not allowed
```

### Privileged Mode
```
Container 'my-container' is configured to run in privileged mode, which is not allowed
```

### Read-Only Filesystem
```
Container 'my-container' does not have a read-only root filesystem enabled
```

### Capabilities
```
Container 'my-container' must drop all capabilities (cap_drop = ["ALL"])
```

### Image Namespace
```
Container 'my-container' uses image 'nginx:1.21' which is not from the hashicorp/ namespace
```

### Version Tags
```
Container 'my-container' uses image 'hashicorp/vault' without an explicit version tag
Container 'my-container' uses image 'hashicorp/vault:latest' with the 'latest' tag, which is not allowed
```

## Technical Implementation Details

### Image Name Resolution

**Challenge**: Terraform plans contain SHA256 digests for container images, not the original image names.

**Solution**: The policy correlates `docker_container` resources with `docker_image` resources in the same plan. The `docker_image` resource contains the original image name with namespace and tag.

**Implementation**: The `image_name_for_container(container)` helper rule searches for corresponding `docker_image` resources.

### Input Normalization

The policy handles both direct Terraform plan JSON and plan-wrapped formats:

```rego
tfplan := object.get(input, "plan", input)
```

This allows the policy to work with:
- Direct plan JSON: `terraform show -json tfplan`
- Wrapped format: `{"plan": {...}}`

### Helper Rules

- `containers` - Collects all docker_container resources being created or updated
- `images` - Collects all docker_image resources
- `container_name(container)` - Extracts container name for error messages
- `image_name_for_container(container)` - Resolves image name from docker_image resources

## Dependencies

- **OPA CLI**: Latest version (tested with 0.60+)
- **Terraform CLI**: >= 1.0
- **Docker Provider**: kreuzwerker/docker ~> 3.0

## Development

### Running Tests During Development

```bash
# Run tests with verbose output
opa test . -v

# Run specific test
opa test . -v -r test_deny_ssh_port_22_mapped

# Run tests with coverage
opa test . --coverage
```

### Linting with Regal

```bash
# Install Regal
# https://github.com/StyraInc/regal

# Lint policy
regal lint container_hardening.rego

# Lint with custom config
regal lint --config .regal.yaml .
```

### Policy Development Workflow

1. Write tests first (TDD approach)
2. Run tests to verify they fail
3. Implement policy rules incrementally
4. Run tests after each rule to verify correctness
5. Test against real Terraform plans
6. Document changes

## Future Enhancements

Potential additions to the policy:

1. **Resource Limits**: Enforce CPU and memory limits
2. **User Restrictions**: Require non-root user
3. **Network Policies**: Restrict network access
4. **Volume Mounts**: Validate volume mount security
5. **Environment Variables**: Check for sensitive data in env vars
6. **Health Checks**: Require health check configuration
7. **Logging**: Enforce logging configuration
8. **Image Scanning**: Integrate with vulnerability scanning results

## Support

For issues or questions:
1. Review test cases for examples
2. Check error messages for specific violations
3. Consult the implementation plan in `.sdd/plans/`
4. Review the specification in `.sdd/specs/`

## License

This policy is part of the demo-sdd-terraform-opa project.
