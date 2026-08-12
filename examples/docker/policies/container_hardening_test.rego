# METADATA
# title: Docker Container Hardening Policy Tests
# description: Comprehensive test suite for container security hardening requirements
# authors:
# - Security Team
package terraform.docker.container_hardening_test

import rego.v1

import data.terraform.docker.container_hardening

# Test Group 1: SSH Port Exposure

# Test: Port 22 mapped to standard host port is denied
test_deny_ssh_port_22_mapped if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"ports": [{"internal": 22, "external": 2222}],
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "SSH port 22")
}

# Test: Container exposing only non-SSH ports is allowed
test_allow_non_ssh_ports if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"ports": [{"internal": 8200, "external": 8200}],
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	# Should not contain SSH-related denial
	every msg in result {
		not contains(msg, "SSH port 22")
	}
}

# Test: Container with no port mappings is allowed
test_allow_no_ports if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "SSH port 22")
	}
}

# Test Group 2: Privileged Mode

# Test: Privileged container is denied
test_deny_privileged_container if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"privileged": true,
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "privileged mode")
}

# Test: Non-privileged container is allowed
test_allow_non_privileged_container if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"privileged": false,
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "privileged mode")
	}
}

# Test: Container with privileged unset is allowed
test_allow_privileged_unset if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "privileged mode")
	}
}

# Test Group 3: Read-Only Root Filesystem

# Test: Writable root filesystem is denied
test_deny_writable_root_filesystem if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": false,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "read-only root filesystem")
}

# Test: Container without read_only field is denied
test_deny_missing_read_only if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "read-only root filesystem")
}

# Test: Read-only root filesystem is allowed
test_allow_read_only_filesystem if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "read-only root filesystem")
	}
}

# Test Group 4: Capability Management

# Test: Container without capabilities block is denied
test_deny_missing_capabilities if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "drop all capabilities")
}

# Test: Container with capabilities represented as an empty list (real
# docker_container plan shape when no capabilities block is configured) is
# denied
test_deny_empty_capabilities_list if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "drop all capabilities")
}

# Test: Container without cap_drop ALL is denied
test_deny_missing_drop_all if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{"drop": ["CHOWN", "DAC_OVERRIDE"]}],
			},
		},
	}]}

	count(result) > 0
	some msg in result
	contains(msg, "drop all capabilities")
}

# Test: Container with drop ALL and specific add is allowed
test_allow_drop_all_add_specific if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{
					"drop": ["ALL"],
					"add": ["IPC_LOCK"],
				}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "capabilities")
	}
}

# Test: Container with drop ALL and no add is allowed
test_allow_drop_all_no_add if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["create"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"read_only": true,
				"capabilities": [{"drop": ["ALL"]}],
			},
		},
	}]}

	every msg in result {
		not contains(msg, "capabilities")
	}
}

# Test Group 5: Image Namespace Validation

# Test: Container using non-hashicorp image is denied
test_deny_non_hashicorp_image if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "nginx:1.21"},
			},
		},
		{
			"type": "docker_container",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "test-container",
					"image": "sha256:abc123",
					"read_only": true,
					"capabilities": [{"drop": ["ALL"]}],
				},
			},
		},
	]}

	count(result) > 0
	some msg in result
	contains(msg, "hashicorp/")
}

# Test: Container using hashicorp image is allowed
test_allow_hashicorp_image if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "hashicorp/vault:1.15"},
			},
		},
		{
			"type": "docker_container",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "test-container",
					"image": "sha256:abc123",
					"read_only": true,
					"capabilities": [{"drop": ["ALL"]}],
				},
			},
		},
	]}

	every msg in result {
		not contains(msg, "hashicorp/")
	}
}

# Test Group 6: Image Version Tag Validation

# Test: Image with no tag is denied
test_deny_image_no_tag if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "hashicorp/vault"},
			},
		},
		{
			"type": "docker_container",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "test-container",
					"image": "sha256:abc123",
					"read_only": true,
					"capabilities": [{"drop": ["ALL"]}],
				},
			},
		},
	]}

	count(result) > 0
	some msg in result
	contains(msg, "explicit version tag")
}

# Test: Image tagged latest is denied
test_deny_image_latest_tag if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "hashicorp/vault:latest"},
			},
		},
		{
			"type": "docker_container",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "test-container",
					"image": "sha256:abc123",
					"read_only": true,
					"capabilities": [{"drop": ["ALL"]}],
				},
			},
		},
	]}

	count(result) > 0
	some msg in result
	contains(msg, "latest")
}

# Test: Image with explicit version is allowed
test_allow_explicit_version if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "hashicorp/vault:1.15"},
			},
		},
		{
			"type": "docker_container",
			"change": {
				"actions": ["create"],
				"after": {
					"name": "test-container",
					"image": "sha256:abc123",
					"read_only": true,
					"capabilities": [{"drop": ["ALL"]}],
				},
			},
		},
	]}

	every msg in result {
		not contains(msg, "version tag")
		not contains(msg, "latest")
	}
}

# Test Group 7: Update Actions

# Test: Policy applies to update actions
test_deny_update_action_violations if {
	result := container_hardening.deny with input as {"resource_changes": [{
		"type": "docker_container",
		"change": {
			"actions": ["update"],
			"after": {
				"name": "test-container",
				"image": "sha256:abc123",
				"privileged": true,
				"read_only": false,
			},
		},
	}]}

	count(result) > 0
}

# Test Group 8: Fully Compliant Container

# Test: Fully compliant container produces no denials
test_allow_fully_compliant_container if {
	result := container_hardening.deny with input as {"resource_changes": [
		{
			"type": "docker_image",
			"change": {
				"actions": ["create"],
				"after": {"name": "hashicorp/vault:1.15"},
			},
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
						"external": 8200,
					}],
					"read_only": true,
					"capabilities": [{
						"drop": ["ALL"],
						"add": ["IPC_LOCK"],
					}],
				},
			},
		},
	]}

	count(result) == 0
}
