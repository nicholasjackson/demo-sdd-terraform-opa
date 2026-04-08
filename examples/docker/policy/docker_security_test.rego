# METADATA
# title: Docker Security Policy Tests
# description: Tests for Docker container security hardening rules
package docker.security_test

import rego.v1

import data.docker.security

# Helper to build a minimal resource change for docker_container
_container_resource(addr, after) := {
	"address": addr,
	"type": "docker_container",
	"change": {
		"actions": ["create"],
		"after": after,
	},
}

# Helper to build a minimal resource change for docker_image
_image_resource(addr, after) := {
	"address": addr,
	"type": "docker_image",
	"change": {
		"actions": ["create"],
		"after": after,
	},
}

# =============================================================================
# Phase 1: Deny SSH Port Exposure
# =============================================================================

test_deny_port_22_mapped_to_standard_port if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [{"internal": 22, "external": 22}],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "SSH port 22")
}

test_deny_port_22_mapped_to_nonstandard_port if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [{"internal": 22, "external": 2222}],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "SSH port 22")
}

test_allow_non_ssh_ports if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [{"internal": 8200, "external": 8200}],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

test_allow_no_port_mappings if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

# =============================================================================
# Phase 2: Deny Privileged Mode
# =============================================================================

test_deny_privileged_container if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": true,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "privileged mode")
}

test_allow_non_privileged_container if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

test_allow_privileged_null if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": null,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

# =============================================================================
# Phase 3: Enforce Read-Only Filesystem
# =============================================================================

test_deny_writable_filesystem if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": false,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "read-only root filesystem")
}

test_allow_readonly_filesystem if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

# =============================================================================
# Phase 4: Enforce Minimal Capabilities
# =============================================================================

test_deny_no_cap_drop_all if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": ["IPC_LOCK"], "drop": []}],
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "drop all capabilities")
}

test_deny_missing_capabilities_block if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
	})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "drop all capabilities")
}

test_allow_cap_drop_all_add_specific if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": ["IPC_LOCK"], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

test_allow_cap_drop_all_add_none if {
	inp := {"resource_changes": [_container_resource("docker_container.test", {
		"ports": [],
		"privileged": false,
		"read_only": true,
		"capabilities": [{"add": [], "drop": ["ALL"]}],
	})]}

	result := security.deny with input as inp
	count(result) == 0
}

# =============================================================================
# Phase 5: Enforce Approved Image Namespace and Tags
# =============================================================================

test_deny_unapproved_image if {
	inp := {"resource_changes": [_image_resource("docker_image.nginx", {"name": "nginx:latest"})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "not from the hashicorp namespace")
}

test_allow_hashicorp_image if {
	inp := {"resource_changes": [_image_resource("docker_image.vault", {"name": "hashicorp/vault:1.15"})]}

	result := security.deny with input as inp
	count(result) == 0
}

test_deny_hashicorp_image_no_tag if {
	inp := {"resource_changes": [_image_resource("docker_image.vault", {"name": "hashicorp/vault"})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "explicit version tag")
}

test_deny_hashicorp_image_latest_tag if {
	inp := {"resource_changes": [_image_resource("docker_image.vault", {"name": "hashicorp/vault:latest"})]}

	result := security.deny with input as inp
	count(result) == 1
	some msg in result
	contains(msg, "explicit version tag")
}

test_allow_hashicorp_image_explicit_tag if {
	inp := {"resource_changes": [_image_resource("docker_image.vault", {"name": "hashicorp/vault:1.15"})]}

	result := security.deny with input as inp
	count(result) == 0
}
