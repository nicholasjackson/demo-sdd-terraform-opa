# METADATA
# title: Docker Container Security Policy
# description: >
#   Enforces security hardening rules for Docker containers deployed via Terraform.
#   Checks SSH port exposure, privileged mode, read-only filesystem, capability
#   management, and approved image namespaces.
# custom:
#   severity: HIGH
package docker.security

import rego.v1

# Normalize input to handle both raw Terraform plan and HCP Terraform/Enterprise
tfplan := object.get(input, "plan", input)

# =============================================================================
# Helpers
# =============================================================================

_drops_all_capabilities(r) if {
	some cap in r.change.after.capabilities
	"ALL" in cap.drop
}

_has_explicit_version_tag(name) if {
	contains(name, ":")
	tag := split(name, ":")[1]
	tag != "latest"
}

# =============================================================================
# Phase 1: Deny SSH Port Exposure
# =============================================================================

# METADATA
# title: No SSH port exposure
# description: Containers must not expose SSH port 22
# custom:
#   severity: HIGH
deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "docker_container"
	some action in r.change.actions
	action in {"create", "update"}
	some port in r.change.after.ports
	port.internal == 22
	msg := sprintf("Container %v exposes SSH port 22", [r.address])
}

# =============================================================================
# Phase 2: Deny Privileged Mode
# =============================================================================

# METADATA
# title: No privileged containers
# description: Containers must not run in privileged mode
# custom:
#   severity: HIGH
deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "docker_container"
	some action in r.change.actions
	action in {"create", "update"}
	r.change.after.privileged == true
	msg := sprintf("Container %v runs in privileged mode", [r.address])
}

# =============================================================================
# Phase 3: Enforce Read-Only Filesystem
# =============================================================================

# METADATA
# title: Read-only root filesystem
# description: Containers must use a read-only root filesystem
# custom:
#   severity: MEDIUM
deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "docker_container"
	some action in r.change.actions
	action in {"create", "update"}
	r.change.after.read_only == false
	msg := sprintf("Container %v does not have a read-only root filesystem", [r.address])
}

# =============================================================================
# Phase 4: Enforce Minimal Capabilities
# =============================================================================

# METADATA
# title: Drop all capabilities
# description: Containers must drop all capabilities and only add back specific ones
# custom:
#   severity: HIGH
deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "docker_container"
	some action in r.change.actions
	action in {"create", "update"}
	not _drops_all_capabilities(r)
	msg := sprintf("Container %v does not drop all capabilities (must use --cap-drop=ALL)", [r.address])
}

# =============================================================================
# Phase 5: Enforce Approved Image Namespace
# =============================================================================

# METADATA
# title: Approved image namespace
# description: Images must be from the hashicorp namespace
# custom:
#   severity: HIGH
deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "docker_image"
	some action in r.change.actions
	action in {"create", "update"}
	name := r.change.after.name
	not startswith(name, "hashicorp/")
	msg := sprintf("Image %v is not from the hashicorp namespace", [r.address])
}

# METADATA
# title: Explicit image version tag
# description: Images must have an explicit version tag (not 'latest' or untagged)
# custom:
#   severity: MEDIUM
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
