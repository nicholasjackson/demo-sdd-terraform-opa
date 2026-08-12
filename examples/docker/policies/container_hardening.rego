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
	# Find the docker_image resource - in simple cases there's only one
	some image in images
	image_name := image.change.after.name
}

# Helper: Check whether a container drops all Linux capabilities.
# The docker_container provider represents the `capabilities` block as a list
# (zero or one items), not an object, so this must index into the list before
# reading `drop` rather than treating `capabilities` as a map.
container_drops_all_capabilities(container) if {
	some capabilities in object.get(container.change.after, "capabilities", [])
	"ALL" in object.get(capabilities, "drop", [])
}

# METADATA
# title: Deny SSH port exposure
# description: Blocks containers that expose port 22
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
	some container in containers
	some port in object.get(container.change.after, "ports", [])
	port.internal == 22

	msg := sprintf(
		"Container '%s' exposes SSH port 22, which is not allowed",
		[container_name(container)],
	)
}

# METADATA
# title: Deny privileged mode
# description: Blocks containers running in privileged mode
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
	some container in containers
	container.change.after.privileged == true

	msg := sprintf(
		"Container '%s' is configured to run in privileged mode, which is not allowed",
		[container_name(container)],
	)
}

# METADATA
# title: Require read-only root filesystem
# description: Ensures containers have read-only root filesystems
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
	some container in containers
	read_only := object.get(container.change.after, "read_only", false)
	read_only != true

	msg := sprintf(
		"Container '%s' does not have a read-only root filesystem enabled",
		[container_name(container)],
	)
}

# METADATA
# title: Require dropping all capabilities
# description: Ensures containers drop all Linux capabilities
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
	some container in containers
	not container_drops_all_capabilities(container)

	msg := sprintf(
		"Container '%s' must drop all capabilities (cap_drop = [\"ALL\"])",
		[container_name(container)],
	)
}

# METADATA
# title: Require HashiCorp namespace
# description: Ensures containers use images from the hashicorp/ namespace
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
	some container in containers
	image_name := image_name_for_container(container)
	not startswith(image_name, "hashicorp/")

	msg := sprintf(
		"Container '%s' uses image '%s' which is not from the hashicorp/ namespace",
		[container_name(container), image_name],
	)
}

# METADATA
# title: Require explicit version tags (no missing tag)
# description: Ensures containers use images with explicit version tags
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
	some container in containers
	image_name := image_name_for_container(container)

	# Check if image has no tag (no colon)
	not contains(image_name, ":")

	msg := sprintf(
		"Container '%s' uses image '%s' without an explicit version tag",
		[container_name(container), image_name],
	)
}

# METADATA
# title: Require explicit version tags (not latest)
# description: Ensures containers do not use the latest tag
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
	some container in containers
	image_name := image_name_for_container(container)

	# Check if image uses :latest tag
	endswith(image_name, ":latest")

	msg := sprintf(
		"Container '%s' uses image '%s' with the 'latest' tag, which is not allowed",
		[container_name(container), image_name],
	)
}
