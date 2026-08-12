# Kubernetes Admission Control

This document provides comprehensive examples of Kubernetes admission control policies using Rego. These policies validate, mutate, and enforce standards on Kubernetes resources during creation, update, and deletion operations.

---

## 1. Image Registry Validation

Ensures all container images come from approved corporate registries. This is a fundamental security policy that prevents containers from untrusted sources from being deployed in your cluster.

```rego
# METADATA
# title: Image Registry Validation
# description: Ensures container images come from approved registries
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny untrusted images
# description: Blocks pods with images from unapproved registries
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    image := container.image
    not startswith(image, "hooli.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}
```

---

## 2. Multiple Trusted Registries

Validates container images against a list of approved registries. This extends the basic registry validation to support multiple trusted sources, which is common in enterprise environments.

```rego
# METADATA
# title: Multiple Trusted Registries
# description: Validates container images against a list of approved registries
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

trusted_registries := {
    "hooli.com/",
    "gcr.io/hooli/",
    "registry.k8s.io/",
}

# METADATA
# title: Deny untrusted registry images
# description: Blocks pods with images not from any approved registry
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    image := container.image
    not image_from_trusted_registry(image)
    msg := sprintf("container %v uses untrusted image %v", [container.name, image])
}

image_from_trusted_registry(image) if {
    some registry in trusted_registries
    startswith(image, registry)
}
```

---

## 3. Ingress Hostname Allowlist

Restricts ingress hostnames to namespace-specific allowlists using annotations. This prevents teams from creating ingresses for domains they don't own or manage.

```rego
# METADATA
# title: Ingress Hostname Allowlist
# description: Restricts ingress hostnames to namespace-specific allowlists
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

import data.kubernetes.namespaces

operations := {"CREATE", "UPDATE"}

# METADATA
# title: Deny invalid ingress hosts
# description: Blocks ingresses with hostnames not in the namespace allowlist
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Ingress"
    operations[input.request.operation]
    some rule in input.request.object.spec.rules
    host := rule.host
    not fqdn_matches_any(host, valid_ingress_hosts)
    msg := sprintf("invalid ingress host %q", [host])
}

valid_ingress_hosts := {host |
    allowlist := namespaces[input.request.namespace].metadata.annotations["ingress-allowlist"]
    hosts := split(allowlist, ",")
    some host in hosts
}

fqdn_matches_any(str, patterns) if {
    some pattern in patterns
    fqdn_matches(str, pattern)
}

fqdn_matches(str, pattern) if {
    pattern_parts := split(pattern, ".")
    pattern_parts[0] == "*"
    suffix := trim(pattern, "*.")
    endswith(str, suffix)
}

fqdn_matches(str, pattern) if {
    not contains(pattern, "*")
    str == pattern
}
```

---

## 4. Prevent Ingress Hostname Conflicts

Prevents hostname conflicts across namespaces by checking existing ingresses. This ensures that two ingresses in different namespaces don't inadvertently claim the same hostname, which could cause traffic routing issues.

```rego
# METADATA
# title: Prevent Ingress Hostname Conflicts
# description: Prevents hostname conflicts across namespaces by checking existing ingresses
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

import data.kubernetes.ingresses

# METADATA
# title: Deny conflicting ingress hosts
# description: Blocks ingresses that conflict with hosts in other namespaces
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    some other_ns, other_ingress
    input.request.kind.kind == "Ingress"
    input.request.operation == "CREATE"
    some request_rule in input.request.object.spec.rules
    host := request_rule.host
    ingress := ingresses[other_ns][other_ingress]
    other_ns != input.request.namespace
    some ingress_rule in ingress.spec.rules
    host == ingress_rule.host
    msg := sprintf("invalid ingress host %q (conflicts with %v/%v)", [host, other_ns, other_ingress])
}
```

---

## 5. Required Labels on Deployments

Requires specific labels on Kubernetes Deployments to ensure proper organization, tracking, and billing. Labels like 'app', 'team', and 'environment' are essential for resource management.

```rego
# METADATA
# title: Required Labels
# description: Requires specific labels on Kubernetes Deployments
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

required_labels := ["app", "team", "environment"]

# METADATA
# title: Deny deployments missing labels
# description: Blocks deployments without required organizational labels
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Deployment"
    labels := object.get(input.request.object.metadata, "labels", {})
    some required_label in required_labels
    not labels[required_label]
    msg := sprintf("Deployment missing required label: %v", [required_label])
}
```

---

## 6. Pod Security: Run As Non-Root

Enforces that all containers run as non-root users. This is a critical security practice that reduces the attack surface if a container is compromised.

```rego
# METADATA
# title: Run As Non-Root
# description: Enforces that all containers run as non-root users
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny root containers
# description: Blocks pods with containers not configured to run as non-root
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not is_run_as_non_root(container)
    msg := sprintf("container %v must run as non-root user", [container.name])
}

is_run_as_non_root(container) if {
    container.securityContext.runAsNonRoot == true
}

is_run_as_non_root(container) if {
    container.securityContext.runAsUser > 0
}
```

---

## 7. Pod Security: Read-Only Root Filesystem

Enforces read-only root filesystems on containers. This prevents containers from modifying their filesystem at runtime, making it harder for attackers to persist changes.

```rego
# METADATA
# title: Read-Only Root Filesystem
# description: Enforces read-only root filesystems on containers
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny writable root filesystem
# description: Blocks pods with containers that lack read-only root filesystems
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("container %v must use read-only root filesystem", [container.name])
}
```

---

## 8. Prevent Privileged Containers

Blocks the creation of privileged containers. Privileged containers have access to all host devices and can bypass many security controls, so they should only be used when absolutely necessary.

```rego
# METADATA
# title: Prevent Privileged Containers
# description: Blocks the creation of privileged containers
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny privileged containers
# description: Blocks pods that run containers in privileged mode
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("privileged container %v is not allowed", [container.name])
}
```

---

## 9. Linux Capabilities Restrictions

Restricts which Linux capabilities containers can add. This follows the principle of least privilege by limiting the system capabilities available to containers.

```rego
# METADATA
# title: Linux Capabilities Restrictions
# description: Restricts which Linux capabilities containers can add
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

allowed_capabilities := {
    "NET_BIND_SERVICE",
    "CHOWN",
    "SETGID",
    "SETUID",
}

# METADATA
# title: Deny disallowed capabilities
# description: Blocks pods adding Linux capabilities outside the approved set
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    some cap in container.securityContext.capabilities.add
    not allowed_capabilities[cap]
    msg := sprintf("container %v cannot add capability %v", [container.name, cap])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    some cap in container.securityContext.capabilities.drop
    cap == "ALL"
    count(container.securityContext.capabilities.add) > 0
    msg := sprintf("container %v drops ALL capabilities but then adds some back", [container.name])
}
```

---

## 10. Resource Limits Required

Ensures all containers have CPU and memory limits defined. This prevents resource exhaustion and enables proper capacity planning for the cluster.

```rego
# METADATA
# title: Resource Limits Required
# description: Ensures all containers have CPU and memory limits defined
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny missing resource limits
# description: Blocks pods with containers lacking CPU or memory limits
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.resources.limits.cpu
    msg := sprintf("container %v must specify cpu limits", [container.name])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.resources.limits.memory
    msg := sprintf("container %v must specify memory limits", [container.name])
}
```

---

## 11. Resource Quota Validation

Validates that resource requests don't exceed maximum allowed values. This prevents individual workloads from consuming excessive cluster resources.

```rego
# METADATA
# title: Resource Quota Validation
# description: Validates that resource requests do not exceed maximum allowed values
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

max_cpu := "4000m"
max_memory := "8Gi"

# METADATA
# title: Deny excessive resource requests
# description: Blocks pods requesting more resources than allowed maximums
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    cpu := container.resources.requests.cpu
    units.parse_bytes(cpu) > units.parse_bytes(max_cpu)
    msg := sprintf("container %v requests %v cpu, exceeds max of %v", [container.name, cpu, max_cpu])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    memory := container.resources.requests.memory
    units.parse_bytes(memory) > units.parse_bytes(max_memory)
    msg := sprintf("container %v requests %v memory, exceeds max of %v", [container.name, memory, max_memory])
}
```

---

## 12. Namespace Isolation with Labels

Enforces namespace isolation by requiring specific labels and annotations. This ensures workloads are properly categorized and isolated according to organizational policies.

```rego
# METADATA
# title: Namespace Isolation with Labels
# description: Enforces namespace isolation by requiring specific labels
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny namespaces without required labels
# description: Blocks namespace creation without proper environment labels
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Namespace"
    input.request.operation == "CREATE"
    labels := object.get(input.request.object.metadata, "labels", {})
    not labels["environment"]
    msg := "namespaces must have an 'environment' label"
}

deny contains msg if {
    input.request.kind.kind == "Namespace"
    input.request.operation == "CREATE"
    labels := object.get(input.request.object.metadata, "labels", {})
    env := labels["environment"]
    not env in {"dev", "staging", "prod"}
    msg := sprintf("invalid environment label value: %v (must be dev, staging, or prod)", [env])
}
```

---

## 13. Service Account Restrictions

Prevents pods from using the default service account and requires explicit service account assignment. This improves security by ensuring pods have properly scoped permissions.

```rego
# METADATA
# title: Service Account Restrictions
# description: Prevents pods from using the default service account
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny default service account
# description: Blocks pods using the default service account
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    sa := object.get(input.request.object.spec, "serviceAccountName", "default")
    sa == "default"
    msg := "pods must not use the default service account"
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    not input.request.object.spec.serviceAccountName
    msg := "pods must specify a serviceAccountName"
}
```

---

## 14. ConfigMap and Secret Validation

Validates that ConfigMaps and Secrets have required metadata and proper naming conventions. This ensures consistency and prevents accidental data leakage.

```rego
# METADATA
# title: ConfigMap and Secret Validation
# description: Validates ConfigMaps and Secrets have proper naming and metadata
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny invalid resource names
# description: Blocks ConfigMaps and Secrets with invalid naming conventions
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind in {"ConfigMap", "Secret"}
    input.request.operation in {"CREATE", "UPDATE"}
    name := input.request.object.metadata.name
    not is_valid_name(name)
    msg := sprintf("%v name %v must be lowercase alphanumeric with hyphens", [input.request.kind.kind, name])
}

is_valid_name(name) if {
    regex.match(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, name)
}

deny contains msg if {
    input.request.kind.kind == "Secret"
    input.request.operation in {"CREATE", "UPDATE"}
    annotations := object.get(input.request.object.metadata, "annotations", {})
    not annotations["owner"]
    msg := "secrets must have an 'owner' annotation"
}
```

---

## 15. NetworkPolicy Enforcement

Requires NetworkPolicies to be defined for namespaces and validates their configuration. This ensures that network segmentation is properly implemented.

```rego
# METADATA
# title: NetworkPolicy Enforcement
# description: Requires NetworkPolicies for namespaces and validates their configuration
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

import data.kubernetes.networkpolicies

# METADATA
# title: Deny pods without network policy
# description: Blocks pod creation in namespaces lacking a NetworkPolicy
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    input.request.operation == "CREATE"
    namespace := input.request.namespace
    not has_network_policy(namespace)
    msg := sprintf("namespace %v must have at least one NetworkPolicy defined", [namespace])
}

has_network_policy(namespace) if {
    count(networkpolicies[namespace]) > 0
}

deny contains msg if {
    input.request.kind.kind == "NetworkPolicy"
    input.request.operation in {"CREATE", "UPDATE"}
    spec := input.request.object.spec
    not spec.podSelector
    msg := "NetworkPolicy must define a podSelector"
}
```

---

## 16. Volume Mount Restrictions

Restricts which host paths can be mounted into containers. This prevents containers from accessing sensitive host directories.

```rego
# METADATA
# title: Volume Mount Restrictions
# description: Restricts which host paths can be mounted into containers
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

forbidden_paths := {
    "/",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/proc",
    "/sys",
    "/usr",
}

# METADATA
# title: Deny forbidden host paths
# description: Blocks pods mounting sensitive host directories
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some volume in input.request.object.spec.volumes
    path := volume.hostPath.path
    is_forbidden_path(path)
    msg := sprintf("hostPath volume with path %v is forbidden", [path])
}

is_forbidden_path(path) if {
    some forbidden in forbidden_paths
    startswith(path, forbidden)
}
```

---

## 17. Environment Variable Validation

Validates environment variables to prevent hardcoded secrets and enforce naming conventions. This promotes security best practices and consistency.

```rego
# METADATA
# title: Environment Variable Validation
# description: Validates environment variables to prevent hardcoded secrets
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

sensitive_patterns := [
    "password",
    "secret",
    "key",
    "token",
    "credential",
]

# METADATA
# title: Deny hardcoded sensitive env vars
# description: Blocks pods with hardcoded secrets in environment variables
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    some env in container.env
    some pattern in sensitive_patterns
    contains(lower(env.name), pattern)
    env.value
    msg := sprintf("container %v has hardcoded sensitive env var %v (use valueFrom instead)", [container.name, env.name])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    some env in container.env
    not is_valid_env_name(env.name)
    msg := sprintf("container %v has invalid env var name %v (must be uppercase with underscores)", [container.name, env.name])
}

is_valid_env_name(name) if {
    regex.match(`^[A-Z][A-Z0-9_]*$`, name)
}
```

---

## 18. PodSecurityPolicy Patterns

Comprehensive pod security validation combining multiple security standards. While PodSecurityPolicy is deprecated, these patterns remain useful for validating pod security configurations.

```rego
# METADATA
# title: PodSecurityPolicy Patterns
# description: Comprehensive pod security validation combining multiple security standards
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny insecure pods
# description: Blocks pods that do not comply with baseline security standards
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    not complies_with_baseline_security(input.request.object)
    msg := "pod does not comply with baseline security standards"
}

complies_with_baseline_security(pod) if {
    every container in pod.spec.containers {
        container_is_secure(container)
    }
    pod_spec_is_secure(pod.spec)
}

container_is_secure(container) if {
    # Must run as non-root
    container.securityContext.runAsNonRoot == true

    # Must use read-only root filesystem
    container.securityContext.readOnlyRootFilesystem == true

    # Must not be privileged
    not container.securityContext.privileged

    # Must not allow privilege escalation
    container.securityContext.allowPrivilegeEscalation == false
}

pod_spec_is_secure(spec) if {
    # Host network must not be used
    not spec.hostNetwork

    # Host PID must not be used
    not spec.hostPID

    # Host IPC must not be used
    not spec.hostIPC
}
```

---

## 19. Admission Webhook Integration

Validates webhook configurations and ensures proper security settings. This helps maintain a secure admission control infrastructure.

```rego
# METADATA
# title: Admission Webhook Integration
# description: Validates webhook configurations and ensures proper security settings
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny insecure webhooks
# description: Blocks webhook configurations missing CA bundles when using URLs
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "ValidatingWebhookConfiguration"
    some webhook in input.request.object.webhooks
    not webhook.clientConfig.caBundle
    webhook.clientConfig.url
    msg := sprintf("webhook %v must specify caBundle when using url", [webhook.name])
}

deny contains msg if {
    input.request.kind.kind == "ValidatingWebhookConfiguration"
    some webhook in input.request.object.webhooks
    webhook.failurePolicy != "Fail"
    is_critical_webhook(webhook.name)
    msg := sprintf("critical webhook %v must have failurePolicy set to Fail", [webhook.name])
}

is_critical_webhook(name) if {
    critical_prefixes := ["security-", "policy-", "compliance-"]
    some prefix in critical_prefixes
    startswith(name, prefix)
}
```

---

## 20. Comprehensive Multi-Resource Validation

A complete validation policy that checks multiple resource types and enforces organization-wide standards. This demonstrates how to build comprehensive admission control policies.

```rego
# METADATA
# title: Comprehensive Multi-Resource Validation
# description: Validates multiple resource types and enforces organization-wide standards
# authors:
# - Platform Security Team <platform-security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

import data.kubernetes.namespaces

operations := {"CREATE", "UPDATE"}

# Validate all resources have required labels
# METADATA
# title: Deny resources missing required labels
# description: Blocks workload resources without required organizational labels
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    operations[input.request.operation]
    resource_types := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
    resource_types[input.request.kind.kind]
    labels := object.get(input.request.object.metadata, "labels", {})
    required := ["app", "team", "environment", "version"]
    some label in required
    not labels[label]
    msg := sprintf("%v/%v missing required label: %v", [input.request.kind.kind, input.request.object.metadata.name, label])
}

# Validate annotations
deny contains msg if {
    operations[input.request.operation]
    input.request.kind.kind in {"Deployment", "StatefulSet"}
    annotations := object.get(input.request.object.metadata, "annotations", {})
    not annotations["description"]
    msg := sprintf("%v must have a 'description' annotation", [input.request.kind.kind])
}

# Validate resource belongs to correct namespace
deny contains msg if {
    operations[input.request.operation]
    namespace := input.request.namespace
    labels := object.get(input.request.object.metadata, "labels", {})
    env := labels["environment"]
    ns_env := namespaces[namespace].metadata.labels["environment"]
    env != ns_env
    msg := sprintf("resource environment label %v does not match namespace environment %v", [env, ns_env])
}

# Validate replicas
deny contains msg if {
    operations[input.request.operation]
    input.request.kind.kind == "Deployment"
    replicas := input.request.object.spec.replicas
    env := input.request.object.metadata.labels["environment"]
    min_replicas := min_replicas_for_env[env]
    replicas < min_replicas
    msg := sprintf("Deployment in %v environment must have at least %v replicas, got %v", [env, min_replicas, replicas])
}

min_replicas_for_env := {
    "dev": 1,
    "staging": 2,
    "prod": 3,
}

# Validate image tags
deny contains msg if {
    operations[input.request.operation]
    input.request.kind.kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet"}
    some container in get_containers
    image := container.image
    endswith(image, ":latest")
    msg := sprintf("container %v uses :latest tag which is not allowed", [container.name])
}

get_containers := containers if {
    input.request.kind.kind == "Pod"
    containers := input.request.object.spec.containers
}

get_containers := containers if {
    input.request.kind.kind in {"Deployment", "StatefulSet", "DaemonSet"}
    containers := input.request.object.spec.template.spec.containers
}
```

---

## OPA Gatekeeper

OPA Gatekeeper is the recommended way to use OPA with Kubernetes in production. Instead of deploying OPA directly as an admission webhook (kube-mgmt style), Gatekeeper introduces two Kubernetes CRDs:

- **ConstraintTemplate** — defines the Rego policy and the schema for its parameters
- **Constraint** — an instance of a ConstraintTemplate with specific parameter values

The Rego policy lives inside the ConstraintTemplate. Its structure differs from the kube-mgmt pattern in three key ways:

| | kube-mgmt | Gatekeeper |
|---|---|---|
| Package | `kubernetes.admission` | named after the template, e.g. `k8srequiredlabels` |
| Rule | `deny contains msg if` | `violation[{"msg": msg}]` |
| Input object | `input.request.object` | `input.review.object` |
| Parameters | n/a | `input.parameters` |

### Example: Required Labels (ConstraintTemplate Rego)

```rego
package k8srequiredlabels

import rego.v1

violation contains {"msg": msg} if {
    provided := {label | input.review.object.metadata.labels[label]}
    required := {label | label := input.parameters.labels[_]}
    missing := required - provided
    count(missing) > 0
    msg := sprintf("required labels are missing: %v", [missing])
}
```

The matching Constraint would specify which resources to check and what labels to require:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-team-label
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    labels: ["team"]
```

### Example: Block Privileged Containers (ConstraintTemplate Rego)

```rego
package k8snoprivileged

import rego.v1

violation contains {"msg": msg} if {
    some container in input.review.object.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("container %v must not run as privileged", [container.name])
}
```

### Testing Gatekeeper Policies

Gatekeeper policies are tested with `opa test` like any other Rego policy, but the mock input structure is different — you must mock both `input.review.object` (the Kubernetes resource) and `input.parameters` (the Constraint parameters). Use `with input as` to inject the full input document.

The test package must use the `_test` suffix matching the policy package name.

```rego
package k8srequiredlabels_test

import rego.v1

# Positive case: deployment has all required labels — no violation
test_required_labels_present if {
    result := data.k8srequiredlabels.violation with input as {
        "review": {
            "object": {
                "metadata": {
                    "name": "my-deployment",
                    "labels": {
                        "team": "platform",
                        "env": "prod"
                    }
                }
            }
        },
        "parameters": {
            "labels": ["team", "env"]
        }
    }
    count(result) == 0
}

# Negative case: deployment is missing the "env" label — violation expected
test_required_labels_missing if {
    result := data.k8srequiredlabels.violation with input as {
        "review": {
            "object": {
                "metadata": {
                    "name": "my-deployment",
                    "labels": {
                        "team": "platform"
                    }
                }
            }
        },
        "parameters": {
            "labels": ["team", "env"]
        }
    }
    count(result) == 1
    some v in result
    contains(v.msg, "env")
}
```

Key differences from kube-mgmt test patterns:
- Mock `input.review.object` (not `input.request.object`)
- Include `input.parameters` with the constraint configuration
- Assert on `violation` (not `deny`)

---

## Summary

This document provides 20 comprehensive examples covering:

1. **Image Registry Validation** - Single and multiple trusted registries
2. **Ingress Control** - Hostname allowlists and conflict prevention
3. **Resource Labeling** - Required labels and annotations
4. **Pod Security Standards** - Non-root users, read-only filesystems, privileged containers
5. **Container Security** - Capabilities restrictions and security contexts
6. **Resource Management** - CPU/memory limits and quotas
7. **Namespace Isolation** - Label enforcement and isolation policies
8. **Service Account Control** - Preventing default service account usage
9. **ConfigMap/Secret Validation** - Naming and metadata requirements
10. **Network Policies** - NetworkPolicy enforcement and validation
11. **Volume Restrictions** - HostPath and volume mount controls
12. **Environment Variables** - Validation and secret detection
13. **PodSecurityPolicy Patterns** - Comprehensive security baselines
14. **Webhook Configuration** - Admission webhook validation
15. **Multi-Resource Validation** - Organization-wide standards enforcement

All examples use modern Rego v1 syntax with `if`, `contains`, `some...in`, and `every` keywords. These policies are production-ready and can be adapted to your organization's specific requirements.
