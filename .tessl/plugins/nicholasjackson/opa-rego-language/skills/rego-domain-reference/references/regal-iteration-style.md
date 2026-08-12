# Regal: Iteration Style

## Rule: `prefer-some-in-iteration`

Always use `some x in collection` for iteration — not the old bracket notation `x := collection[_]`. Regal [prefer-some-in-iteration](https://www.openpolicyagent.org/projects/regal/rules/style/prefer-some-in-iteration).

```rego
# Wrong — old bracket notation
container := input.request.object.spec.containers[_]

# Correct — some x in
some container in input.request.object.spec.containers
```

When you need both index and value:
```rego
some i, container in input.request.object.spec.containers
```

## Rule: `mixed-iteration`

Do not mix iteration styles within the same rule. Use `some x in` consistently throughout. Regal [mixed-iteration](https://www.openpolicyagent.org/projects/regal/rules/style/mixed-iteration).

## Rule: `in-wildcard-key`

When the key is unused, omit it — `some v in obj` not `some _, v in obj`. Regal [in-wildcard-key](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/in-wildcard-key).

## Full Example

```rego
# METADATA
# title: Container Image Registry Validation
# description: Denies pods with containers using images from unapproved registries
# authors:
# - Security Team <security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny unapproved image registries
# description: Every container image must come from registry.example.com
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not startswith(container.image, "registry.example.com/")
    msg := sprintf("container '%v' uses image from unapproved registry: %v", [container.name, container.image])
}
```

## Testing

```rego
# admission_test.rego
package kubernetes.admission_test

import rego.v1
import data.kubernetes.admission

test_deny_unapproved_registry if {
    result := admission.deny with input as {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "metadata": {"name": "my-pod"},
                "spec": {"containers": [
                    {"name": "sidecar", "image": "docker.io/nginx:latest"}
                ]}
            }
        }
    }
    count(result) == 1
}

test_allow_approved_registry if {
    result := admission.deny with input as {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "metadata": {"name": "my-pod"},
                "spec": {"containers": [
                    {"name": "app", "image": "registry.example.com/myapp:v1"}
                ]}
            }
        }
    }
    count(result) == 0
}

test_deny_any_unapproved_container if {
    result := admission.deny with input as {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "metadata": {"name": "my-pod"},
                "spec": {"containers": [
                    {"name": "app", "image": "registry.example.com/myapp:v1"},
                    {"name": "sidecar", "image": "docker.io/nginx:latest"}
                ]}
            }
        }
    }
    count(result) == 1
}
```
