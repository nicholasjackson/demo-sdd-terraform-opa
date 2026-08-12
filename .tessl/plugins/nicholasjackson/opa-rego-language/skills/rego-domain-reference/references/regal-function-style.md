# Regal: Function Style

## Rule: `external-reference`

Functions must operate only on their arguments. Never reference `input` or `data` directly inside a function body — pass all required data as explicit arguments. Regal [external-reference](https://www.openpolicyagent.org/projects/regal/rules/style/external-reference).

Functions with external references are hard to test (you cannot mock `input` independently of the function) and create hidden dependencies.

```rego
# Wrong — references input inside function body
is_privileged(name) if {
    some c in input.request.object.spec.containers  # external reference!
    c.name == name
    c.securityContext.privileged
}

# Correct — container is passed as explicit argument
is_privileged(container) if {
    container.securityContext.privileged == true
}
```

## Rule: `zero-arity-function`

Functions without arguments are just rules. Don't define `f() := value` — write it as a rule `f := value`. Regal [zero-arity-function](https://www.openpolicyagent.org/projects/regal/rules/bugs/zero-arity-function).

## Rule: `function-arg-return`

Return values via the function head, not via a last argument. Use `result := f(x)` at the call site — never `f(x, result)`. Regal [function-arg-return](https://www.openpolicyagent.org/projects/regal/rules/style/function-arg-return).

## Full Example

```rego
# METADATA
# title: Container Security Validation
# description: Denies pods with privileged containers or missing resource limits
# authors:
# - Security Team <security@example.com>
# custom:
#   category: kubernetes-admission
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny privileged containers
# description: No container may run as privileged
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    is_privileged(container)
    msg := sprintf("container '%v' runs as privileged", [container.name])
}

# METADATA
# title: Deny missing resource limits
# description: All containers must declare CPU and memory limits
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not has_resource_limits(container)
    msg := sprintf("container '%v' is missing resource limits", [container.name])
}

# Helper functions — take container as explicit argument, no external references

is_privileged(container) if {
    container.securityContext.privileged == true
}

has_resource_limits(container) if {
    container.resources.limits.cpu
    container.resources.limits.memory
}
```

## Testing

```rego
# admission_test.rego
package kubernetes.admission_test

import rego.v1
import data.kubernetes.admission

test_deny_privileged_container if {
    result := admission.deny with input as {"request": {
        "kind": {"kind": "Pod"},
        "object": {"metadata": {"name": "p"}, "spec": {"containers": [
            {"name": "app", "securityContext": {"privileged": true},
             "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}
        ]}}
    }}
    count(result) == 1
}

test_deny_missing_limits if {
    result := admission.deny with input as {"request": {
        "kind": {"kind": "Pod"},
        "object": {"metadata": {"name": "p"}, "spec": {"containers": [
            {"name": "app", "securityContext": {"privileged": false}, "resources": {}}
        ]}}
    }}
    count(result) == 1
}

test_allow_compliant_container if {
    result := admission.deny with input as {"request": {
        "kind": {"kind": "Pod"},
        "object": {"metadata": {"name": "p"}, "spec": {"containers": [
            {"name": "app", "securityContext": {"privileged": false},
             "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}
        ]}}
    }}
    count(result) == 0
}
```
