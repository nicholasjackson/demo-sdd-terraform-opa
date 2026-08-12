# Regal: Boolean Assignments and Rule Structure

This document covers Regal rules related to boolean assignments and unconditional rule patterns.

**Relevant Regal rules:**
- [`boolean-assignment`](https://docs.styra.com/regal/rules/idiomatic/boolean-assignment) — use `rule := true` / `rule := false` (or just `rule if { ... }`) rather than assigning boolean literals inside rule bodies
- [`unconditional-assignment`](https://docs.styra.com/regal/rules/idiomatic/unconditional-assignment) — avoid rules that always assign the same value unconditionally; express constants as `rule := value`
- [`prefer-set-or-object-rule`](https://docs.styra.com/regal/rules/idiomatic/prefer-set-or-object-rule) — prefer incremental rules (`rule contains item`) over comprehensions at the top level

## Pattern: Boolean Rules

Use Rego's natural boolean rule syntax rather than assigning `true`/`false` literals.

```rego
# CORRECT: boolean rule (no assignment needed for true)
is_admin if input.role == "admin"

# CORRECT: default false, conditional true
default is_valid := false
is_valid if {
    input.name != ""
    count(input.name) >= 3
}
```

```rego
# WRONG: boolean assignment inside body (boolean-assignment violation)
is_admin := true if input.role == "admin"
```

## Pattern: Unconditional Assignments

Express compile-time constants as simple assignments, not conditional rules.

```rego
# CORRECT: simple constant
max_retries := 3
allowed_methods := {"GET", "POST", "PUT", "DELETE"}
```

```rego
# WRONG: unconditional body (unconditional-assignment violation)
max_retries := 3 if {
    true
}
```

## Pattern: Incremental Rules vs Comprehensions

Prefer incremental `set` or `object` rules over comprehensions assigned to a top-level rule.

```rego
# CORRECT: incremental rule
violations contains msg if {
    some container in input.spec.containers
    not container.resources.limits
    msg := sprintf("container %s has no resource limits", [container.name])
}
```

```rego
# WRONG: comprehension at top level (prefer-set-or-object-rule violation)
violations := {msg |
    some container in input.spec.containers
    not container.resources.limits
    msg := sprintf("container %s has no resource limits", [container.name])
}
```

## Complete Example: Kubernetes Security Policy

```rego
package kubernetes.security
import rego.v1

# Boolean rule — no boolean assignment needed
default allow := false

allow if count(violations) == 0

# Incremental violations set
violations contains msg if {
    some container in input.spec.template.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("container '%s' runs as privileged", [container.name])
}

violations contains msg if {
    some container in input.spec.template.spec.containers
    not container.resources.limits
    msg := sprintf("container '%s' has no resource limits", [container.name])
}
```

## Testing Structure Rules

```rego
package kubernetes.security_test
import rego.v1
import data.kubernetes.security

test_allow_secure_pod if {
    security.allow with input as {
        "spec": {"template": {"spec": {"containers": [
            {"name": "app", "securityContext": {"privileged": false},
             "resources": {"limits": {"cpu": "500m"}}}
        ]}}}
    }
}

test_deny_privileged if {
    "container 'root' runs as privileged" in security.violations with input as {
        "spec": {"template": {"spec": {"containers": [
            {"name": "root", "securityContext": {"privileged": true},
             "resources": {"limits": {"cpu": "500m"}}}
        ]}}}
    }
}
```
