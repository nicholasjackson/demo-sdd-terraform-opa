# Regal: Common Bug Patterns to Avoid

This document covers Regal rules that catch common bugs in Rego policies.

**Relevant Regal rules:**
- [`constant-condition`](https://docs.styra.com/regal/rules/bugs/constant-condition) — avoid conditions that are always true or always false
- [`sprintf-arguments-mismatch`](https://docs.styra.com/regal/rules/bugs/sprintf-arguments-mismatch) — `sprintf` format string must match the number of arguments
- [`not-equals-in-loop`](https://docs.styra.com/regal/rules/bugs/not-equals-in-loop) — using `!=` in a loop creates an unexpected universal quantifier; use `not ... in` instead
- [`top-level-iteration`](https://docs.styra.com/regal/rules/bugs/top-level-iteration) — avoid iterating over a collection at the top level of a rule body when a comprehension or `some` is needed
- [`impossible-not`](https://docs.styra.com/regal/rules/bugs/impossible-not) — negating a rule that can only be true makes the check always fail

## Bug: Constant Condition

Avoid conditions that are trivially true or false — they indicate logic errors.

```rego
# WRONG: always true condition (constant-condition violation)
allow if {
    input.user != ""   # This is always true (non-empty string != "")
    input.role == "admin"
}

# CORRECT: test for existence, then use the value
allow if {
    input.user          # truthy check — user field exists and is non-empty
    input.role == "admin"
}
```

## Bug: sprintf Argument Count Mismatch

The number of `%v`/`%s`/`%d` format verbs must match the array of arguments.

```rego
# WRONG: 2 verbs, 1 argument (sprintf-arguments-mismatch violation)
msg := sprintf("container %s in pod %s is privileged", [container.name])

# CORRECT: 2 verbs, 2 arguments
msg := sprintf("container %s in pod %s is privileged", [container.name, pod.name])
```

## Bug: `!=` in a Loop

Using `!=` inside a loop does **not** check that no element equals the value — it succeeds whenever any element differs. Use `not ... in` for "not a member" checks.

```rego
# WRONG: succeeds if ANY role != "admin" (not-equals-in-loop violation)
deny if {
    some role in input.roles
    role != "admin"
}

# CORRECT: succeeds if "admin" is NOT in the collection
deny if {
    not "admin" in input.roles
}
```

## Bug: Not-Equals Membership Confusion

Distinguish between "this specific value is not in the set" and "some value in the set differs."

```rego
# WRONG: succeeds for any element that doesn't match (not-equals-in-loop)
allow if {
    some permission in user_permissions
    permission != "blocked"
}

# CORRECT: check that a specific permission is not present
allow if {
    not "blocked" in user_permissions
}

# CORRECT: check that a required permission is present
allow if {
    "read" in user_permissions
}
```

## Bug: Top-Level Iteration

Don't iterate at the top level of a rule when you need to collect results.

```rego
# WRONG: top-level iteration assigns one value at a time (top-level-iteration)
container_names := input.spec.containers[_].name

# CORRECT: use a comprehension to collect all values
container_names := {c.name | some c in input.spec.containers}
```

## Complete Example: Safe Policy Patterns

```rego
package kubernetes.validation
import rego.v1

# Use sprintf with matching argument count
deny contains msg if {
    some container in input.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("container '%s' in namespace '%s' runs as privileged",
                   [container.name, input.metadata.namespace])
}

# Use `not ... in` for negative membership
deny contains msg if {
    required_labels := {"app", "version", "owner"}
    provided_labels := object.keys(input.metadata.labels)
    missing := required_labels - provided_labels
    count(missing) > 0
    msg := sprintf("missing required labels: %v", [missing])
}
```

## Testing Bug-Free Patterns

```rego
package kubernetes.validation_test
import rego.v1
import data.kubernetes.validation

test_privileged_container_denied if {
    some msg in validation.deny
    contains(msg, "runs as privileged")
} with input as {
    "metadata": {"namespace": "default", "labels": {"app": "x", "version": "1", "owner": "y"}},
    "spec": {"containers": [
        {"name": "shell", "securityContext": {"privileged": true}}
    ]}
}

test_missing_labels_denied if {
    some msg in validation.deny
    contains(msg, "missing required labels")
} with input as {
    "metadata": {"namespace": "default", "labels": {"app": "x"}},
    "spec": {"containers": [
        {"name": "app", "securityContext": {"privileged": false}}
    ]}
}
```
