# Regal: Comprehension Patterns

This document covers Regal rules related to set, object, and array comprehensions.

**Relevant Regal rules:**
- [`comprehension-term-assignment`](https://docs.styra.com/regal/rules/idiomatic/comprehension-term-assignment) — do not assign a value inside a comprehension just to use it as the term; use the expression directly
- [`use-object-keys`](https://docs.styra.com/regal/rules/idiomatic/use-object-keys) — use `object.keys(obj)` instead of `{k | some k in obj}` to get object keys
- [`use-some-for-output-vars`](https://docs.styra.com/regal/rules/idiomatic/use-some-for-output-vars) — declare output variables with `some` in comprehension bodies

## Pattern: Comprehension Term Assignment

Use the expression directly as the comprehension term rather than assigning it to a variable first.

```rego
# CORRECT: use expression directly as the term
names := {container.name | some container in input.spec.containers}

# CORRECT: multi-field object comprehension
resources := {name: limit |
    some container in input.spec.containers
    name := container.name
    limit := container.resources.limits.cpu
}
```

```rego
# WRONG: assigning to variable just to use as term (comprehension-term-assignment violation)
names := {name | some container in input.spec.containers; name := container.name}
```

## Pattern: Object Keys

Use `object.keys()` to get the keys of an object.

```rego
# CORRECT: use object.keys()
required_fields := {"name", "email", "role"}
provided_fields := object.keys(input.user)
missing := required_fields - provided_fields
```

```rego
# WRONG: comprehension to get keys (use-object-keys violation)
provided_fields := {k | some k in input.user}
```

## Pattern: Output Variables in Comprehensions

Declare output variables with `some` in comprehension bodies.

```rego
# CORRECT: some for output variable
active_users := {user |
    some user in input.users
    user.active == true
}

# CORRECT: some for key iteration
tag_names := {key | some key, _ in input.resource.tags}
```

## Complete Example: Resource Compliance Check

```rego
package terraform.compliance
import rego.v1

# Use object.keys() — not a comprehension
provided_tags := object.keys(input.resource.tags)

required_tags := {"environment", "owner", "cost_center"}

missing_tags := required_tags - provided_tags

# Use expression directly as term — no intermediate variable
allowed_regions := {"us-east-1", "us-west-2", "eu-west-1"}

deny contains msg if {
    count(missing_tags) > 0
    msg := sprintf("missing required tags: %v", [missing_tags])
}

deny contains msg if {
    input.resource.region != null
    not input.resource.region in allowed_regions
    msg := sprintf("region '%s' is not allowed", [input.resource.region])
}
```

## Testing Comprehension Patterns

```rego
package terraform.compliance_test
import rego.v1
import data.terraform.compliance

test_missing_tags if {
    some msg in compliance.deny
    contains(msg, "missing required tags")
} with input as {
    "resource": {
        "tags": {"environment": "prod"},
        "region": "us-east-1"
    }
}

test_all_tags_present if {
    count(compliance.deny) == 0
} with input as {
    "resource": {
        "tags": {"environment": "prod", "owner": "team-a", "cost_center": "123"},
        "region": "us-east-1"
    }
}
```
