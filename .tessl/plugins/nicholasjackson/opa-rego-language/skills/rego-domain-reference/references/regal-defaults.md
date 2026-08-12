# Regal: Default Rules and Fallback Values

This document covers Regal rules related to how default values are declared and used.

**Relevant Regal rules:**
- [`default-over-else`](https://docs.styra.com/regal/rules/idiomatic/default-over-else) — use `default rule := value` instead of an else branch for fallback values
- [`default-over-not`](https://docs.styra.com/regal/rules/idiomatic/default-over-not) — use `default rule := false` instead of `rule := false if { not other_rule }`
- [`trailing-default-rule`](https://docs.styra.com/regal/rules/style/trailing-default-rule) — place `default` declarations at the top of the rule group, not at the bottom

## Pattern: `default rule := value`

Use `default` to declare fallback values. Declare the default **before** the conditional rules in the file.

```rego
package rate.limiting
import rego.v1

# CORRECT: default at top, conditional overrides below
default user_limit := 10

user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100  if data.user_tiers[input.user] == "standard"
```

```rego
# WRONG: trailing default (trailing-default-rule violation)
user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100  if data.user_tiers[input.user] == "standard"
default user_limit := 10
```

## Pattern: `default` instead of `else`

Prefer `default rule := false` over an `else` branch for simple fallbacks.

```rego
# CORRECT: use default
default allow := false

allow if {
    input.role == "admin"
}
```

```rego
# WRONG: else branch for fallback (default-over-else violation)
allow if {
    input.role == "admin"
} else := false
```

## Pattern: `default` instead of negation

Prefer `default rule := false` over explicitly checking `not other_rule`.

```rego
# CORRECT: use default
default allow := false

allow if input.role == "admin"
```

```rego
# WRONG: negation to set false (default-over-not violation)
allow if input.role == "admin"
allow := false if not allow
```

## Multiple Tiered Defaults

When a rule has multiple conditional values and a fallback, the default is always the fallback:

```rego
package api.limits
import rego.v1

# Fallback declared first
default max_requests := 100

# Overrides for specific tiers
max_requests := 10000 if data.tiers[input.user_id] == "enterprise"
max_requests := 1000  if data.tiers[input.user_id] == "pro"
```

## Testing Default Rules

Test both the default case and each override:

```rego
package api.limits_test
import rego.v1
import data.api.limits

test_default_limit if {
    limits.max_requests == 100 with data.tiers as {}
}

test_pro_limit if {
    limits.max_requests == 1000 with input as {"user_id": "alice"}
                                with data.tiers as {"alice": "pro"}
}

test_enterprise_limit if {
    limits.max_requests == 10000 with input as {"user_id": "corp"}
                                 with data.tiers as {"corp": "enterprise"}
}
```
