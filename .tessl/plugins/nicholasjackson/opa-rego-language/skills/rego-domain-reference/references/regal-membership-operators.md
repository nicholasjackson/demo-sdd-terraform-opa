# Regal: Membership and Operators

## Rule: `use-in-operator`

Use the `in` keyword to check set/array membership — do not iterate and compare. Regal [use-in-operator](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-in-operator).

```rego
# Wrong — iterates to check membership
"admin" == input.user.roles[_]

# Correct — in operator
"admin" in input.user.roles
```

## Rule: `use-assignment-operator`

Use `:=` for assignment, never `=`. The `=` operator is unification (pattern matching) — using it for assignment is misleading and error-prone. Regal [use-assignment-operator](https://www.openpolicyagent.org/projects/regal/rules/style/use-assignment-operator).

```rego
# Wrong
user = input.user

# Correct
user := input.user
```

## Rule: `yoda-condition`

Write the variable on the left, the literal on the right — not the other way around. Regal [yoda-condition](https://www.openpolicyagent.org/projects/regal/rules/style/yoda-condition).

```rego
# Wrong — yoda condition
"admin" == input.user.role

# Correct
input.user.role == "admin"
```

## Rule: `prefer-equals-comparison`

Use `==` for equality comparison, not `=`. Regal [prefer-equals-comparison](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/prefer-equals-comparison).

## Full Example

```rego
# METADATA
# title: Department-Based API Access Control
# description: Allows access to endpoints based on user department membership
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow department access
# description: Permits requests when the user's department is in the allowed set for the path
# entrypoint: true
# custom:
#   severity: HIGH
allow if {
    allowed_departments := data.endpoint_access[input.path]
    input.user.department in allowed_departments
}
```

**Data** (`data.endpoint_access`):
```json
{
    "/api/reports": ["engineering", "finance", "management"],
    "/api/admin": ["management"]
}
```

**Input**:
```json
{
    "method": "GET",
    "path": "/api/reports",
    "user": {"department": "engineering"}
}
```

**Result**: `allow == true` — `"engineering" in ["engineering", "finance", "management"]`

## Testing

```rego
# authz_test.rego
package httpapi.authz_test

import rego.v1
import data.httpapi.authz

access := {"/api/reports": ["engineering", "finance"], "/api/admin": ["management"]}

test_allowed_department if {
    authz.allow with input as {"path": "/api/reports", "user": {"department": "engineering"}}
               with data.endpoint_access as access
}

test_denied_department if {
    not authz.allow with input as {"path": "/api/reports", "user": {"department": "hr"}}
                   with data.endpoint_access as access
}

test_denied_wrong_path if {
    not authz.allow with input as {"path": "/api/admin", "user": {"department": "engineering"}}
                   with data.endpoint_access as access
}
```
