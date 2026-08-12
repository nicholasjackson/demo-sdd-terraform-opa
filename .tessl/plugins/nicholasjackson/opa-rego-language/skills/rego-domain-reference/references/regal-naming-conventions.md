# Regal: Naming Conventions

## Rule: `prefer-snake-case`

All identifiers — rules, functions, variables, constants — must use `snake_case`. No camelCase or PascalCase. Regal [prefer-snake-case](https://www.openpolicyagent.org/projects/regal/rules/style/prefer-snake-case).

```rego
# Wrong
getUserRole := input.user.role
isAdmin := ...

# Correct
user_role := input.user.role
is_admin := ...
```

## Rule: `avoid-get-and-list-prefix`

Do not prefix rule or function names with `get_` or `list_`. These prefixes are implied by Rego semantics — a rule that evaluates to a value is already a "getter". Regal [avoid-get-and-list-prefix](https://www.openpolicyagent.org/projects/regal/rules/style/avoid-get-and-list-prefix).

```rego
# Wrong
get_user_role := data.roles[input.user]
list_allowed_actions := data.permissions[input.user.role]

# Correct
user_role := data.roles[input.user]
allowed_actions := data.permissions[input.user.role]
```

## Rule: `rule-name-repeats-package`

Do not repeat the package path in rule names. If the package is `rbac.authz`, a rule named `rbac_authz_allow` is redundant — call it `allow`. Regal [rule-name-repeats-package](https://www.openpolicyagent.org/projects/regal/rules/style/rule-name-repeats-package).

## Conventions

- Use `is_` or `has_` prefix for boolean helpers: `is_admin`, `has_required_labels`
- Use `_` prefix for internal helpers not part of the public API: `_normalize_path`
- Test functions use `test_` prefix with a descriptive name: `test_deny_missing_label`

## Full Example

```rego
# METADATA
# title: RBAC Authorization
# description: Role-based access control for API endpoints
# authors:
# - Platform Team <platform@example.com>
# custom:
#   category: rbac
package rbac.authz

import rego.v1

default allow := false

# METADATA
# title: Allow authorized users
# description: Permits requests where the user has the required permission
# entrypoint: true
# custom:
#   severity: HIGH
allow if {
    required_permission := endpoint_permission[input.path][input.method]
    required_permission in user_permissions
}

# User's permissions derived from their role
user_permissions := data.role_permissions[user_role]

# User's assigned role
user_role := data.user_roles[input.user]

# Permission required for each endpoint and method
endpoint_permission := {
    "/api/reports": {"GET": "reports:read", "POST": "reports:write"},
    "/api/users":   {"GET": "users:read",   "POST": "users:write"},
}

# Boolean helper — is_* prefix for boolean checks
is_admin if user_role == "admin"
```

## Testing

```rego
# authz_test.rego
package rbac.authz_test

import rego.v1
import data.rbac.authz

roles := {"alice": "engineer", "bob": "admin"}
permissions := {"engineer": {"reports:read"}, "admin": {"reports:read", "reports:write", "users:read", "users:write"}}

test_allow_engineer_read if {
    authz.allow with input as {"user": "alice", "method": "GET", "path": "/api/reports"}
               with data.user_roles as roles
               with data.role_permissions as permissions
}

test_deny_engineer_write if {
    not authz.allow with input as {"user": "alice", "method": "POST", "path": "/api/reports"}
                   with data.user_roles as roles
                   with data.role_permissions as permissions
}

test_allow_admin_write if {
    authz.allow with input as {"user": "bob", "method": "POST", "path": "/api/reports"}
               with data.user_roles as roles
               with data.role_permissions as permissions
}
```
