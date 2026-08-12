# Regal: Policy Annotations

This document covers Regal rules related to metadata annotations on policies and rules.

**Relevant Regal rules:**
- [`missing-metadata`](https://docs.styra.com/regal/rules/idiomatic/missing-metadata) — modules and rules should have metadata annotations
- [`detached-metadata`](https://docs.styra.com/regal/rules/idiomatic/detached-metadata) — metadata comments must be immediately above the rule with no blank lines between
- [`no-defined-entrypoint`](https://docs.styra.com/regal/rules/idiomatic/no-defined-entrypoint) — at least one rule should be annotated with `entrypoint: true`

## Package Annotation

Every module must have a package-level annotation block using the `# METADATA` comment syntax.

```rego
# METADATA
# title: API Authorization Policy
# description: Enforces role-based access control for the REST API
# authors:
#   - Platform Security Team
# related_resources:
#   - ref: https://www.openpolicyagent.org/docs/latest/
# schemas:
#   - input: schema.input
package api.authz
import rego.v1
```

## Rule-Level Annotations with Entrypoint

Mark the primary decision rule as the entrypoint.

```rego
# METADATA
# title: Allow
# description: Grants access when the user's role has the required permission
# entrypoint: true
default allow := false

allow if {
    user_role := data.user_roles[input.user]
    required_permission in data.role_permissions[user_role]
}
```

## Detached Metadata — No Blank Lines

The `# METADATA` block must immediately precede the rule it annotates — no blank lines in between.

```rego
# CORRECT: annotation immediately above the rule
# METADATA
# title: Deny
# description: Collects policy violation messages
deny contains msg if {
    not input.user
    msg := "user is required"
}
```

```rego
# WRONG: blank line between annotation and rule (detached-metadata violation)
# METADATA
# title: Deny

deny contains msg if {     # blank line above detaches the annotation
    not input.user
    msg := "user is required"
}
```

## Complete Annotated Policy

```rego
# METADATA
# title: RBAC Authorization
# description: |
#   Role-based access control for API endpoints.
#   Users have roles; roles have permissions; allow when the user's role
#   grants the required permission.
# authors:
#   - Platform Team
# schemas:
#   - input: schema["input.json"]
package rbac.authz
import rego.v1

# METADATA
# title: Allow
# description: Grants access when user role has the required permission
# entrypoint: true
default allow := false

allow if {
    user_role := data.user_roles[input.user]
    required_permission in data.role_permissions[user_role]
}

# METADATA
# title: User Role
# description: Returns the role assigned to the requesting user
user_role := role if {
    role := data.user_roles[input.user]
}

# METADATA
# title: Required Permission
# description: Derives the permission key from method and path
required_permission := permission if {
    action := lower(input.method)
    resource := trim_prefix(input.path, "/api/")
    permission := sprintf("%s:%s", [resource, action])
}
```

## Testing Annotated Policies

Annotations do not affect runtime behavior — test the rules as normal.

```rego
package rbac.authz_test
import rego.v1
import data.rbac.authz

test_allow_engineer_read if {
    authz.allow
        with input as {"user": "alice", "method": "GET", "path": "/api/reports"}
        with data.user_roles as {"alice": "engineer"}
        with data.role_permissions as {"engineer": ["reports:get"]}
}

test_deny_engineer_write if {
    not authz.allow
        with input as {"user": "alice", "method": "POST", "path": "/api/reports"}
        with data.user_roles as {"alice": "engineer"}
        with data.role_permissions as {"engineer": ["reports:get"]}
}
```
