# Regal: Import Conventions

This document covers Regal rules related to import organization and style.

**Relevant Regal rules:**
- [`prefer-package-imports`](https://docs.styra.com/regal/rules/imports/prefer-package-imports) — import the package, not individual rules from it
- [`redundant-alias`](https://docs.styra.com/regal/rules/imports/redundant-alias) — do not alias an import with the same name it already has
- [`import-after-rule`](https://docs.styra.com/regal/rules/imports/import-after-rule) — all imports must appear before any rule declarations
- [`avoid-importing-input-data`](https://docs.styra.com/regal/rules/imports/avoid-importing-input-data) — do not `import input` or `import data` at the top level

## Pattern: Import the Package, Not Rules

Import the package and use the alias to reference its rules.

```rego
# CORRECT: import the package
import data.lib.http_utils  # → use as http_utils.is_valid_method(...)
import data.rbac.authz      # → use as authz.allow
```

```rego
# WRONG: importing individual rules (prefer-package-imports violation)
import data.lib.http_utils.is_valid_method
import data.rbac.authz.allow
```

## Pattern: No Redundant Aliases

Don't alias an import to the same identifier it already has.

```rego
# CORRECT: no alias (last path segment is already the name)
import data.lib.helpers
import data.policies.authz

# CORRECT: alias only when renaming is meaningful
import data.very.long.package.name as short_name
```

```rego
# WRONG: alias equals the last path segment (redundant-alias violation)
import data.lib.helpers as helpers     # redundant
import data.policies.authz as authz   # redundant
```

## Pattern: Imports Before Rules

All imports must appear in the header section before any rules.

```rego
# CORRECT: all imports at the top
package myapp.policy
import rego.v1
import data.lib.helpers
import data.users

default allow := false

allow if helpers.is_admin(input.user)
```

```rego
# WRONG: import after rule (import-after-rule violation)
package myapp.policy
import rego.v1

default allow := false

import data.lib.helpers   # too late — must be before all rules

allow if helpers.is_admin(input.user)
```

## Pattern: Do Not Import Input or Data Directly

Avoid importing `input` or `data` at the top level — reference them directly in rules.

```rego
# WRONG: importing data or input (avoid-importing-input-data violation)
import input as req
import data.users as users_db

# CORRECT: reference directly
allow if {
    some user in data.users
    user.name == input.username
}
```

## Complete Example: Correct Import Structure

**`policy.rego`**:
```rego
package api.authz
import rego.v1
import data.lib.jwt_utils
import data.rbac.roles

default allow := false

allow if {
    claims := jwt_utils.decode(input.token)
    user_role := roles.user_role(claims.sub)
    user_role in {"admin", "editor"}
}
```

**`lib/jwt_utils.rego`** (the imported package):
```rego
package lib.jwt_utils
import rego.v1

decode(token) := claims if {
    parts := split(token, ".")
    claims := json.unmarshal(base64url.decode(parts[1]))
}
```

**`policy_test.rego`**:
```rego
package api.authz_test
import rego.v1
import data.api.authz

test_allow_admin if {
    authz.allow with input as {"token": "header.eyJzdWIiOiJhbGljZSJ9.sig"}
                with data.rbac.roles as {"user_role": {"alice": "admin"}}
}
```
