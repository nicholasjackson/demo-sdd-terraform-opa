# Regal: Testing Style and Conventions

This document covers Regal rules related to how tests are written and organized.

**Relevant Regal rules:**
- [`file-missing-test-suffix`](https://docs.styra.com/regal/rules/testing/file-missing-test-suffix) — test files must have a `_test.rego` filename suffix
- [`test-outside-test-package`](https://docs.styra.com/regal/rules/testing/test-outside-test-package) — test rules must live in packages ending in `_test`
- [`identically-named-tests`](https://docs.styra.com/regal/rules/testing/identically-named-tests) — every `test_` rule in a package must have a unique name
- [`todo-test`](https://docs.styra.com/regal/rules/testing/todo-test) — do not commit `todo_test_` prefixed rules; write the test or remove it

## Pattern: File Naming

Test files must use a `_test.rego` suffix alongside their policy files.

```
# CORRECT file layout:
policy.rego          # the policy
policy_test.rego     # the tests

# WRONG — not recognized as a test file:
policy.test.rego     # (file-missing-test-suffix)
test_policy.rego     # (file-missing-test-suffix)
```

## Pattern: Test Package Names

Test packages must mirror the policy package with a `_test` suffix.

```rego
# policy.rego
package myapp.authz
import rego.v1

# policy_test.rego — CORRECT
package myapp.authz_test
import rego.v1
import data.myapp.authz  # import the policy to test it
```

```rego
# WRONG: test rules inside the policy package (test-outside-test-package)
package myapp.authz

test_allow if { ... }  # violation — tests must be in *_test packages
```

## Pattern: Importing the Policy Under Test

Because the test package is different from the policy package, import the policy and use its alias.

```rego
package myapp.authz_test
import rego.v1
import data.myapp.authz  # gives the alias "authz"

test_admin_allowed if {
    authz.allow with input as {"role": "admin"}
}

test_viewer_denied if {
    not authz.allow with input as {"role": "viewer"}
}
```

## Pattern: Unique Test Names

Every `test_` rule in a package must have a unique name.

```rego
# WRONG: duplicate name (identically-named-tests violation)
test_allow if { authz.allow with input as {"role": "admin"} }
test_allow if { authz.allow with input as {"role": "superuser"} }  # duplicate!

# CORRECT: descriptive unique names
test_allow_admin if { authz.allow with input as {"role": "admin"} }
test_allow_superuser if { authz.allow with input as {"role": "superuser"} }
```

## Pattern: No TODO Tests

Do not leave placeholder `todo_test_` rules in committed code. Either write the test or remove it.

```rego
# WRONG: todo test stub (todo-test violation)
todo_test_rate_limiting if { true }

# CORRECT: write the actual test
test_rate_limit_premium if {
    limits.max_requests == 1000
        with input as {"user": "alice"}
        with data.tiers as {"alice": "premium"}
}
```

## Complete Example: Well-Structured Test File

**`authz.rego`**:
```rego
package api.authz
import rego.v1

default allow := false

allow if input.role == "admin"
allow if {
    input.role == "viewer"
    input.method == "GET"
}
```

**`authz_test.rego`**:
```rego
package api.authz_test
import rego.v1
import data.api.authz

test_allow_admin if {
    authz.allow with input as {"role": "admin", "method": "POST"}
}

test_allow_viewer_get if {
    authz.allow with input as {"role": "viewer", "method": "GET"}
}

test_deny_viewer_post if {
    not authz.allow with input as {"role": "viewer", "method": "POST"}
}

test_deny_unknown_role if {
    not authz.allow with input as {"role": "guest", "method": "GET"}
}
```

Run with: `opa test . -v`
