# HTTP API Request Body Validation

## Overview

Request body validation in Rego uses **set subtraction** to detect unknown fields and explicit iteration to detect missing required fields. This pattern efficiently validates that a POST body contains only allowed fields and all required fields are present.

## Key Pattern: Set Subtraction for Unknown Fields

To detect unknown fields, compute the set of submitted field names from `input.body` using a set comprehension, then subtract the allowed set. If the result is non-empty (`!= set()`), unknown fields are present.

```rego
body_fields := {field | input.body[field]}
body_fields - allowed_fields != set()
```

This is more concise and efficient than iterating field-by-field — a single subtraction operation finds all unknown fields at once.

## Full Example

```rego
# METADATA
# title: Request Body Validation
# description: Validates request body structure — rejects unknown fields and enforces required fields
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

allowed_fields := {"username", "email", "display_name"}
required_fields := {"username", "email"}

# METADATA
# title: Allow valid POST requests
# description: Permits POST /api/users when the body has no unknown fields and all required fields are present
# entrypoint: true
# custom:
#   severity: MEDIUM
allow if {
    input.method == "POST"
    input.path == "/api/users"
    count(deny) == 0
}

# Reject unknown fields: compute submitted field names and use set subtraction
deny contains msg if {
    input.method == "POST"
    input.path == "/api/users"
    body_fields := {field | input.body[field]}
    body_fields - allowed_fields != set()
    msg := sprintf("unknown fields in request body: %v", [body_fields - allowed_fields])
}

# Reject missing required fields
deny contains msg if {
    input.method == "POST"
    input.path == "/api/users"
    some field in required_fields
    not input.body[field]
    msg := sprintf("required field missing from request body: %v", [field])
}
```

## Input / Output

**Example Input** (unknown field `admin` present):
```json
{
    "method": "POST",
    "path": "/api/users",
    "body": {
        "username": "alice",
        "email": "alice@example.com",
        "admin": true
    }
}
```

**Result**: `allow == false` — `body_fields` is `{"username", "email", "admin"}`, so `body_fields - allowed_fields` is `{"admin"}` which is not `set()`, and the deny rule fires.

**Example Input** (valid body):
```json
{
    "method": "POST",
    "path": "/api/users",
    "body": {
        "username": "alice",
        "email": "alice@example.com"
    }
}
```

**Result**: `allow == true` — `body_fields - allowed_fields` is `set()` and both required fields are present.

## Testing

Per the Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix) rule, test files must use a `_test.rego` suffix. Because the test is in a separate `_test` package, import the policy and reference rules via the alias.

```rego
# authz_test.rego
package httpapi.authz_test

import rego.v1
import data.httpapi.authz  # import the policy package under test

# Allow: only allowed fields, all required fields present
test_valid_body_allowed if {
    authz.allow with input as {
        "method": "POST",
        "path": "/api/users",
        "body": {"username": "alice", "email": "alice@example.com"}
    }
}

# Deny: unknown field present — set subtraction detects it
test_unknown_field_denied if {
    not authz.allow with input as {
        "method": "POST",
        "path": "/api/users",
        "body": {"username": "alice", "email": "alice@example.com", "admin": true}
    }
}

# Deny: required field missing
test_missing_required_field_denied if {
    not authz.allow with input as {
        "method": "POST",
        "path": "/api/users",
        "body": {"username": "alice"}
    }
}
```
