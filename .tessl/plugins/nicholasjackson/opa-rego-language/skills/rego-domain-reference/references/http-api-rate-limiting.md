# HTTP API Rate Limiting with Per-User Limits

## Overview

Rate limiting in Rego uses the `default rule := value` pattern to provide a fallback limit. This is the same pattern as `default allow := false` — just applied to a non-boolean rule. Multiple rule heads then return tier-specific values when conditions match.

## Key Pattern: `default rule := value`

Declare the fallback with `default`, then add specific rule heads for each tier:

```rego
# Fallback for unknown tiers — same pattern as `default allow := false`
default user_limit := 10

# Specific values for known tiers
user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100 if data.user_tiers[input.user] == "standard"
```

The `default` declaration ensures `user_limit` always has a value even when no tier matches. Do **not** use `else :=` — Regal flags this with [default-over-else](https://www.openpolicyagent.org/projects/regal/rules/style/default-over-else).

## Full Example

```rego
# METADATA
# title: Rate Limiting Policies
# description: Enforces rate limits based on user tier with a safe default fallback
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow rate-limited requests
# description: Permits requests when the user is within their rate limit
# entrypoint: true
# custom:
#   severity: MEDIUM
allow if {
    not rate_limit_exceeded
}

rate_limit_exceeded if {
    input.request_count >= user_limit
}

# Default fallback for unknown tiers
default user_limit := 10

user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100 if data.user_tiers[input.user] == "standard"
```

## Input / Data

**Input**:
```json
{
    "user": "bob",
    "request_count": 120
}
```

**Data** (`data.user_tiers`):
```json
{
    "alice": "premium",
    "bob": "standard"
}
```

**Result**: `allow == false` — bob is standard tier (limit 100), request_count 120 >= 100.

## Testing

Per the Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix) rule, test files must use a `_test.rego` suffix. Import the policy package and reference rules via the alias.

```rego
# authz_test.rego
package httpapi.authz_test

import rego.v1
import data.httpapi.authz  # import the policy package under test

tiers := {"alice": "premium", "bob": "standard"}

# Premium user within limit
test_premium_user_allowed if {
    authz.allow with input as {"user": "alice", "request_count": 999}
               with data.user_tiers as tiers
}

# Standard user over limit
test_standard_user_denied if {
    not authz.allow with input as {"user": "bob", "request_count": 101}
                   with data.user_tiers as tiers
}

# Unknown user gets default limit of 10
test_unknown_user_default_limit if {
    not authz.allow with input as {"user": "unknown", "request_count": 11}
                   with data.user_tiers as tiers
}

# Unknown user within default limit
test_unknown_user_within_default if {
    authz.allow with input as {"user": "unknown", "request_count": 5}
               with data.user_tiers as tiers
}
```
