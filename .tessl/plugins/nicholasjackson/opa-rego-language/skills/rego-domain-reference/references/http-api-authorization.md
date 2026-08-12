# HTTP API Authorization

## Overview

HTTP API authorization is a critical component of modern application security. OPA and Rego provide powerful, context-aware policy enforcement for controlling access to REST APIs, microservices, and web applications. This document covers common patterns for implementing fine-grained authorization policies that control who can access which API endpoints and under what conditions.

HTTP API authorization policies typically evaluate requests based on:
- User identity and roles
- HTTP method (GET, POST, PUT, DELETE, etc.)
- Request path and parameters
- Authentication tokens (JWT, OAuth2, API keys)
- Request headers and body content
- Time-based constraints
- IP address and network location
- Rate limits and quotas

---

## 1. Hierarchical Authorization (Manager-Subordinate Relationships)

**Description**: Implements context-aware authorization based on organizational hierarchy, allowing users to access their own resources and managers to access their subordinates' resources.

```rego
# METADATA
# title: Hierarchical Authorization
# description: Context-aware authorization based on organizational hierarchy
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

# Define organizational hierarchy
subordinates := {
    "alice": [],
    "charlie": [],
    "bob": ["alice"],
    "betty": ["charlie"]
}

default allow := false

# METADATA
# title: Allow authorized requests
# description: Permits requests based on hierarchical manager-subordinate relationships
# entrypoint: true
# custom:
#   severity: HIGH
# Allow users to get their own salaries
allow if {
    input.method == "GET"
    input.path == ["finance", "salary", input.user]
}

# Allow managers to get their subordinates' salaries
allow if {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    username in subordinates[input.user]
}
```

**Example Input**:
```json
{
    "method": "GET",
    "path": ["finance", "salary", "alice"],
    "user": "bob"
}
```

**Result**: `allow == true` (bob is alice's manager)

---

## 2. JWT-Based Access Control with Claims Validation

**Description**: Validates JWT tokens and extracts claims to make authorization decisions, ensuring tokens are issued to the correct user.

```rego
# METADATA
# title: JWT-Based Access Control
# description: Validates JWT tokens and extracts claims for authorization decisions
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow JWT-authenticated requests
# description: Permits requests when JWT token claims match authorization requirements
# entrypoint: true
# custom:
#   severity: HIGH
# Allow users to get their own salaries
allow if {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    token.payload.user == username
    user_owns_token
}

# Allow managers to get their subordinates' salaries
allow if {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    username in token.payload.subordinates
    user_owns_token
}

# Allow HR members to get anyone's salary
allow if {
    input.method == "GET"
    input.path = ["finance", "salary", _]
    token.payload.hr == true
    user_owns_token
}

# Ensure that the token was issued to the user supplying it
user_owns_token if {
    input.user == token.payload.azp
}

# Helper to get the token payload
token := {"payload": payload} if {
    [header, payload, signature] := io.jwt.decode(input.token)
}
```

**Example Input**:
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "method": "GET",
    "path": ["finance", "salary", "alice"],
    "user": "alice"
}
```

**Result**: `allow == true` (token validates and user matches)

---

## 3. Method-Based Permissions (GET/POST/PUT/DELETE)

**Description**: Restricts HTTP methods based on user permissions, implementing a standard read/write/admin permission model.

```rego
# METADATA
# title: Method-Based Permissions
# description: Restricts HTTP methods based on user read/write/admin permissions
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

import data.users

default allow := false

# METADATA
# title: Allow method-based access
# description: Permits requests when user has the required permission for the HTTP method
# entrypoint: true
# custom:
#   severity: HIGH
# Allow GET requests for users with read permission
allow if {
    input.method == "GET"
    "read" in users[input.user].permissions
}

# Allow POST, PUT, PATCH for users with write permission
allow if {
    input.method in {"POST", "PUT", "PATCH"}
    "write" in users[input.user].permissions
}

# Allow DELETE for users with admin permission
allow if {
    input.method == "DELETE"
    "admin" in users[input.user].permissions
}
```

**Example Data** (loaded as `data.users`):
```json
{
    "alice": {"permissions": ["read", "write"]},
    "bob": {"permissions": ["read"]},
    "admin": {"permissions": ["read", "write", "admin"]}
}
```

**Example Input**:
```json
{
    "method": "DELETE",
    "user": "alice"
}
```

**Result**: `allow == false` (alice doesn't have admin permission)

---

## 4. Path-Based Authorization with Wildcards and Patterns

**Description**: Controls access based on API path patterns using glob matching, allowing administrators to define flexible access rules.

```rego
# METADATA
# title: Path-Based Authorization
# description: Controls access based on API path patterns using glob matching
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

import data.api_permissions

default allow := false

# METADATA
# title: Allow path-matched requests
# description: Permits requests when the user has a matching path pattern permission
# entrypoint: true
# custom:
#   severity: HIGH
# Check if user has permission for the requested path
allow if {
    some pattern in api_permissions[input.user]
    glob.match(pattern, ["/"], concat("/", input.path))
}
```

**Example Data** (loaded as `data.api_permissions`):
```json
{
    "alice": ["/api/users/*", "/api/reports/personal/*"],
    "bob": ["/api/*/read", "/api/public/*"],
    "admin": ["/api/**"]
}
```

**Example Input**:
```json
{
    "user": "alice",
    "path": ["api", "users", "123"]
}
```

**Result**: `allow == true` (matches pattern `/api/users/*`)

---

## 5. Token Validation (OAuth2 and OIDC)

**Description**: Validates JWT-based tokens for both OAuth2 (scope + expiry) and OIDC (email domain extraction) patterns.

The key patterns beyond basic `io.jwt.decode`:
- **OAuth2**: check expiry with `token.payload.exp > time.now_ns() / 1000000000` (nanosecond to second conversion) and look up required scopes via an endpoint map
- **OIDC**: extract email domain with `split(email, "@")[1]` and validate multiple claims (exp, iss, aud, email_verified) in one rule body

```rego
package httpapi.authz

import rego.v1

# --- OAuth2 ---

default allow := false

allow if {
    token_valid
    has_required_scope
}

token_valid if {
    token.payload.exp > time.now_ns() / 1000000000
    token.payload.iss == "https://auth.example.com"
}

has_required_scope if {
    required_scope := endpoint_scopes[concat("/", input.path)]
    required_scope in token.payload.scope
}

endpoint_scopes := {
    "/api/users": "users:read",
    "/api/users/create": "users:write",
    "/api/admin": "admin:access",
}

token := {"payload": payload} if {
    [_, payload, _] := io.jwt.decode(input.token)
}

# --- OIDC ---

oidc_token_valid if {
    token.payload.exp > time.now_ns() / 1000000000
    token.payload.iss == "https://accounts.google.com"
    token.payload.aud == "our-app-client-id"
    token.payload.email_verified == true
}

user_domain_allowed if {
    email := token.payload.email
    domain := split(email, "@")[1]
    domain in {"example.com", "partner.com"}
}
```

---

## 6. API Key Authentication

**Description**: Validates API keys and enforces key-specific permissions and rate limits.

```rego
# METADATA
# title: API Key Authentication
# description: Validates API keys and enforces key-specific permissions and rate limits
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

import data.api_keys

default allow := false

# METADATA
# title: Allow API key-authenticated requests
# description: Permits requests when the API key is valid and has matching path permission
# entrypoint: true
# custom:
#   severity: HIGH
# Allow access if API key is valid and has permission
allow if {
    api_key_valid
    api_key_has_permission
}

# Validate API key exists and is active
api_key_valid if {
    key := api_keys[input.api_key]
    key.active == true
    key.expires > time.now_ns()
}

# Check if API key has permission for the endpoint
api_key_has_permission if {
    key := api_keys[input.api_key]
    endpoint := concat("/", input.path)
    some path in key.allowed_paths
    glob.match(path, ["/"], endpoint)
}
```

**Example Data** (loaded as `data.api_keys`):
```json
{
    "sk_live_abc123": {
        "active": true,
        "expires": 9999999999000000000,
        "allowed_paths": ["/api/v1/*", "/webhooks/*"],
        "rate_limit": 1000
    },
    "sk_test_xyz789": {
        "active": true,
        "expires": 9999999999000000000,
        "allowed_paths": ["/api/v1/test/*"],
        "rate_limit": 100
    }
}
```

**Example Input**:
```json
{
    "api_key": "sk_live_abc123",
    "path": ["api", "v1", "users"]
}
```

**Result**: `allow == true` (valid key with matching path permission)

---

## 7. Rate Limiting Policies per User/IP

**Description**: Enforces rate limits based on user identity or IP address to prevent abuse.

**Key pattern — `default` for rule fallbacks**: The same `default rule := value` pattern used for `default allow := false` applies to any rule. Declare the fallback at the top, then add specific rule heads for each tier. This is the Regal-recommended style ([default-over-else](https://www.openpolicyagent.org/projects/regal/rules/style/default-over-else)) — do **not** use `else :=`:

```rego
# Fallback for unknown tiers — same pattern as `default allow := false`
default user_limit := 10

# Specific values for known tiers
user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100 if data.user_tiers[input.user] == "standard"
```

Full example:

```rego
# METADATA
# title: Rate Limiting Policies
# description: Enforces rate limits based on user identity or IP address to prevent abuse
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

default user_limit := 10

user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100 if data.user_tiers[input.user] == "standard"
```

**Example Data** (loaded as `data.rate_limits`):
```json
{
    "user_requests": {
        "alice": 95,
        "bob": 150
    },
    "ip_requests": {
        "192.168.1.100": 45,
        "192.168.1.101": 60
    }
}
```

**Example Input**:
```json
{
    "user": "bob",
    "request_count": 150
}
```

**Result**: `allow == false` (bob is standard tier, limit 100, request_count 150 >= 100)

**Testing**: Test each tier and the default fallback. Note that `data.user_tiers` is injected via `with data.user_tiers as`:

```rego
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
```

---

## 8. API Versioning Policies

**Description**: Enforces different authorization rules based on API version, allowing gradual migration and deprecation.

```rego
# METADATA
# title: API Versioning Policies
# description: Enforces different authorization rules based on API version
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow version-appropriate requests
# description: Permits requests based on API version-specific authentication requirements
# entrypoint: true
# custom:
#   severity: LOW
# API v1 - Legacy, requires basic auth
allow if {
    input.path[0] == "api"
    input.path[1] == "v1"
    input.auth_type == "basic"
    valid_basic_auth
}

# API v2 - Modern, requires JWT
allow if {
    input.path[0] == "api"
    input.path[1] == "v2"
    input.auth_type == "bearer"
    valid_jwt_token
}

# API v3 - Future, requires OAuth2 with specific scopes
allow if {
    input.path[0] == "api"
    input.path[1] == "v3"
    input.auth_type == "bearer"
    valid_oauth2_token
    has_required_scope_v3
}

valid_basic_auth if {
    # Basic validation logic
    input.credentials != ""
}

valid_jwt_token if {
    token := {"payload": payload} | [_, payload, _] := io.jwt.decode(input.token)
    token.payload.exp > time.now_ns() / 1000000000
}

valid_oauth2_token if {
    valid_jwt_token
}

has_required_scope_v3 if {
    token := {"payload": payload} | [_, payload, _] := io.jwt.decode(input.token)
    "api:v3:access" in token.payload.scopes
}
```

**Example Input**:
```json
{
    "path": ["api", "v2", "users"],
    "auth_type": "bearer",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTl9..."
}
```

**Result**: `allow == true` (v2 API with valid JWT)

---

## 9. CORS Policy Enforcement

**Description**: Enforces Cross-Origin Resource Sharing (CORS) policies by validating origin headers.

```rego
# METADATA
# title: CORS Policy Enforcement
# description: Enforces Cross-Origin Resource Sharing policies by validating origin headers
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow CORS-compliant requests
# description: Permits requests from same-origin or allowed cross-origin sources
# entrypoint: true
# custom:
#   severity: MEDIUM
# Allow same-origin requests
allow if {
    input.method in {"GET", "POST", "PUT", "DELETE"}
    not input.headers["origin"]
}

# Allow CORS requests from allowed origins
allow if {
    input.method in {"GET", "POST", "PUT", "DELETE"}
    origin := input.headers["origin"]
    origin in allowed_origins
}

# Allow preflight requests from allowed origins
allow if {
    input.method == "OPTIONS"
    origin := input.headers["origin"]
    origin in allowed_origins
}

# Define allowed origins
allowed_origins := {
    "https://app.example.com",
    "https://staging.example.com",
    "https://admin.example.com"
}

# Additional check for credentials
deny contains "CORS credentials not allowed" if {
    input.headers["origin"]
    input.headers["origin"] not in allowed_origins
    input.headers["access-control-allow-credentials"] == "true"
}
```

**Example Input**:
```json
{
    "method": "POST",
    "headers": {
        "origin": "https://app.example.com",
        "content-type": "application/json"
    }
}
```

**Result**: `allow == true` (request from allowed origin)

---

## 10. Request Body Validation

**Description**: Validates request body fields before allowing API access. Use set subtraction to detect unknown fields and explicit iteration to detect missing required fields.

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

**Example Input**:
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

**Testing**: Use `with input as` to inject body payloads. Test both the unknown-field case (set subtraction) and the missing-field case:

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

---

## 11. Response Filtering

**Description**: Filters response data based on user permissions, removing sensitive fields.

```rego
# METADATA
# title: Response Filtering
# description: Filters response data based on user permissions, removing sensitive fields
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

import data.users

# METADATA
# title: Allowed response fields
# description: Determines which fields can be included in the response based on user role
# entrypoint: true
# custom:
#   severity: MEDIUM
# Determine which fields can be included in response
allowed_response_fields contains field if {
    input.method == "GET"
    input.path = ["api", "users", user_id]

    # Public fields always allowed
    field in public_fields
}

allowed_response_fields contains field if {
    input.method == "GET"
    input.path = ["api", "users", user_id]

    # Private fields only for the user themselves
    user_id == input.user
    field in private_fields
}

allowed_response_fields contains field if {
    input.method == "GET"
    input.path = ["api", "users", user_id]

    # Admin fields only for admins
    users[input.user].role == "admin"
    field in admin_fields
}

public_fields := {"username", "display_name", "avatar"}
private_fields := {"email", "phone", "bio"}
admin_fields := {"created_at", "last_login", "ip_address", "status"}

# Generate filtered response
filtered_response := {field: value |
    some field, value in input.response
    field in allowed_response_fields
}
```

**Example Input**:
```json
{
    "method": "GET",
    "path": ["api", "users", "alice"],
    "user": "bob",
    "response": {
        "username": "alice",
        "email": "alice@example.com",
        "display_name": "Alice Smith",
        "created_at": "2023-01-01"
    }
}
```

**Result**: `filtered_response` contains only public fields (username, display_name)

---

## 12. Tenant Isolation in Multi-Tenant APIs

**Description**: Enforces tenant isolation to prevent cross-tenant data access in SaaS applications.

```rego
# METADATA
# title: Tenant Isolation
# description: Enforces tenant isolation to prevent cross-tenant data access in SaaS applications
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

import data.tenants

default allow := false

# METADATA
# title: Allow tenant-scoped requests
# description: Permits requests when the user belongs to the requested tenant
# entrypoint: true
# custom:
#   severity: HIGH
# Allow access if user belongs to the tenant
allow if {
    user_tenant_id := user_tenant[input.user]
    requested_tenant_id := extract_tenant_from_path
    user_tenant_id == requested_tenant_id
}

# Extract tenant ID from request path
extract_tenant_from_path := tenant_id if {
    input.path[0] == "tenants"
    tenant_id := input.path[1]
}

# Get user's tenant
user_tenant[user] := tenant_id if {
    some tenant_id, tenant in tenants
    user in tenant.users
}

# Platform admins can access any tenant
allow if {
    input.user in platform_admins
}

platform_admins := {"platform_admin", "support_admin"}
```

**Example Data** (loaded as `data.tenants`):
```json
{
    "tenant_a": {
        "users": ["alice", "bob"],
        "name": "Company A"
    },
    "tenant_b": {
        "users": ["charlie", "david"],
        "name": "Company B"
    }
}
```

**Example Input**:
```json
{
    "user": "alice",
    "path": ["tenants", "tenant_a", "resources", "123"]
}
```

**Result**: `allow == true` (alice belongs to tenant_a)

---

## 13. Time-Window Based Access (Business Hours Only)

**Description**: Restricts API access to specific time windows, such as business hours or maintenance windows.

```rego
# METADATA
# title: Time-Window Based Access
# description: Restricts API access to specific time windows such as business hours
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow time-restricted requests
# description: Permits requests during business hours and outside maintenance windows
# entrypoint: true
# custom:
#   severity: MEDIUM
# Allow access during business hours
allow if {
    is_business_hours
    not is_maintenance_window
}

# Allow admin access anytime
allow if {
    input.user in admins
}

# Check if current time is within business hours
is_business_hours if {
    [hour, minute, second] := time.clock(time.now_ns())
    hour >= 9
    hour < 17
}

# Check if current time is within maintenance window
is_maintenance_window if {
    [year, month, day] := time.date(time.now_ns())
    [hour, minute, second] := time.clock(time.now_ns())

    # Maintenance every Sunday 2-4 AM
    day_of_week := time.weekday(time.now_ns())
    day_of_week == "Sunday"
    hour >= 2
    hour < 4
}

admins := {"admin", "ops_team"}
```

**Example Input** (assuming current time is Monday 10:30 AM):
```json
{
    "user": "alice"
}
```

**Result**: `allow == true` (within business hours, not maintenance window)

---

## 14. IP Allowlist/Denylist

**Description**: Controls API access based on source IP addresses using allowlists and denylists.

```rego
# METADATA
# title: IP Allowlist/Denylist
# description: Controls API access based on source IP addresses using allowlists and denylists
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow IP-validated requests
# description: Permits requests from allowlisted IPs that are not on the denylist
# entrypoint: true
# custom:
#   severity: HIGH
# Allow if IP is in allowlist and not in denylist
allow if {
    ip_allowed
    not ip_denied
}

# Check if IP is in allowlist (using CIDR ranges)
ip_allowed if {
    some cidr in ip_allowlist
    net.cidr_contains(cidr, input.source_ip)
}

# Check if IP is explicitly denied
ip_denied if {
    input.source_ip in ip_denylist
}

# Internal network ranges
ip_allowlist := [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

# Known malicious IPs
ip_denylist := {
    "192.168.1.100",
    "10.0.0.50"
}

# Allow specific public IPs for partners
allow if {
    input.source_ip in partner_ips
    input.path[0] == "api"
    input.path[1] == "partner"
}

partner_ips := {
    "203.0.113.10",
    "198.51.100.20"
}
```

**Example Input**:
```json
{
    "source_ip": "10.0.0.25",
    "path": ["api", "internal", "resources"]
}
```

**Result**: `allow == true` (IP in allowlist and not denied)

---

## 15. User Agent Restrictions

**Description**: Restricts API access based on User-Agent headers to prevent scraping or enforce client requirements.

```rego
# METADATA
# title: User Agent Restrictions
# description: Restricts API access based on User-Agent headers to prevent scraping
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow approved user agent requests
# description: Permits requests from approved user agents and client applications
# entrypoint: true
# custom:
#   severity: MEDIUM
# Allow requests from approved user agents
allow if {
    user_agent := input.headers["user-agent"]
    is_approved_user_agent(user_agent)
}

# Check if user agent is approved
is_approved_user_agent(ua) if {
    # Official mobile app
    contains(ua, "MyApp-iOS")
}

is_approved_user_agent(ua) if {
    # Official Android app
    contains(ua, "MyApp-Android")
}

is_approved_user_agent(ua) if {
    # Web browser access
    some allowed in approved_browsers
    contains(ua, allowed)
}

# Block known bots and scrapers
deny contains "Bot/scraper not allowed" if {
    user_agent := input.headers["user-agent"]
    some blocked in blocked_patterns
    contains(lower(user_agent), blocked)
}

approved_browsers := {
    "Chrome",
    "Firefox",
    "Safari",
    "Edge"
}

blocked_patterns := {
    "bot",
    "crawler",
    "scraper",
    "spider"
}
```

**Example Input**:
```json
{
    "headers": {
        "user-agent": "MyApp-iOS/1.2.3 (iPhone; iOS 15.0)"
    }
}
```

**Result**: `allow == true` (approved mobile app)

---

## 16. Content-Type Validation

**Description**: Validates that requests have appropriate Content-Type headers for the endpoint.

```rego
# METADATA
# title: Content-Type Validation
# description: Validates that requests have appropriate Content-Type headers for the endpoint
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow content-type validated requests
# description: Permits requests with correct Content-Type headers for the target endpoint
# entrypoint: true
# custom:
#   severity: LOW
# Allow GET requests (no content-type required)
allow if {
    input.method == "GET"
}

# Allow POST/PUT with correct content type
allow if {
    input.method in {"POST", "PUT", "PATCH"}
    valid_content_type
}

# Validate content type for the endpoint
valid_content_type if {
    content_type := input.headers["content-type"]
    endpoint := concat("/", input.path)
    required := required_content_types[endpoint]
    startswith(content_type, required)
}

# Map endpoints to required content types
required_content_types := {
    "/api/users": "application/json",
    "/api/upload": "multipart/form-data",
    "/api/webhook": "application/json",
    "/api/import": "text/csv"
}

# Deny specific dangerous content types
deny contains "Dangerous content type" if {
    content_type := input.headers["content-type"]
    some dangerous in dangerous_content_types
    contains(content_type, dangerous)
}

dangerous_content_types := {
    "application/x-www-form-urlencoded",  # If not expected
    "text/html"  # Prevent XSS injection
}
```

**Example Input**:
```json
{
    "method": "POST",
    "path": ["api", "users"],
    "headers": {
        "content-type": "application/json; charset=utf-8"
    }
}
```

**Result**: `allow == true` (correct content-type for endpoint)

---

## 17. Query Parameter Validation

**Description**: Validates query parameters to prevent injection attacks and enforce business rules.

```rego
# METADATA
# title: Query Parameter Validation
# description: Validates query parameters to prevent injection attacks and enforce business rules
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow parameter-validated requests
# description: Permits requests with valid query parameters and no injection risk
# entrypoint: true
# custom:
#   severity: MEDIUM
# Allow requests with valid query parameters
allow if {
    valid_query_params
    not has_injection_risk
}

# Validate query parameters for the endpoint
valid_query_params if {
    endpoint := concat("/", input.path)
    endpoint == "/api/users"
    validate_users_query_params
}

# Validate parameters for /api/users endpoint
validate_users_query_params if {
    params := input.query_params

    # Limit parameter must be a reasonable number
    limit := to_number(params.limit)
    limit > 0
    limit <= 100

    # Offset must be non-negative
    offset := to_number(params.offset)
    offset >= 0

    # Sort field must be allowed
    params.sort in allowed_sort_fields
}

# Check for SQL injection patterns
has_injection_risk if {
    some param, value in input.query_params
    some pattern in injection_patterns
    contains(lower(value), pattern)
}

allowed_sort_fields := {
    "created_at",
    "username",
    "email"
}

injection_patterns := {
    "union select",
    "drop table",
    "--",
    "/*",
    "xp_",
    "exec"
}
```

**Example Input**:
```json
{
    "path": ["api", "users"],
    "query_params": {
        "limit": "50",
        "offset": "0",
        "sort": "username"
    }
}
```

**Result**: `allow == true` (valid query parameters)

---

## 18. HTTP Header Requirements

**Description**: Enforces required HTTP headers for security and tracking purposes.

```rego
# METADATA
# title: HTTP Header Requirements
# description: Enforces required HTTP headers for security and tracking purposes
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow header-validated requests
# description: Permits requests that include all required headers with valid values
# entrypoint: true
# custom:
#   severity: MEDIUM
# Allow requests with all required headers
allow if {
    has_required_headers
    valid_header_values
}

# Check if all required headers are present
has_required_headers if {
    every header in required_headers {
        input.headers[header]
    }
}

# Validate header values
valid_header_values if {
    # API version header
    api_version := input.headers["x-api-version"]
    api_version in supported_api_versions

    # Request ID for tracing
    request_id := input.headers["x-request-id"]
    count(request_id) > 0

    # Content Security Policy compliance
    not input.headers["x-frame-options"]
    not input.headers["x-xss-protection"]
}

# Security headers check
deny contains "Missing security headers" if {
    input.path[0] == "admin"
    some header in security_headers
    not input.headers[header]
}

required_headers := {
    "x-api-version",
    "x-request-id"
}

supported_api_versions := {"v1", "v2", "v3"}

security_headers := {
    "x-csrf-token",
    "authorization"
}
```

**Example Input**:
```json
{
    "path": ["api", "resources"],
    "headers": {
        "x-api-version": "v2",
        "x-request-id": "req-abc-123-xyz",
        "authorization": "Bearer token123"
    }
}
```

**Result**: `allow == true` (all required headers present and valid)

---

## 19. Comprehensive Multi-Factor Authorization

**Description**: Combines multiple authorization factors including user identity, JWT validation, role permissions, IP restrictions, and time constraints.

```rego
# METADATA
# title: Comprehensive Multi-Factor Authorization
# description: Combines multiple authorization factors including identity, JWT, roles, IP, and time
# authors:
# - API Security Team <api-security@example.com>
# custom:
#   category: http-authorization
package httpapi.authz

import rego.v1

default allow := false

# METADATA
# title: Allow multi-factor authorized requests
# description: Permits requests that pass authentication, authorization, and blocking checks
# entrypoint: true
# custom:
#   severity: HIGH
# Main authorization decision combining multiple factors
allow if {
    authenticated
    authorized
    not blocked
}

# Authentication: Valid JWT token
authenticated if {
    token_valid
    token_not_expired
    token_signature_valid
}

token_valid if {
    [header, payload, signature] := io.jwt.decode(input.token)
    payload.iss == "https://auth.example.com"
    payload.aud == "api.example.com"
}

token_not_expired if {
    [_, payload, _] := io.jwt.decode(input.token)
    payload.exp > time.now_ns() / 1000000000
}

token_signature_valid if {
    # In production, verify signature with public key
    io.jwt.verify_rs256(input.token, input.public_key)
}

# Authorization: Role-based and attribute-based checks
authorized if {
    has_required_role
    has_path_permission
    within_rate_limit
}

has_required_role if {
    [_, payload, _] := io.jwt.decode(input.token)
    required_role := endpoint_roles[concat("/", input.path)]
    required_role in payload.roles
}

has_path_permission if {
    [_, payload, _] := io.jwt.decode(input.token)
    user_level := payload.level
    endpoint_level := endpoint_levels[concat("/", input.path)]
    user_level >= endpoint_level
}

within_rate_limit if {
    import data.rate_limits
    [_, payload, _] := io.jwt.decode(input.token)
    user_id := payload.sub
    current_requests := rate_limits[user_id]
    current_requests < 1000
}

# Blocking conditions
blocked if {
    ip_blocked
}

blocked if {
    outside_business_hours
    not emergency_access
}

ip_blocked if {
    some blocked_ip in blocked_ips
    input.source_ip == blocked_ip
}

outside_business_hours if {
    [hour, _, _] := time.clock(time.now_ns())
    hour < 9
    hour >= 18
}

emergency_access if {
    [_, payload, _] := io.jwt.decode(input.token)
    "emergency" in payload.roles
}

# Configuration data
endpoint_roles := {
    "/api/users": "user",
    "/api/admin": "admin",
    "/api/reports": "analyst"
}

endpoint_levels := {
    "/api/users": 1,
    "/api/admin": 5,
    "/api/reports": 3
}

blocked_ips := {
    "192.168.1.100",
    "10.0.0.50"
}
```

**Example Input**:
```json
{
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJleHAiOjk5OTk5OTk5OTksInN1YiI6InVzZXIxMjMiLCJyb2xlcyI6WyJ1c2VyIiwiYW5hbHlzdCJdLCJsZXZlbCI6M30...",
    "path": ["api", "reports"],
    "source_ip": "10.0.1.50",
    "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**Result**: `allow == true` (all authorization factors satisfied)

---

## Best Practices

### 1. Default Deny
Always use `default allow := false` to ensure that access is denied unless explicitly permitted.

### 2. Layered Security
Combine multiple authorization factors (authentication, roles, attributes, time, location) for defense in depth.

### 3. Token Validation
Always validate token signatures, expiration times, issuers, and audiences when using JWT or OAuth2 tokens.

### 4. Rate Limiting
Implement rate limiting at multiple levels (user, IP, API key) to prevent abuse.

### 5. Audit Logging
While not shown in these examples, production systems should log all authorization decisions for security auditing.

### 6. Input Validation
Always validate and sanitize inputs to prevent injection attacks and ensure data integrity.

### 7. Separation of Concerns
Keep authentication (verifying identity) separate from authorization (verifying permissions).

### 8. Fail Securely
Ensure that errors or undefined values result in denied access, not granted access.

### 9. Test Thoroughly
Write comprehensive tests for all authorization rules, including edge cases and attack scenarios.

### 10. Performance Optimization
Cache frequently accessed data and use efficient algorithms for pattern matching and collection operations.

---

## Common Input Structure

Most HTTP API authorization policies expect input in the following structure:

```json
{
    "user": "alice",
    "method": "GET",
    "path": ["api", "v1", "resources", "123"],
    "headers": {
        "authorization": "Bearer token...",
        "content-type": "application/json",
        "user-agent": "MyApp/1.0"
    },
    "query_params": {
        "limit": "10",
        "offset": "0"
    },
    "body": {},
    "source_ip": "192.168.1.50",
    "token": "eyJhbGci...",
    "timestamp": 1234567890
}
```

---

## Integration Patterns

### REST API Integration
```python
# Python example
import requests

input_dict = {
    "input": {
        "user": request.user,
        "method": request.method,
        "path": request.path.strip("/").split("/"),
        "headers": dict(request.headers),
        "source_ip": request.remote_addr
    }
}

response = requests.post(
    "http://opa:8181/v1/data/httpapi/authz",
    json=input_dict
)

if response.json().get("result", {}).get("allow"):
    # Request authorized
    pass
else:
    # Request denied
    return 403
```

### Middleware Integration
Most modern web frameworks support middleware that can integrate with OPA for authorization decisions before request handlers execute.

---

## Summary

HTTP API authorization with Rego provides:
- Fine-grained access control based on multiple factors
- Context-aware decision making using request metadata
- Flexible policy models supporting RBAC, ABAC, and custom logic
- Token-based authentication with JWT, OAuth2, and API keys
- Security controls including rate limiting, IP filtering, and input validation
- Multi-tenant isolation and data protection
- Time-based and location-based access controls

These patterns can be combined and extended to meet the specific security requirements of any HTTP API or microservices architecture.
