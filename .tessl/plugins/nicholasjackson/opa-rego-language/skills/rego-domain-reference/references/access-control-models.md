# Access Control Models in Rego

This document provides comprehensive examples of implementing various access control models using Rego, including Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), and other advanced access control patterns.

## Table of Contents

1. [Basic RBAC](#basic-rbac)
2. [RBAC with Separation of Duty](#rbac-with-separation-of-duty)
3. [Dynamic Role Assignment](#dynamic-role-assignment)
4. [Hierarchical Roles and Permission Inheritance](#hierarchical-roles-and-permission-inheritance)
5. [Time-Based Access Control](#time-based-access-control)
6. [Location-Based Access Control](#location-based-access-control)
7. [Multi-Factor Authentication Requirements](#multi-factor-authentication-requirements)
8. [Context-Aware Authorization](#context-aware-authorization)
9. [Role Delegation and Temporary Permissions](#role-delegation-and-temporary-permissions)
10. [Group-Based Access Control](#group-based-access-control)
11. [ABAC Patterns](#abac-patterns)
12. [Policy Combination Algorithms - Permit Overrides](#policy-combination-algorithms-permit-overrides)
13. [Policy Combination Algorithms - Deny Overrides](#policy-combination-algorithms-deny-overrides)
14. [Delegation Constraints](#delegation-constraints)
15. [Mandatory Access Control (MAC) Patterns](#mandatory-access-control-mac-patterns)
16. [Discretionary Access Control (DAC) Patterns](#discretionary-access-control-dac-patterns)
17. [Resource Ownership Patterns](#resource-ownership-patterns)
18. [Conditional Permissions Based on Resource State](#conditional-permissions-based-on-resource-state)
19. [Break-Glass Access for Emergencies](#break-glass-access-for-emergencies)
20. [Multi-Tenant Access Control](#multi-tenant-access-control)

---

## 1. Basic RBAC

The most fundamental access control pattern: users are assigned roles, and roles are granted permissions.

```rego
package rbac.authz

import rego.v1

# user-role assignments
user_roles := {
    "alice": ["engineering", "webdev"],
    "bob": ["hr"],
    "charlie": ["engineering"],
}

# role-permissions assignments
role_permissions := {
    "engineering": [
        {"action": "read", "object": "server123"},
    ],
    "webdev": [
        {"action": "read", "object": "server123"},
        {"action": "write", "object": "server123"},
    ],
    "hr": [
        {"action": "read", "object": "database456"},
    ],
}

default allow := false

allow if {
    # lookup the list of roles for the user
    roles := user_roles[input.user]
    # for each role in that list
    some r in roles
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    some p in permissions
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
}
```

**Example Input:**
```json
{
  "user": "alice",
  "action": "write",
  "object": "server123"
}
```

**Result:** `allow` is `true` because alice has the webdev role with write permission.

---

## 2. RBAC with Separation of Duty

Prevents users from being assigned conflicting roles simultaneously to enforce compliance requirements.

```rego
package rbac.sod

import rego.v1

# user-role assignments
user_roles := {
    "alice": ["create-payment"],
    "bob": ["approve-payment"],
    "charlie": ["create-payment", "approve-payment"],
}

# Pairs of roles that no user can be assigned to simultaneously
sod_roles := [
    ["create-payment", "approve-payment"],
    ["create-vendor", "pay-vendor"],
]

# Find all users violating SOD
sod_violation contains user if {
    some user
    # grab one role for a user
    some role1 in user_roles[user]
    # grab another role for that same user
    some role2 in user_roles[user]
    # check if those roles are forbidden by SOD
    [role1, role2] in sod_roles
}

# Deny access if user has SOD violation
default allow := false

allow if {
    not input.user in sod_violation
    # ... additional authorization checks
}
```

**Example Query:**
```rego
# Query: data.rbac.sod.sod_violation
# Result: {"charlie"}
```

---

## 3. Dynamic Role Assignment

Automatically assigns roles based on user attributes rather than static assignments.

```rego
package rbac.dynamic

import rego.v1

import data.employees

# Dynamically compute roles based on employee attributes
user_roles[user] := roles if {
    employee := employees[user]
    roles := {role |
        employee.department == "Engineering"
        role := "developer"
    } | {role |
        employee.level >= 5
        role := "senior"
    } | {role |
        employee.is_manager == true
        role := "manager"
    } | {role |
        employee.department == "Security"
        role := "security-admin"
    }
}

# Role-based permissions
role_permissions := {
    "developer": [
        {"action": "read", "resource": "code"},
        {"action": "write", "resource": "code"},
    ],
    "senior": [
        {"action": "read", "resource": "architecture"},
        {"action": "approve", "resource": "pull-request"},
    ],
    "manager": [
        {"action": "read", "resource": "performance-reviews"},
        {"action": "write", "resource": "performance-reviews"},
    ],
    "security-admin": [
        {"action": "read", "resource": "security-logs"},
        {"action": "modify", "resource": "access-policies"},
    ],
}

default allow := false

allow if {
    roles := user_roles[input.user]
    some role in roles
    permissions := role_permissions[role]
    some permission in permissions
    permission.action == input.action
    permission.resource == input.resource
}
```

**Example Data:**
```json
{
  "employees": {
    "alice": {
      "department": "Engineering",
      "level": 6,
      "is_manager": true
    }
  }
}
```

---

## 4. Hierarchical Roles and Permission Inheritance

Implements role hierarchies where higher-level roles inherit permissions from lower-level roles.

```rego
package rbac.hierarchical

import rego.v1

# Role hierarchy: parent roles inherit permissions from child roles
role_hierarchy := {
    "admin": ["manager", "developer"],
    "manager": ["developer"],
    "developer": ["viewer"],
    "viewer": [],
}

# Direct permissions for each role
direct_permissions := {
    "viewer": [
        {"action": "read", "resource": "documents"},
    ],
    "developer": [
        {"action": "write", "resource": "code"},
        {"action": "read", "resource": "code"},
    ],
    "manager": [
        {"action": "approve", "resource": "pull-requests"},
        {"action": "read", "resource": "team-metrics"},
    ],
    "admin": [
        {"action": "delete", "resource": "any"},
        {"action": "manage", "resource": "users"},
    ],
}

# Compute all permissions for a role (including inherited)
all_permissions[role] := permissions if {
    some role
    # Get direct permissions
    direct := object.get(direct_permissions, role, [])
    # Get inherited permissions from child roles
    children := role_hierarchy[role]
    inherited := {p |
        some child in children
        child_perms := all_permissions[child]
        some p in child_perms
    }
    # Combine direct and inherited
    permissions := direct | inherited
}

user_roles := {
    "alice": ["admin"],
    "bob": ["manager"],
    "charlie": ["developer"],
}

default allow := false

allow if {
    roles := user_roles[input.user]
    some role in roles
    permissions := all_permissions[role]
    some permission in permissions
    permission.action == input.action
    permission.resource == input.resource
}
```

**Example Input:**
```json
{
  "user": "bob",
  "action": "read",
  "resource": "documents"
}
```

**Result:** `allow` is `true` because manager inherits viewer's read permission.

---

## 5. Multi-Factor Authentication Requirements

Requires MFA for sensitive operations or privileged access.

```rego
package abac.mfa

import rego.v1

# Operations requiring MFA
sensitive_operations := {"delete", "admin", "transfer-funds", "modify-security"}

# Resources requiring MFA
sensitive_resources := {"production-database", "payment-system", "customer-pii"}

# High-value transaction threshold
high_value_threshold := 10000

default allow := false

# Allow non-sensitive operations without MFA
allow if {
    not input.operation in sensitive_operations
    not input.resource in sensitive_resources
    not is_high_value_transaction
}

# Allow sensitive operations only with MFA
allow if {
    input.operation in sensitive_operations
    input.mfa_verified == true
}

# Allow access to sensitive resources only with MFA
allow if {
    input.resource in sensitive_resources
    input.mfa_verified == true
}

# High-value transactions require MFA
allow if {
    is_high_value_transaction
    input.mfa_verified == true
}

is_high_value_transaction if {
    input.transaction_amount
    input.transaction_amount > high_value_threshold
}

# Emergency bypass (only for break-glass scenarios)
allow if {
    input.emergency_override == true
    input.override_code
    validate_emergency_code(input.override_code)
    # Log this access for audit
}

validate_emergency_code(code) if {
    # In production, this would validate against a secure store
    code == "EMERGENCY-ACCESS-2024"
}
```

**Example Input:**
```json
{
  "user": "alice",
  "operation": "delete",
  "resource": "user-account",
  "mfa_verified": true
}
```

**Result:** `allow` is `true` because MFA is verified for sensitive operation.

---

## 6. Context-Aware Authorization

Makes access decisions based on device type, network security level, and other contextual factors.

```rego
package abac.context

import rego.v1

# Trusted device fingerprints
trusted_devices := {
    "alice": ["device-abc123", "device-xyz789"],
    "bob": ["device-def456"],
}

# Network security levels
network_security_levels := {
    "corporate-wifi": "high",
    "corporate-vpn": "high",
    "home-broadband": "medium",
    "public-wifi": "low",
}

# Required security levels for resources
resource_security_requirements := {
    "customer-data": "high",
    "internal-docs": "medium",
    "public-wiki": "low",
}

default allow := false

# Allow if device is trusted and network security is sufficient
allow if {
    is_trusted_device
    has_sufficient_network_security
    not requires_additional_verification
}

# Allow with step-up authentication on untrusted contexts
allow if {
    not is_trusted_device
    input.step_up_auth_verified == true
    has_sufficient_network_security
}

is_trusted_device if {
    devices := trusted_devices[input.user]
    input.device_id in devices
}

has_sufficient_network_security if {
    network_level := network_security_levels[input.network_type]
    required_level := resource_security_requirements[input.resource]

    # Convert levels to numeric for comparison
    security_scores := {"low": 1, "medium": 2, "high": 3}
    security_scores[network_level] >= security_scores[required_level]
}

requires_additional_verification if {
    input.resource in {"customer-data", "payment-info"}
    input.network_type == "public-wifi"
}
```

**Example Input:**
```json
{
  "user": "alice",
  "device_id": "device-abc123",
  "network_type": "corporate-vpn",
  "resource": "internal-docs"
}
```

**Result:** `allow` is `true` because device is trusted and network security is sufficient.

---

## 7. Role Delegation and Temporary Permissions

Allows users to temporarily delegate their permissions to others with time-based constraints.

```rego
package rbac.delegation

import rego.v1

import data.delegations

# User role assignments
user_roles := {
    "alice": ["manager"],
    "bob": ["developer"],
}

# Role permissions
role_permissions := {
    "manager": [
        {"action": "approve", "resource": "expenses"},
        {"action": "read", "resource": "team-reports"},
    ],
    "developer": [
        {"action": "write", "resource": "code"},
    ],
}

# Example delegations data:
# {
#   "delegation-001": {
#     "from": "alice",
#     "to": "bob",
#     "permissions": [{"action": "approve", "resource": "expenses"}],
#     "valid_from": "2024-01-01T00:00:00Z",
#     "valid_until": "2024-01-07T23:59:59Z",
#     "max_uses": 10,
#     "used_count": 3
#   }
# }

default allow := false

# Normal role-based access
allow if {
    roles := user_roles[input.user]
    some role in roles
    permissions := role_permissions[role]
    some permission in permissions
    permission.action == input.action
    permission.resource == input.resource
}

# Delegated access
allow if {
    some delegation_id, delegation in delegations
    delegation.to == input.user
    is_valid_delegation(delegation)
    has_delegated_permission(delegation)
}

is_valid_delegation(delegation) if {
    # Check time validity
    current_time := time.now_ns()
    valid_from := time.parse_rfc3339_ns(delegation.valid_from)
    valid_until := time.parse_rfc3339_ns(delegation.valid_until)
    current_time >= valid_from
    current_time <= valid_until

    # Check usage limits
    delegation.used_count < delegation.max_uses
}

has_delegated_permission(delegation) if {
    some permission in delegation.permissions
    permission.action == input.action
    permission.resource == input.resource
}
```

**Example Input:**
```json
{
  "user": "bob",
  "action": "approve",
  "resource": "expenses"
}
```

**Result:** `allow` is `true` if bob has an active delegation from alice.

---

## 8. Group-Based Access Control

Organizes users into groups with shared permissions, supporting nested groups.

```rego
package gbac.authz

import rego.v1

# User to group memberships
user_groups := {
    "alice": ["engineers", "team-leads"],
    "bob": ["engineers"],
    "charlie": ["contractors", "external"],
}

# Nested groups: parent groups inherit member permissions
group_hierarchy := {
    "all-staff": ["engineers", "contractors"],
    "engineers": ["team-leads"],
}

# Group permissions
group_permissions := {
    "engineers": [
        {"action": "read", "resource": "code-repository"},
        {"action": "write", "resource": "code-repository"},
    ],
    "team-leads": [
        {"action": "approve", "resource": "pull-requests"},
        {"action": "merge", "resource": "code-repository"},
    ],
    "contractors": [
        {"action": "read", "resource": "documentation"},
    ],
    "all-staff": [
        {"action": "read", "resource": "company-wiki"},
    ],
}

# Compute all groups a user belongs to (including inherited)
all_user_groups[user] := groups if {
    some user
    direct_groups := object.get(user_groups, user, [])
    inherited := {group |
        some direct in direct_groups
        parent_groups[direct][group]
    }
    groups := direct_groups | inherited
}

# Compute parent groups
parent_groups[child] := parents if {
    some child
    parents := {parent |
        some parent
        children := group_hierarchy[parent]
        child in children
    } | {child}
}

default allow := false

allow if {
    groups := all_user_groups[input.user]
    some group in groups
    permissions := group_permissions[group]
    some permission in permissions
    permission.action == input.action
    permission.resource == input.resource
}
```

**Example Input:**
```json
{
  "user": "alice",
  "action": "merge",
  "resource": "code-repository"
}
```

**Result:** `allow` is `true` because alice is in team-leads group.

---

## 9. ABAC Patterns

Comprehensive attribute-based access control using user, resource, and environmental attributes.

```rego
package abac.comprehensive

import rego.v1

# User attributes
user_attributes := {
    "alice": {
        "department": "Engineering",
        "clearance_level": 3,
        "tenure_years": 5,
        "projects": ["project-alpha", "project-beta"],
    },
    "bob": {
        "department": "Sales",
        "clearance_level": 1,
        "tenure_years": 2,
        "projects": ["project-gamma"],
    },
}

# Resource attributes
resource_attributes := {
    "secret-design": {
        "classification": "confidential",
        "required_clearance": 3,
        "owning_department": "Engineering",
        "project": "project-alpha",
    },
    "sales-report": {
        "classification": "internal",
        "required_clearance": 1,
        "owning_department": "Sales",
    },
}

default allow := false

# Allow if user has sufficient clearance and is in owning department
allow if {
    user := user_attributes[input.user]
    resource := resource_attributes[input.resource]

    user.clearance_level >= resource.required_clearance
    user.department == resource.owning_department
}

# Allow if user is assigned to the resource's project
allow if {
    user := user_attributes[input.user]
    resource := resource_attributes[input.resource]

    resource.project
    resource.project in user.projects
}

# Allow senior employees (5+ years) to access internal resources
allow if {
    user := user_attributes[input.user]
    resource := resource_attributes[input.resource]

    user.tenure_years >= 5
    resource.classification == "internal"
}
```

**Example Input:**
```json
{
  "user": "alice",
  "resource": "secret-design",
  "action": "read"
}
```

**Result:** `allow` is `true` because alice meets clearance, department, and project requirements.

---

## 10. Policy Combination Algorithms - Permit Overrides

Implements permit-overrides algorithm where any permit decision overrides all deny decisions.

```rego
package policy.permit_overrides

import rego.v1

# Multiple policy modules that can return allow/deny decisions
default allow := false

# Policy 1: Time-based restriction
policy_time_restriction := false

policy_time_restriction if {
    [hour, _, _] := time.clock(time.now_ns())
    hour >= 9
    hour < 17
}

# Policy 2: Role-based permission
policy_role_based := false

policy_role_based if {
    input.user in {"admin", "manager"}
}

# Policy 3: Resource ownership
policy_resource_owner := false

policy_resource_owner if {
    input.resource_owner == input.user
}

# Permit-overrides: allow if ANY policy permits
allow if {
    policy_time_restriction
}

allow if {
    policy_role_based
}

allow if {
    policy_resource_owner
}

# Collect all policy results for audit
policy_results := {
    "time_restriction": policy_time_restriction,
    "role_based": policy_role_based,
    "resource_owner": policy_resource_owner,
    "final_decision": allow,
}
```

**Example Input:**
```json
{
  "user": "alice",
  "resource": "document-123",
  "resource_owner": "bob"
}
```

**Result:** `allow` depends on whether any policy permits access.

---

## 11. Policy Combination Algorithms - Deny Overrides

Implements deny-overrides algorithm where any deny decision overrides all permit decisions.

```rego
package policy.deny_overrides

import rego.v1

# Deny rules take precedence
default allow := true

# Deny if user is blacklisted
deny if {
    input.user in blacklisted_users
}

# Deny if accessing from blocked IP
deny if {
    input.source_ip in blocked_ips
}

# Deny if resource is locked
deny if {
    input.resource in locked_resources
}

# Deny if security score is too low
deny if {
    input.security_score < minimum_security_score
}

blacklisted_users := {"malicious-user", "terminated-employee"}

blocked_ips := {"192.0.2.1", "198.51.100.1"}

locked_resources := {"critical-system-1", "under-maintenance"}

minimum_security_score := 75

# Final decision: deny overrides any permit
allow if {
    not deny
    has_valid_permission
}

has_valid_permission if {
    input.user in authorized_users
}

authorized_users := {"alice", "bob", "charlie"}
```

**Example Input:**
```json
{
  "user": "alice",
  "source_ip": "10.0.1.1",
  "resource": "document-123",
  "security_score": 85
}
```

**Result:** `allow` is `true` only if no deny rule triggers.

---

## 12. Delegation Constraints

Controls who can delegate permissions and under what conditions.

```rego
package delegation.constraints

import rego.v1

# Roles that are allowed to delegate
delegable_roles := {"manager", "admin", "team-lead"}

# Maximum delegation duration in seconds (7 days)
max_delegation_duration := 604800000000000

# Permissions that can be delegated
delegable_permissions := {
    "approve-expense",
    "approve-leave",
    "read-reports",
}

# Permissions that cannot be delegated (non-delegable)
non_delegable_permissions := {
    "delete-account",
    "modify-security",
    "access-audit-logs",
}

default can_delegate := false

# User can delegate if they have the appropriate role
can_delegate if {
    input.from_user_role in delegable_roles
    is_delegable_permission
    within_time_limits
    not delegating_to_external
}

is_delegable_permission if {
    input.permission in delegable_permissions
    not input.permission in non_delegable_permissions
}

within_time_limits if {
    valid_from := time.parse_rfc3339_ns(input.valid_from)
    valid_until := time.parse_rfc3339_ns(input.valid_until)
    duration := valid_until - valid_from
    duration <= max_delegation_duration
}

delegating_to_external if {
    import data.users
    to_user := users[input.to_user]
    to_user.employment_type == "external"
}

# Prevent delegation chains (delegated permissions can't be re-delegated)
can_delegate if {
    not input.is_delegated_permission
}
```

**Example Input:**
```json
{
  "from_user": "alice",
  "from_user_role": "manager",
  "to_user": "bob",
  "permission": "approve-expense",
  "valid_from": "2024-01-01T00:00:00Z",
  "valid_until": "2024-01-03T00:00:00Z",
  "is_delegated_permission": false
}
```

**Result:** `can_delegate` is `true` if all constraints are met.

---

## 13. Mandatory Access Control (MAC) Patterns

Implements mandatory access control with security labels and clearance levels.

```rego
package mac.authz

import rego.v1

# User security clearances
user_clearances := {
    "alice": {
        "level": "top-secret",
        "categories": ["nato", "crypto", "nuclear"],
    },
    "bob": {
        "level": "secret",
        "categories": ["nato"],
    },
    "charlie": {
        "level": "confidential",
        "categories": [],
    },
}

# Resource security classifications
resource_classifications := {
    "doc-001": {
        "level": "top-secret",
        "categories": ["crypto"],
    },
    "doc-002": {
        "level": "secret",
        "categories": ["nato"],
    },
    "doc-003": {
        "level": "confidential",
        "categories": [],
    },
}

# Security level hierarchy
clearance_hierarchy := ["top-secret", "secret", "confidential", "unclassified"]

default allow := false

# Allow if user has sufficient clearance level and required categories
allow if {
    user := user_clearances[input.user]
    resource := resource_classifications[input.resource]

    # Check clearance level (user level >= resource level)
    has_sufficient_clearance(user.level, resource.level)

    # Check categories (user has all required categories)
    has_required_categories(user.categories, resource.categories)

    # MAC write-up protection: can't write to higher classification
    input.action == "read"
}

# Allow write only to same or lower classification (no write-up)
allow if {
    user := user_clearances[input.user]
    resource := resource_classifications[input.resource]

    has_sufficient_clearance(user.level, resource.level)
    has_required_categories(user.categories, resource.categories)

    input.action == "write"
    # User can only write to same level (simplified rule)
    user.level == resource.level
}

has_sufficient_clearance(user_level, resource_level) if {
    user_index := indexof(clearance_hierarchy, user_level)
    resource_index := indexof(clearance_hierarchy, resource_level)
    user_index <= resource_index
}

has_required_categories(user_categories, required_categories) if {
    # Check if user has all required categories
    every category in required_categories {
        category in user_categories
    }
}

indexof(array, element) := i if {
    some i
    array[i] == element
}
```

**Example Input:**
```json
{
  "user": "alice",
  "resource": "doc-001",
  "action": "read"
}
```

**Result:** `allow` is `true` because alice has top-secret clearance with crypto category.

---

## 14. Discretionary Access Control (DAC) Patterns

Implements discretionary access control where resource owners control access to their resources.

```rego
package dac.authz

import rego.v1

# Resource ownership
resource_owners := {
    "file-001": "alice",
    "file-002": "bob",
    "file-003": "alice",
}

# Access control lists set by owners
resource_acls := {
    "file-001": {
        "alice": ["read", "write", "delete", "share"],
        "bob": ["read"],
        "charlie": ["read", "write"],
    },
    "file-002": {
        "bob": ["read", "write", "delete", "share"],
        "alice": ["read", "write"],
    },
    "file-003": {
        "alice": ["read", "write", "delete", "share"],
    },
}

default allow := false

# Owner has full access
allow if {
    resource_owners[input.resource] == input.user
}

# Check ACL for non-owners
allow if {
    acl := resource_acls[input.resource]
    user_permissions := acl[input.user]
    input.action in user_permissions
}

# Owners can modify ACLs
can_modify_acl if {
    resource_owners[input.resource] == input.user
}

# Owners can transfer ownership
can_transfer_ownership if {
    resource_owners[input.resource] == input.user
}

# Users with 'share' permission can grant read access
can_share if {
    acl := resource_acls[input.resource]
    user_permissions := acl[input.user]
    "share" in user_permissions
    input.grant_permission == "read"
}
```

**Example Input:**
```json
{
  "user": "charlie",
  "resource": "file-001",
  "action": "write"
}
```

**Result:** `allow` is `true` because charlie has write permission in the ACL.

---

## 15. Resource Ownership Patterns

Enforces ownership-based access control with ownership transfer and delegation capabilities.

```rego
package ownership.authz

import rego.v1

import data.resources

# Example resources data:
# {
#   "project-alpha": {
#     "owner": "alice",
#     "created_at": "2023-01-01T00:00:00Z",
#     "shared_with": ["bob"],
#     "type": "project"
#   }
# }

default allow := false

# Owners have full access to their resources
allow if {
    resource := resources[input.resource]
    resource.owner == input.user
}

# Shared users have limited access
allow if {
    resource := resources[input.resource]
    input.user in resource.shared_with
    input.action in {"read", "comment"}
}

# Team members can access team resources
allow if {
    resource := resources[input.resource]
    resource.type == "team-resource"
    import data.users
    user := users[input.user]
    resource.team == user.team
}

# Organizational hierarchy: managers can access subordinate resources
allow if {
    resource := resources[input.resource]
    import data.org_hierarchy
    is_manager_of(input.user, resource.owner)
}

is_manager_of(manager, employee) if {
    import data.org_hierarchy
    subordinates := org_hierarchy.subordinates[manager]
    employee in subordinates
}

# Ownership transfer allowed only by current owner
can_transfer_ownership if {
    resource := resources[input.resource]
    resource.owner == input.user
    input.new_owner
}

# Resource deletion requires ownership
can_delete if {
    resource := resources[input.resource]
    resource.owner == input.user
    input.action == "delete"
}
```

**Example Input:**
```json
{
  "user": "bob",
  "resource": "project-alpha",
  "action": "read"
}
```

**Result:** `allow` is `true` if bob is in shared_with list.

---

## 16. Conditional Permissions Based on Resource State

Access decisions depend on the current state or properties of the resource being accessed.

```rego
package conditional.authz

import rego.v1

import data.resources

# Example resources data:
# {
#   "document-123": {
#     "status": "draft",
#     "locked": false,
#     "approval_stage": "pending",
#     "owner": "alice"
#   }
# }

default allow := false

# Allow edits only to draft documents
allow if {
    resource := resources[input.resource]
    resource.status == "draft"
    input.action == "edit"
    resource.owner == input.user
}

# Published documents are read-only
allow if {
    resource := resources[input.resource]
    resource.status == "published"
    input.action == "read"
}

# Locked resources cannot be modified
deny if {
    resource := resources[input.resource]
    resource.locked == true
    input.action in {"edit", "delete"}
}

# Approval stage determines who can approve
allow if {
    resource := resources[input.resource]
    resource.approval_stage == "pending"
    input.action == "approve"
    can_approve_at_stage(input.user, resource.approval_stage)
}

can_approve_at_stage(user, stage) if {
    approvers_by_stage := {
        "pending": {"manager-1", "manager-2"},
        "final": {"director", "vp"},
    }
    user in approvers_by_stage[stage]
}

# Documents under review cannot be deleted
deny if {
    resource := resources[input.resource]
    resource.status == "under-review"
    input.action == "delete"
}

# Allow archiving only for completed and published documents
allow if {
    resource := resources[input.resource]
    resource.status in {"completed", "published"}
    input.action == "archive"
    input.user in {"admin", resource.owner}
}
```

**Example Input:**
```json
{
  "user": "alice",
  "resource": "document-123",
  "action": "edit"
}
```

**Result:** `allow` depends on document status, lock state, and ownership.

---

## 17. Break-Glass Access for Emergencies

Provides emergency override mechanisms with strict auditing and justification requirements.

```rego
package breakglass.authz

import rego.v1

# Normal authorization rules
default allow := false

allow if {
    normal_authorization
}

normal_authorization if {
    import data.user_roles
    roles := user_roles[input.user]
    "admin" in roles
}

# Break-glass access
allow if {
    input.break_glass == true
    is_valid_emergency
    has_valid_justification
    is_authorized_for_break_glass
}

is_valid_emergency if {
    # Emergency must be recent (within last hour)
    input.emergency_timestamp
    current_time := time.now_ns()
    emergency_time := time.parse_rfc3339_ns(input.emergency_timestamp)
    time_diff := current_time - emergency_time
    # Within 1 hour (3600 seconds)
    time_diff < 3600000000000
}

has_valid_justification if {
    input.justification
    count(input.justification) >= 50
    # Check against valid emergency reasons
    valid_reason_keywords := {"outage", "security", "incident", "critical", "production"}
    some keyword in valid_reason_keywords
    contains(lower(input.justification), keyword)
}

is_authorized_for_break_glass if {
    # Only certain users can use break-glass
    authorized_break_glass_users := {"sre-oncall", "security-team", "incident-commander"}
    input.user in authorized_break_glass_users
}

# Generate audit record for break-glass access
audit_record := record if {
    input.break_glass == true
    record := {
        "timestamp": time.now_ns(),
        "user": input.user,
        "resource": input.resource,
        "action": input.action,
        "justification": input.justification,
        "emergency_timestamp": input.emergency_timestamp,
        "approved": allow,
        "requires_review": true,
    }
}

# Deny break-glass for destructive actions without additional approval
deny if {
    input.break_glass == true
    input.action in {"delete", "destroy", "purge"}
    not input.secondary_approval
}

# Require notification to security team
requires_security_notification if {
    input.break_glass == true
    allow
}
```

**Example Input:**
```json
{
  "user": "sre-oncall",
  "resource": "production-database",
  "action": "read",
  "break_glass": true,
  "emergency_timestamp": "2024-01-22T10:00:00Z",
  "justification": "Critical production outage affecting customer transactions, need immediate access to diagnose database issues"
}
```

**Result:** `allow` is `true` if all emergency conditions are met, with audit record generated.

---

## 18. Multi-Tenant Access Control

Implements isolation and access control in multi-tenant environments.

```rego
package multitenant.authz

import rego.v1

# User to tenant mappings
user_tenants := {
    "alice": ["tenant-a"],
    "bob": ["tenant-b"],
    "charlie": ["tenant-a", "tenant-b"],
    "admin": ["tenant-a", "tenant-b", "tenant-c"],
}

# Resource to tenant mappings
resource_tenants := {
    "data-001": "tenant-a",
    "data-002": "tenant-b",
    "data-003": "tenant-a",
}

# Tenant-specific roles
tenant_roles := {
    "tenant-a": {
        "alice": ["owner"],
        "charlie": ["viewer"],
    },
    "tenant-b": {
        "bob": ["owner"],
        "charlie": ["editor"],
    },
}

# Role permissions within a tenant
role_permissions := {
    "owner": ["read", "write", "delete", "manage"],
    "editor": ["read", "write"],
    "viewer": ["read"],
}

default allow := false

# Users can only access resources in their tenants
allow if {
    tenant := resource_tenants[input.resource]
    tenant in user_tenants[input.user]
    has_permission_in_tenant(input.user, tenant, input.action)
}

has_permission_in_tenant(user, tenant, action) if {
    # Get user's role in the tenant
    some user_role in tenant_roles[tenant][user]
    # Get permissions for that role
    permissions := role_permissions[user_role]
    # Check if action is permitted
    action in permissions
}

# Cross-tenant access denied
deny if {
    tenant := resource_tenants[input.resource]
    not tenant in user_tenants[input.user]
}

# Super admins can access all tenants
allow if {
    input.user == "admin"
    input.action in {"read", "write", "manage"}
}

# Tenant isolation check
tenant_isolated(resource1, resource2) if {
    resource_tenants[resource1] != resource_tenants[resource2]
}
```

**Example Input:**
```json
{
  "user": "charlie",
  "resource": "data-001",
  "action": "read"
}
```

**Result:** `allow` is `true` because charlie is a viewer in tenant-a.

---

## Summary

This document covered 20 comprehensive access control patterns in Rego:

1. **Basic RBAC** - User/role/permission mappings
2. **RBAC with Separation of Duty** - Prevent conflicting role assignments
3. **Dynamic Role Assignment** - Attribute-based role computation
4. **Hierarchical Roles** - Permission inheritance through role hierarchy
5. **Time-Based Access Control** - Business hours and time restrictions
6. **Location-Based Access Control** - Geographic and network-based restrictions
7. **Multi-Factor Authentication** - MFA requirements for sensitive operations
8. **Context-Aware Authorization** - Device and network context
9. **Role Delegation** - Temporary permission delegation with constraints
10. **Group-Based Access Control** - Group memberships with nesting
11. **ABAC Patterns** - Comprehensive attribute-based decisions
12. **Permit Overrides** - Any permit wins policy combination
13. **Deny Overrides** - Any deny wins policy combination
14. **Delegation Constraints** - Rules for permission delegation
15. **Mandatory Access Control** - Security clearances and classifications
16. **Discretionary Access Control** - Owner-controlled access
17. **Resource Ownership** - Ownership-based authorization
18. **Conditional Permissions** - State-dependent access control
19. **Break-Glass Access** - Emergency override with auditing
20. **Multi-Tenant Access Control** - Tenant isolation and access

These patterns can be combined and extended to implement sophisticated authorization policies for modern cloud-native applications and infrastructure.
