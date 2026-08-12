# Infrastructure as Code Policy Validation with Rego

This document provides comprehensive examples of using Rego for Infrastructure as Code (IaC) validation, covering Terraform plans, AWS CloudFormation templates, and general infrastructure security policies.

## Overview

Infrastructure as Code validation with OPA enables:
- Pre-deployment validation of infrastructure changes
- Enforcement of security and compliance requirements
- Cost control and blast radius management
- Consistent naming and tagging standards
- Least privilege access control

---

## IMPORTANT: Testing IaC Policies

**The examples below include `entrypoint: true` on `deny` and `warn` rules**, which is correct for governance tooling (`opa inspect -a`, `opa build`) and direct OPA evaluation. **If you are evaluating policies with Conftest**, remove `entrypoint: true` from all `deny`, `warn`, and `violation` rules — Conftest queries rules by naming convention and does not use OPA's entrypoint mechanism. Adding `entrypoint: true` to Conftest rules changes their default scope to `document`, which may produce unexpected behavior in multi-file packages.

**Do not assume you know the field structure of a Terraform resource.** Provider schemas change across versions and vary between providers. Before writing a policy for a specific resource type, use the Terraform MCP server to look up the current resource documentation and confirm the exact attribute names and their types as they appear in the plan JSON (`change.after`). Use `search_providers` to find the provider, then `get_provider_details` to retrieve the resource schema. For example, to confirm the `ingress` block attributes for `aws_security_group`, call `get_provider_details` with the resource type name. If the Terraform MCP server is not available, do not guess field names — ask the user to provide a sample plan JSON or the resource documentation.

**Never run `terraform plan` or `terraform apply` to test policies.** Rego policies MUST be tested exclusively using `opa test`. Do NOT run `terraform plan`, `terraform apply`, or any Terraform commands to validate policy logic. Terraform operations are slow, require real infrastructure configuration, and do not provide the fine-grained test coverage that `opa test` offers. If you need to test a policy against a Terraform plan, create a mock plan JSON input in your `_test.rego` file and use the `with` keyword to inject it.

**Test file structure — name the file `policy_test.rego`.** Per the Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix) rule, test files must use the `_test.rego` filename suffix (e.g. `terraform_test.rego` alongside `terraform.rego`). The package should end in `_test` (e.g. `package terraform.analysis_test`). Use `with input as` to inject mock Terraform plan JSON. Include both a passing case (compliant resource, deny is empty) and a failing case (non-compliant resource, deny contains a message):

```rego
# terraform_test.rego
package terraform.analysis_test

import rego.v1
import data.terraform.analysis  # import the policy package under test

# Passing case: compliant resource → deny must be empty
test_compliant_bucket_allowed if {
    count(analysis.deny) == 0 with input as {"resource_changes": [{
        "type": "aws_s3_bucket",
        "address": "aws_s3_bucket.good",
        "change": {
            "actions": ["create"],
            "after": {"bucket_prefix": "my-prefix"}
        }
    }]}
}

# Failing case: non-compliant resource → deny must contain a message
test_missing_prefix_denied if {
    count(analysis.deny) == 1 with input as {"resource_changes": [{
        "type": "aws_s3_bucket",
        "address": "aws_s3_bucket.bad",
        "change": {
            "actions": ["create"],
            "after": {}
        }
    }]}
}
```

**Always check both `create` and `update` actions.** When writing policies that validate resource configuration (e.g., encryption, tags, security settings), always check for both `"create"` and `"update"` actions. A resource that passes validation at creation time can later be modified to a non-compliant state. Use the pattern: `some action in r.change.actions; action in {"create", "update"}`. Only omit `"update"` when the policy is specifically about initial resource creation (e.g., naming conventions that cannot change after creation).

**Do not check for `delete` actions unless the policy specifically prevents resource deletion.** Most policies validate resource configuration (encryption, tags, security settings) which is irrelevant when a resource is being destroyed. Only include `"delete"` in the action check when the policy is intended to prevent a resource from being deleted (e.g., protecting critical infrastructure from accidental removal).

**Handle both raw Terraform and HCP Terraform/Enterprise input structures.** The plan JSON input differs depending on how OPA is invoked:

- **Raw Terraform** (via `terraform show -json tfplan.binary`): The plan JSON **is** the entire input, so `resource_changes` is at `input.resource_changes`.
- **HCP Terraform / Terraform Enterprise**: The plan is nested under `input.plan`, with additional run metadata at `input.run`. So `resource_changes` is at `input.plan.resource_changes`.

Always use `object.get` to normalize access so policies work in both contexts without modification:

```rego
# Works with both raw Terraform and HCP Terraform/Enterprise input
tfplan := object.get(input, "plan", input)
```

This should be the default pattern in all Terraform IaC policies. With this in place, `tfplan.resource_changes` resolves correctly regardless of the input source. Policy rules then use `tfplan` consistently:

```rego
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    some action in r.change.actions; action in {"create", "update"}
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}
```

---

## 1. S3 BUCKET COMPLIANCE (ENCRYPTION AND VERSIONING)

**Key patterns this section teaches:**
- Checking **two Terraform resource types** for the same setting: the primary `aws_s3_bucket` resource (inline config) and a dedicated configuration resource (`aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_versioning`)
- **Helper function with nested list traversal**: the encryption algorithm is buried two levels deep (`rule[*].apply_server_side_encryption_by_default[*].sse_algorithm`) — a helper with `some rule_entry in ...` and `some encryption_config in ...` is the correct pattern
- Checking `status != "Enabled"` (string) for the versioning resource, not a boolean flag

S3 bucket settings like encryption and versioning can be configured either inline on the `aws_s3_bucket` resource or via a dedicated separate resource (`aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_versioning`). Policies must check both resource types.

```rego
# METADATA
# title: S3 Bucket Compliance — Encryption and Versioning
# description: Ensures all S3 buckets have server-side encryption and versioning enabled
# authors:
# - Infrastructure Security Team <infrasec@example.com>
# custom:
#   category: infrastructure-as-code
package terraform.analysis

import rego.v1

tfplan := object.get(input, "plan", input)

# --- Encryption ---

# METADATA
# title: Deny unencrypted S3 buckets
# description: Blocks S3 bucket creation without encryption configuration
# custom:
#   severity: HIGH
# entrypoint: true
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    some action in r.change.actions; action in {"create", "update"}
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}

deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket_server_side_encryption_configuration"
    some action in r.change.actions; action in {"create", "update"}
    not encryption_algorithm_valid(r)
    msg := sprintf("S3 bucket %v uses invalid encryption algorithm", [r.address])
}

# resource.change.after.rule is a list of rule objects.
# Each rule has apply_server_side_encryption_by_default as a list with one element.
encryption_algorithm_valid(resource) if {
    some rule_entry in resource.change.after.rule
    some encryption_config in rule_entry.apply_server_side_encryption_by_default
    encryption_config.sse_algorithm in {"AES256", "aws:kms"}
}

# --- Versioning ---

# METADATA
# title: Deny S3 buckets without versioning
# description: Blocks S3 bucket creation or update without versioning enabled
# custom:
#   severity: HIGH
# entrypoint: true
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    some action in r.change.actions; action in {"create", "update"}
    not has_versioning_enabled(r)
    msg := sprintf("S3 bucket %v must have versioning enabled", [r.address])
}

has_versioning_enabled(resource) if {
    some v in resource.change.after.versioning
    v.enabled == true
}

# Also check the separate versioning resource type
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket_versioning"
    some action in r.change.actions; action in {"create", "update"}
    some vc in r.change.after.versioning_configuration
    vc.status != "Enabled"
    msg := sprintf("S3 bucket versioning %v must be Enabled", [r.address])
}
```

**Description**: Validates S3 buckets have both encryption and versioning configured, checking both inline configuration and dedicated separate resource types.

---

## 2. REQUIRED TAGS ENFORCEMENT

**Key patterns this section teaches:**
- **Exclude delete actions**: use `action != "delete"` (not `action in {"create", "update"}`) when the policy should apply to all non-destructive changes — this is subtly different from the create/update pattern
- **Safe tag access**: use `object.get(r.change.after, "tags", {})` to get an empty map instead of undefined when `tags` is absent
- **Two deny rules**: one for missing tags and one for empty-string tag values — both must be enforced separately

Enforce mandatory tags across all cloud resources for cost tracking and governance.

```rego
# METADATA
# title: Required Tags Enforcement
# description: Enforces mandatory tags across all cloud resources for cost tracking and governance
# authors:
# - Infrastructure Security Team <infrasec@example.com>
# custom:
#   category: infrastructure-as-code
package terraform.analysis

import rego.v1

tfplan := object.get(input, "plan", input)

required_tags := ["Environment", "Owner", "CostCenter", "Project"]

# METADATA
# title: Deny resources missing required tags
# description: Blocks resource creation or update when mandatory tags are missing
# custom:
#   severity: MEDIUM
# entrypoint: true
deny contains msg if {
    some r in tfplan.resource_changes
    some action in r.change.actions
    action != "delete"
    supports_tags(r.type)
    tags := object.get(r.change.after, "tags", {})
    some required_tag in required_tags
    not tags[required_tag]
    msg := sprintf("Resource %v missing required tag: %v", [r.address, required_tag])
}

deny contains msg if {
    some r in tfplan.resource_changes
    some action in r.change.actions
    action != "delete"
    supports_tags(r.type)
    tags := object.get(r.change.after, "tags", {})
    some tag_key, tag_value in tags
    tag_value == ""
    msg := sprintf("Resource %v has empty tag value for: %v", [r.address, tag_key])
}

supports_tags(resource_type) if {
    resource_type in {
        "aws_instance",
        "aws_s3_bucket",
        "aws_rds_cluster",
        "aws_lambda_function",
        "aws_dynamodb_table",
        "aws_ebs_volume",
    }
}
```

**Description**: Validates that taggable resources have all required tags with non-empty values for proper resource management and cost allocation.

---

## 3. CLOUDFORMATION S3 BUCKET ACCESS CONTROL

**Key patterns this section teaches:**
- **`package system` with a `main` response object**: CloudFormation hooks use `package system` and must return `{"allow": bool, "violations": set}` — this is different from Terraform policies that only use `deny` rules
- **Uppercase action strings**: CloudFormation uses `"CREATE"` and `"UPDATE"` (not lowercase), and the resource type uses `AWS::S3::Bucket` notation
- **Helper rules for readability**: factor repeated conditions (`bucket_create_or_update`, `bucket_is_private`, `block_public_acls`) into separate boolean rules rather than inlining them in every deny rule
- **`input.resource`** (not `input.resource_changes`) — CloudFormation hooks receive a single resource at `input.resource.type`, `input.resource.id`, and `input.resource.properties`

CloudFormation hook policy to enforce S3 bucket security configurations.

```rego
# METADATA
# title: CloudFormation S3 Bucket Access Control
# description: CloudFormation hook policy to enforce S3 bucket security configurations
# authors:
# - Infrastructure Security Team <infrasec@example.com>
# custom:
#   category: infrastructure-as-code
package system

import rego.v1

main := {
    "allow": count(deny) == 0,
    "violations": deny,
}

# METADATA
# title: Deny non-private S3 buckets
# description: Blocks S3 buckets that do not have private access control
# custom:
#   severity: HIGH
# entrypoint: true
deny contains msg if {
    bucket_create_or_update
    not bucket_is_private
    msg := sprintf("S3 Bucket %s 'AccessControl' attribute value must be 'Private'", [input.resource.id])
}

deny contains msg if {
    bucket_create_or_update
    not block_public_acls
    msg := sprintf("S3 Bucket %s must block public ACLs", [input.resource.id])
}

deny contains msg if {
    bucket_create_or_update
    not block_public_policy
    msg := sprintf("S3 Bucket %s must block public bucket policies", [input.resource.id])
}

bucket_create_or_update if {
    input.resource.type == "AWS::S3::Bucket"
    input.action in {"CREATE", "UPDATE"}
}

bucket_is_private if {
    input.resource.properties.AccessControl == "Private"
}

block_public_acls if {
    input.resource.properties.PublicAccessBlockConfiguration.BlockPublicAcls == "true"
}

block_public_policy if {
    input.resource.properties.PublicAccessBlockConfiguration.BlockPublicPolicy == "true"
}
```

**Description**: CloudFormation hook policy that validates S3 buckets have private access control and block public access configurations before deployment.

---

## 4. TERRAFORM MODULE SECURITY GROUP VALIDATION

**Key patterns this section teaches:**
- **`walk()` to traverse nested modules**: use `walk(input.planned_values, [path, value])` to visit every node in the plan tree, including resources in child modules
- **Distinguishing root vs child module resources**: check `reverse_index(path, 2) == "root_module"` for top-level resources and `reverse_index(path, 3) == "child_modules"` for nested module resources
- **`reverse_index` helper**: `path[count(path) - idx]` reads the path array from the end — a reusable pattern for positional path matching

Validate security groups don't use insecure protocols across modules.

```rego
# METADATA
# title: Terraform Module Security Group Validation
# description: Validates security groups across modules do not use insecure protocols
# authors:
# - Infrastructure Security Team <infrasec@example.com>
# custom:
#   category: infrastructure-as-code
package terraform.module

import rego.v1

# METADATA
# title: Deny insecure HTTP in security groups
# description: Blocks security groups that reference HTTP protocol across all modules
# custom:
#   severity: HIGH
# entrypoint: true
deny contains msg if {
    some r
    desc := resources[r].values.description
    contains(desc, "HTTP")
    msg := sprintf("No security groups should be using HTTP. Resource in violation: %v", [r.address])
}

resources contains r if {
    some path, value
    walk(input.planned_values, [path, value])
    some r in module_resources(path, value)
}

module_resources(path, value) := value if {
    reverse_index(path, 1) == "resources"
    reverse_index(path, 2) == "root_module"
}

module_resources(path, value) := value if {
    reverse_index(path, 1) == "resources"
    reverse_index(path, 3) == "child_modules"
}

reverse_index(path, idx) := path[count(path) - idx]
```

**Description**: Walks Terraform plan structure including child modules to ensure no security groups use insecure HTTP protocol.

---

## 5. MULTI-REGION DEPLOYMENT POLICIES

**Key patterns this section teaches:**
- **Multiple function heads for the same helper**: define `has_replication(resource)` twice, each with a different `resource.type` check — OPA evaluates all heads and the rule is true if any head succeeds. This is cleaner than a single function with `if/else` logic
- **Provider region access path**: the AWS provider region is at `tfplan.configuration.provider_config.aws.expressions.region.constant_value` — a deeply nested path not easily guessed

When checking the same logical condition against multiple resource types, define a helper with multiple function heads — one per resource type. OPA evaluates all heads and the rule is true if any head succeeds.

```rego
# METADATA
# title: Multi-Region Deployment Policies
# description: Ensures multi-region resources follow geographic compliance requirements
# authors:
# - Infrastructure Security Team <infrasec@example.com>
# custom:
#   category: infrastructure-as-code
package terraform.analysis

import rego.v1

tfplan := object.get(input, "plan", input)

allowed_regions := {"us-east-1", "us-west-2", "eu-west-1", "eu-central-1"}
eu_only_regions := {"eu-west-1", "eu-central-1"}

deny contains msg if {
    region := tfplan.configuration.provider_config.aws.expressions.region.constant_value
    not allowed_regions[region]
    msg := sprintf("Region %v is not in approved regions list", [region])
}

deny contains msg if {
    some r in tfplan.resource_changes
    r.type in {"aws_s3_bucket", "aws_rds_cluster", "aws_dynamodb_table"}
    "create" in r.change.actions
    tags := object.get(r.change.after, "tags", {})
    tags.DataResidency == "EU"
    region := tfplan.configuration.provider_config.aws.expressions.region.constant_value
    not eu_only_regions[region]
    msg := sprintf("Resource %v with EU data residency requirement must be in EU region", [r.address])
}

# METADATA
# title: Warn about missing replication for critical resources
# description: Warns when critical resources lack multi-region replication
# custom:
#   severity: LOW
# entrypoint: true
warn contains msg if {
    some r in tfplan.resource_changes
    r.type in {"aws_s3_bucket", "aws_dynamodb_table"}
    "create" in r.change.actions
    tags := object.get(r.change.after, "tags", {})
    tags.Criticality == "high"
    not has_replication(r)
    msg := sprintf("Critical resource %v should have multi-region replication configured", [r.address])
}

# Multiple function heads — one per resource type. OPA tries each head in turn.
has_replication(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.replication_configuration
}

has_replication(resource) if {
    resource.type == "aws_dynamodb_table"
    count(resource.change.after.replica) > 0
}
```

**Description**: Validates resources are deployed in approved regions and enforces data residency requirements with multi-region replication for critical resources.

---
