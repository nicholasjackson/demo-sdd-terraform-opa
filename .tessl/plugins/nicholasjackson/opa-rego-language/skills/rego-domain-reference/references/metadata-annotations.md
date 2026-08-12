# OPA Metadata Annotations

Metadata annotations document, categorize, and enable runtime inspection of Rego policies. OPA supports structured YAML annotations via `# METADATA` comment blocks that can be applied at package, document, and rule scope. These annotations power CLI auto-discovery, schema validation, policy cataloging, and governance tooling.

---

## 1. Package-Level Metadata

Annotate entire policy packages with title, description, authors, organizations, and custom fields to document what a policy module does and who owns it.

```rego
# METADATA
# title: Kubernetes Admission Control
# description: >-
#   Validates Kubernetes resources against organization security
#   standards including image provenance, resource limits, and
#   pod security baselines.
# authors:
# - name: Platform Security Team
#   email: platform-security@example.com
# organizations:
# - Example Corp
# custom:
#   category: kubernetes
#   compliance_framework: SOC2
#   version: "2.1"
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny untrusted images
# description: Ensures all container images come from approved registries
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    image := container.image
    not startswith(image, "registry.example.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}
```

**Key Points:**
- Package-level metadata is placed **before** the `package` declaration
- Use `>-` for multi-line YAML strings (folds lines, strips trailing newline)
- Authors support both object format (`name:`, `email:`) and string format (`Name <email>`)
- Custom fields can hold any YAML-valid data structure

---

## 2. Rule-Level Metadata with Entrypoints

Mark decision rules with `entrypoint: true` so that OPA's CLI and tooling can automatically discover which rules are intended for external consumption. Helper rules should not be marked as entrypoints.

**`entrypoint: true` is required for governance tooling.** When you run `opa inspect -a` or use `opa build`, OPA uses this flag to distinguish the policy's public API (the rules your system queries) from internal helper rules. Without `entrypoint: true`, a rule's metadata will appear in `opa inspect` output but tooling cannot identify it as a decision rule vs. a utility function. Every decision rule that external systems call must be marked `entrypoint: true`.

> **Conftest exception:** Do **not** add `entrypoint: true` to policies evaluated by Conftest. Conftest queries rules by naming convention (`deny`, `warn`, `violation` and their suffixed variants like `deny_no_latest_tag`) — it does not use OPA's entrypoint mechanism. Adding `entrypoint: true` to a Conftest rule is unnecessary and changes the rule's default scope to `document`, which may produce unexpected behavior in multi-file packages.

```rego
# METADATA
# title: Terraform Security Policy
# description: Validates Terraform plans against security requirements
# authors:
# - Infrastructure Security <infrasec@example.com>
package terraform.analysis

import input as tfplan
import rego.v1

# METADATA
# title: Deny unencrypted S3 buckets
# description: >-
#   Ensures all S3 buckets have server-side encryption configured
#   before creation is allowed.
# entrypoint: true
# custom:
#   severity: HIGH
#   compliance: ["PCI-DSS 3.4", "SOC2 CC6.6"]
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    "create" in r.change.actions
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}

# METADATA
# title: Warn about expensive instances
# description: Flags EC2 instances with high estimated monthly cost
# entrypoint: true
# custom:
#   severity: LOW
warn contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_instance"
    "create" in r.change.actions
    instance_type := r.change.after.instance_type
    cost := instance_costs[instance_type]
    cost > 100
    msg := sprintf("Instance %v uses expensive type %v (~$%.2f/month)", [r.address, instance_type, cost])
}

# Helper rule - NOT an entrypoint
instance_costs := {
    "t3.micro": 7.50,
    "m5.large": 70.00,
    "r5.xlarge": 182.00,
}
```

**Key Points:**
- **Every decision rule that external systems query must have `entrypoint: true`** — this is what makes it discoverable by `opa inspect -a`, `opa build`, and governance tooling
- Helper rules (`instance_costs`) must **not** have `entrypoint: true`
- Multiple entrypoint rules can exist in the same package
- The `entrypoint` flag implies `scope: document` unless explicitly overridden

---

## 3. Schema Annotations for Type Checking

Associate JSON schemas with `input` and `data` paths to enable `opa check` to catch structural errors and typos at build time rather than runtime.

```rego
# METADATA
# title: API Authorization
# description: Validates API requests against access control rules
# schemas:
# - input:
#     type: object
#     required:
#     - method
#     - path
#     - user
#     properties:
#       method:
#         type: string
#         enum: ["GET", "POST", "PUT", "DELETE", "PATCH"]
#       path:
#         type: array
#         items:
#           type: string
#       user:
#         type: string
#       headers:
#         type: object
package httpapi.authz

import rego.v1

# METADATA
# title: Allow authorized requests
# entrypoint: true
# schemas:
# - input:
#     type: object
#     required: ["method", "path", "user"]
default allow := false

allow if {
    input.method == "GET"
    "read" in data.users[input.user].permissions
}
```

**Using External Schema Files:**
```rego
# METADATA
# title: Kubernetes Admission
# schemas:
# - input: schema.input
# - data.kubernetes.namespaces: schema["kubernetes-namespaces"]
package kubernetes.admission

import rego.v1

# METADATA
# title: Deny invalid ingress hosts
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    input.request.kind.kind == "Ingress"
    some rule in input.request.object.spec.rules
    host := rule.host
    not valid_host(host)
    msg := sprintf("invalid ingress host %q", [host])
}

valid_host(host) if {
    endswith(host, ".example.com")
}
```

**Key Points:**
- Inline schemas use standard JSON Schema syntax embedded in YAML
- External schemas reference files via `schema.{name}` and are loaded with `opa check -s`
- Schemas can be attached at package or rule level
- Run `opa check --strict -s schema/` to validate against schemas at build time

---

## 4. Custom Metadata for Policy Categorization

Use the `custom:` field for severity levels, compliance frameworks, audit flags, team ownership, and any domain-specific classification. This builds a self-documenting policy library.

```rego
# METADATA
# title: PCI-DSS Encryption Policy
# description: Validates encryption requirements for payment card data
# custom:
#   category: compliance
#   compliance_framework: PCI-DSS
#   applicable_requirements:
#   - "Req 3.4 - Render PAN unreadable"
#   - "Req 3.5 - Protect encryption keys"
#   team: payment-security
#   review_cycle: quarterly
#   last_reviewed: "2024-09-15"
package compliance.pci.encryption

import rego.v1

# METADATA
# title: Require encryption for cardholder data
# description: Databases storing cardholder data must use encryption at rest
# entrypoint: true
# custom:
#   severity: HIGH
#   pci_requirement: "3.4"
#   auto_remediation: false
deny contains msg if {
    some resource in input.resources
    resource.type == "database"
    resource.stores_cardholder_data
    not resource.encrypted_at_rest
    msg := sprintf("Database %v stores cardholder data but is not encrypted (PCI-DSS Req 3.4)", [resource.id])
}

# METADATA
# title: Require strong encryption algorithms
# description: Resources must use approved encryption algorithms
# entrypoint: true
# custom:
#   severity: HIGH
#   pci_requirement: "3.5"
#   auto_remediation: false
deny contains msg if {
    some resource in input.resources
    resource.encrypted_at_rest
    not valid_encryption_algorithm(resource.encryption_algorithm)
    msg := sprintf("Resource %v uses weak encryption algorithm %v (PCI-DSS Req 3.5)", [resource.id, resource.encryption_algorithm])
}

valid_encryption_algorithm(algorithm) if {
    algorithm in {"AES-256", "AES-256-GCM", "RSA-2048", "RSA-4096"}
}
```

**Key Points:**
- `custom:` accepts any YAML-valid structure (strings, lists, maps, nested objects)
- Use consistent field names across your policy library for programmatic access
- Common custom fields: `severity`, `category`, `team`, `compliance_framework`, `auto_remediation`
- Enables filtering policies by category, team, or compliance requirement

---

## 5. Accessing Metadata at Runtime with `rego.metadata.rule()`

Use `rego.metadata.rule()` and `rego.metadata.chain()` to access annotations programmatically. This enables dynamic policy behavior based on metadata, such as severity-aware error formatting or policy self-documentation.

```rego
# METADATA
# title: Security Violation Reporter
# description: Generates structured violation reports with severity from metadata
package security.reporter

import rego.v1

# METADATA
# title: Deny privileged containers
# description: Blocks creation of privileged containers in Kubernetes
# entrypoint: true
# custom:
#   severity: HIGH
#   category: pod-security
violations contains violation if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    container.securityContext.privileged == true
    annotation := rego.metadata.rule()
    violation := {
        "title": annotation.title,
        "severity": annotation.custom.severity,
        "category": annotation.custom.category,
        "message": sprintf("privileged container %v is not allowed", [container.name]),
        "resource": input.request.object.metadata.name,
    }
}

# METADATA
# title: Deny containers without resource limits
# description: Requires CPU and memory limits on all containers
# entrypoint: true
# custom:
#   severity: MEDIUM
#   category: resource-management
violations contains violation if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.resources.limits
    annotation := rego.metadata.rule()
    violation := {
        "title": annotation.title,
        "severity": annotation.custom.severity,
        "category": annotation.custom.category,
        "message": sprintf("container %v must specify resource limits", [container.name]),
        "resource": input.request.object.metadata.name,
    }
}

# Summary report derived from violations
report := {
    "total": count(violations),
    "by_severity": {
        "HIGH": count([v | some v in violations; v.severity == "HIGH"]),
        "MEDIUM": count([v | some v in violations; v.severity == "MEDIUM"]),
        "LOW": count([v | some v in violations; v.severity == "LOW"]),
    },
    "violations": violations,
}
```

**Key Points:**
- `rego.metadata.rule()` returns the annotation object for the current rule
- `rego.metadata.chain()` returns annotations from rule through package ancestry
- Use metadata to build structured violation objects with severity, category, and context
- Enables consistent reporting format without hardcoding metadata in rule bodies

**Testing**: Because `rego.metadata.rule()` reads annotations baked into the policy source, tests do not need to mock the metadata — they only need to mock `input`. Assert on the structured fields (`severity`, `message`) returned in each violation:

```rego
# security_reporter_test.rego
package security.reporter_test

import rego.v1
import data.security.reporter  # import the policy package under test

# Privileged container → one HIGH violation
test_privileged_container_violation if {
    result := reporter.violations with input as {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "metadata": {"name": "my-pod"},
                "spec": {
                    "containers": [
                        {"name": "app", "securityContext": {"privileged": true}, "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}
                    ]
                }
            }
        }
    }
    count(result) == 1
    some v in result
    v.severity == "HIGH"
    contains(v.message, "app")
}

# Non-privileged container with limits → no violations
test_compliant_container_allowed if {
    result := reporter.violations with input as {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "metadata": {"name": "my-pod"},
                "spec": {
                    "containers": [
                        {"name": "app", "securityContext": {"privileged": false}, "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}
                    ]
                }
            }
        }
    }
    count(result) == 0
}
```

---

## 6. Related Resources and Authors

Document policy provenance with `related_resources:` and `authors:` to link policies to specifications, standards, and responsible teams.

```rego
# METADATA
# title: GDPR Data Protection Policy
# description: >-
#   Enforces GDPR Article 32 requirements for data protection
#   including encryption, access controls, and data minimization.
# authors:
# - name: Data Protection Officer
#   email: dpo@example.com
# - name: Privacy Engineering Team
#   email: privacy-eng@example.com
# organizations:
# - Example Corp Data Governance
# related_resources:
# - ref: https://gdpr-info.eu/art-32-gdpr/
#   description: GDPR Article 32 - Security of Processing
# - ref: https://wiki.example.com/privacy/data-protection-policy
#   description: Internal data protection implementation guide
# - ref: https://example.com/compliance/gdpr-checklist
#   description: GDPR compliance checklist
# custom:
#   category: compliance
#   regulation: GDPR
#   articles: ["32", "5(1)(f)"]
package compliance.gdpr.protection

import rego.v1

# METADATA
# title: Require encryption for personal data
# description: Resources storing personal data must use encryption
# entrypoint: true
# related_resources:
# - ref: https://gdpr-info.eu/art-32-gdpr/
#   description: GDPR Art. 32 - appropriate technical measures
# custom:
#   severity: HIGH
deny contains msg if {
    some resource in input.resources
    resource.stores_personal_data
    not resource.encrypted
    msg := sprintf("Resource %v stores personal data without encryption (GDPR Art. 32)", [resource.id])
}

# METADATA
# title: Validate data minimization
# description: Collections must only include necessary personal data fields
# entrypoint: true
# related_resources:
# - ref: https://gdpr-info.eu/art-5-gdpr/
#   description: GDPR Art. 5(1)(c) - data minimisation
# custom:
#   severity: MEDIUM
deny contains msg if {
    some collection in input.data_collections
    some field in collection.fields
    field.data_category == "personal"
    not field.necessary_for_purpose
    msg := sprintf("Collection %v includes unnecessary personal data field %v (GDPR Art. 5(1)(c))", [collection.name, field.name])
}
```

**Key Points:**
- `related_resources:` supports both object format (`ref:`, `description:`) and plain URL strings
- `authors:` supports object format (`name:`, `email:`) and string format (`Name <email>`)
- Link to external standards, internal wikis, and compliance documentation
- Both package-level and rule-level annotations can have related resources

---

## 7. Metadata Scoping: Rule, Document, Package, Subpackages

The `scope` field determines where annotations apply. Understanding scope is essential for large policy libraries with multiple files per package.

```rego
# METADATA
# scope: subpackages
# title: Network Security Policies
# description: >-
#   All network security policies across the organization.
#   This annotation applies to this package and all subpackages.
# custom:
#   domain: network-security
#   owner: network-team
package network

import rego.v1
```

```rego
# METADATA
# scope: package
# title: Firewall Rule Validation
# description: >-
#   Validates firewall rules across all files in this package.
#   Applies to all rules regardless of which file they're in.
# custom:
#   category: firewall
package network.firewall

import rego.v1

# METADATA
# scope: document
# title: Deny overly permissive rules
# description: >-
#   All deny rules with this name across all files in this
#   package share this annotation (document scope).
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    some rule in input.firewall_rules
    rule.source_range == "0.0.0.0/0"
    rule.action == "allow"
    sensitive_port(rule.port)
    msg := sprintf("Firewall rule %v allows access from anywhere to sensitive port %v", [rule.name, rule.port])
}

# METADATA
# scope: rule
# title: Deny broad access without justification
# description: >-
#   This annotation applies only to this specific rule
#   definition (rule scope, the default).
# entrypoint: true
# custom:
#   severity: MEDIUM
deny contains msg if {
    some rule in input.firewall_rules
    rule.source_range == "0.0.0.0/0"
    not rule.justification
    msg := sprintf("Firewall rule %v allows broad access but lacks justification", [rule.name])
}

sensitive_port(port) if {
    port in {22, 3389, 1433, 3306, 5432, 6379, 27017}
}
```

**Scope Reference:**

| Scope | Applies To | Default For |
|-------|-----------|-------------|
| `rule` | Single rule definition in current file | Rules |
| `document` | All rules with same name in same package | Rules with `entrypoint: true` |
| `package` | All rules in the package (across files) | Package annotations |
| `subpackages` | Package and all subpackages recursively | -- |

**Key Points:**
- Default scope for rules is `rule`; setting `entrypoint: true` changes default to `document`
- Default scope for package annotations is `package`
- Use `subpackages` scope for organization-wide metadata on root packages
- Scope determines what `rego.metadata.chain()` returns when traversing ancestry

---

## 8. Policy Discovery and Inspection with `opa inspect`

Use `opa inspect -a` to list all metadata annotations across your policy bundle. This enables policy catalog generation, compliance auditing, and governance tooling.

```rego
# METADATA
# title: Container Security Policy Suite
# description: >-
#   Comprehensive container security policies for Docker
#   daemon authorization and Kubernetes admission control.
# authors:
# - Container Security Team <containersec@example.com>
# organizations:
# - Example Corp Platform Engineering
# custom:
#   category: container-security
#   version: "3.0"
#   audit_frequency: monthly
package container.security

import rego.v1

# METADATA
# title: Deny privileged containers
# description: Prevents running containers in privileged mode
# entrypoint: true
# custom:
#   severity: HIGH
#   cis_benchmark: "5.4"
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    container.securityContext.privileged == true
    msg := sprintf("privileged container %v is not allowed (CIS 5.4)", [container.name])
}

# METADATA
# title: Require non-root user
# description: Ensures containers run as non-root for defense in depth
# entrypoint: true
# custom:
#   severity: HIGH
#   cis_benchmark: "5.2"
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.securityContext.runAsNonRoot
    msg := sprintf("container %v must run as non-root user (CIS 5.2)", [container.name])
}

# METADATA
# title: Require resource limits
# description: All containers must have CPU and memory limits
# entrypoint: true
# custom:
#   severity: MEDIUM
#   cis_benchmark: "5.10"
deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.resources.limits
    msg := sprintf("container %v must specify resource limits (CIS 5.10)", [container.name])
}
```

**Inspecting Annotations:**

```bash
# List all annotations in a policy bundle
opa inspect -a ./policies/

# Example output:
# container.security (package):
#   title: Container Security Policy Suite
#   authors: [Container Security Team <containersec@example.com>]
#   custom:
#     category: container-security
#     version: "3.0"
#
# container.security.deny (rule):
#   title: Deny privileged containers
#   entrypoint: true
#   custom:
#     severity: HIGH
#     cis_benchmark: "5.4"
```

**Building a Policy Catalog:**
```rego
# METADATA
# title: Policy Catalog Generator
# description: Generates a catalog of all policies from metadata
# entrypoint: true
package tools.catalog

import rego.v1

# Use rego.metadata.chain() in combination with data to build
# dynamic catalogs. External tools can also use opa inspect -a
# to generate policy inventories programmatically.

catalog[rule_path] := info if {
    some rule_path
    annotation := rego.metadata.chain()[0]
    info := {
        "title": object.get(annotation, "title", "untitled"),
        "severity": object.get(annotation.custom, "severity", "UNSET"),
        "entrypoint": object.get(annotation, "entrypoint", false),
    }
}
```

**Key Points:**
- `opa inspect -a` shows all annotations grouped by path and location
- Use annotations to build policy catalogs, compliance matrices, and governance dashboards
- Annotations are included in OPA bundles and accessible via the REST API
- Combine with `opa build` to create annotated policy bundles for distribution

---

## Summary

| Section | Pattern | Key Annotation Fields |
|---------|---------|----------------------|
| Package-Level | Document entire policy modules | `title`, `description`, `authors`, `organizations`, `custom` |
| Entrypoints | Mark externally-queried rules | `entrypoint: true`, `title`, `description`, `custom.severity` |
| Schemas | Type-check input and data | `schemas` with inline or external JSON Schema |
| Custom Metadata | Categorize and classify policies | `custom.*` (severity, category, compliance, team) |
| Runtime Access | Dynamic behavior from metadata | `rego.metadata.rule()`, `rego.metadata.chain()` |
| Provenance | Document authors and references | `authors`, `organizations`, `related_resources` |
| Scoping | Control annotation application | `scope: rule\|document\|package\|subpackages` |
| Inspection | Discover and catalog policies | `opa inspect -a`, bundle metadata |

These metadata patterns enable self-documenting policy libraries, automated governance tooling, and consistent policy management across teams and compliance frameworks.
