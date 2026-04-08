# Feature: Security Hardening for Docker Containers

<!--
  OVERVIEW
  A concise 2-3 sentence summary of the feature. Answer three questions:
    1. What is being built?
    2. What problem does it solve?
    3. Who benefits and why does it matter?
  Avoid implementation details — this should be readable by any stakeholder.
-->
## Overview
An OPA policy that enforces security hardening for Docker containers provisioned with Terraform. The policy prevents common container misconfiguration risks, including privilege escalation, writable filesystems, and unvetted images, by failing the Terraform plan before any infrastructure is applied. Platform and security engineers can use this to enforce a consistent security baseline across all container workloads without relying on manual review.

<!--
  REQUIREMENTS
  Specific, testable behaviours the feature must deliver.
  Format: bold title on the checkbox line, detail indented below.
  Rules:
    - Use active voice: "Users can...", "The system must..."
    - Each requirement should be independently verifiable
    - Focus on WHAT, not HOW — avoid prescribing implementation
    - Keep each item atomic — one behaviour per line
-->
## Requirements
- [ ] **SSH port exposure is blocked**
  The policy must deny any Docker container that exposes port 22, regardless of the host port it is mapped to.
- [ ] **Privileged mode is blocked**
  The policy must deny any Docker container configured to run in privileged mode.
- [ ] **Writable root filesystems are blocked**
  The policy must deny any Docker container that does not have a read-only root filesystem.
- [ ] **Containers must drop all Linux capabilities**
  The policy must deny any Docker container that does not explicitly drop all Linux capabilities.
- [ ] **Containers may only add explicitly required capabilities**
  The policy must deny any Docker container that adds capabilities beyond those listed as required.
- [ ] **Images must use the hashicorp namespace**
  The policy must deny any Docker container using an image that is not prefixed with the `hashicorp/` namespace.
- [ ] **Images must specify an explicit version tag**
  The policy must deny any Docker container using an image tagged as `latest` or with no tag specified.

<!--
  CONSTRAINTS
  Hard boundaries the solution must operate within. These are non-negotiable.
  Examples:
    - Must integrate with the existing authentication system
    - Cannot introduce breaking changes to the public API
    - Must support the current minimum supported runtime versions
  Leave blank if there are no constraints.
-->
## Constraints


<!--
  ACCEPTANCE CRITERIA
  The specific, binary conditions that define "done".
  Format: bold title on the checkbox line, verifiable detail indented below.
  Each criterion must be:
    - Independently verifiable (pass/fail, not subjective)
    - Traceable back to a requirement above
    - Testable by someone who didn't write the code
-->
## Acceptance Criteria

### SSH port exposure is blocked
- [ ] **Port 22 mapped to a standard host port is denied**
  A plan containing a container with port 22 mapped to any host port must produce a deny message.
- [ ] **A container exposing only non-SSH ports is allowed**
  A plan containing a container exposing only non-SSH ports (e.g. 8200) must produce no deny messages for this rule.
- [ ] **A container with no port mappings is allowed**
  A plan containing a container with no port mappings defined must produce no deny messages for this rule.

### Privileged mode is blocked
- [ ] **A privileged container is denied**
  A plan containing a container with privileged mode set to true must produce a deny message.
- [ ] **A non-privileged container is allowed**
  A plan containing a container with privileged mode unset or set to false must produce no deny messages for this rule.

### Writable root filesystems are blocked
- [ ] **A container with a writable root filesystem is denied**
  A plan containing a container without read_only_root_filesystem set to true must produce a deny message.
- [ ] **A container with a read-only root filesystem is allowed**
  A plan containing a container with read_only_root_filesystem set to true must produce no deny messages for this rule.

### Containers must drop all Linux capabilities
- [ ] **A container that does not drop all capabilities is denied**
  A plan containing a container that does not include cap_drop = ["ALL"] must produce a deny message.
- [ ] **A container with no capabilities block is denied**
  A plan containing a container with no capabilities block defined must produce a deny message.

### Containers may only add explicitly required capabilities
- [ ] **A container that drops all and adds a specific capability is allowed**
  A plan containing a container with cap_drop = ["ALL"] and cap_add = ["IPC_LOCK"] must produce no deny messages for this rule.
- [ ] **A container that drops all and adds no capabilities is allowed**
  A plan containing a container with cap_drop = ["ALL"] and no cap_add must produce no deny messages for this rule.

### Images must use the hashicorp namespace
- [ ] **A container using an image from an unknown namespace is denied**
  A plan containing a container using an image not prefixed with hashicorp/ (e.g. nginx:latest) must produce a deny message.
- [ ] **A container using a hashicorp-namespaced image is allowed**
  A plan containing a container using an image prefixed with hashicorp/ must produce no deny messages for this rule.

### Images must specify an explicit version tag
- [ ] **A container using an image with no tag is denied**
  A plan containing a container using an image with no tag specified must produce a deny message.
- [ ] **A container using an image tagged latest is denied**
  A plan containing a container using an image tagged as latest must produce a deny message.
- [ ] **A container using an image with an explicit version tag is allowed**
  A plan containing a container using hashicorp/vault:1.15 must produce no deny messages for this rule.

<!--
  TECHNICAL APPROACH
  High-level technical direction to guide the planning agent. Include:
    - Key architectural decisions already made
    - Preferred patterns or technologies if known
    - Integration points with existing systems
    - Known risks or areas of uncertainty
  Leave blank if you want the planner to propose the approach.
-->
## Technical Approach
- The policy must support both create and update Terraform plan actions
- Best practices, language conventions, and provider documentation are provided 
  via project context — refer to `AGENTS.md`

<!--
  SUCCESS METRICS
  How you will know the feature is working well after delivery. Be specific:
    - Quantitative: "p99 latency < 200ms", "error rate < 0.1%"
    - Behavioural: "users complete the flow without support intervention"
  Leave blank if not applicable.
-->
## Success Metrics
- All OPA unit tests pass
- All unit tests map to an acceptance criterion — no untraceable tests, no untested criteria
- The policy produces no deny messages against a correctly configured Terraform example

<!--
  NON-GOALS
  Explicitly state what this spec does NOT cover. This is as important as
  the requirements — it prevents scope creep and sets clear expectations.
  Examples:
    - "Mobile support is out of scope (tracked in #456)"
    - "Internationalisation will be addressed in a follow-up spec"
  Leave blank if there are no explicit exclusions to call out.
-->
## Non-Goals
