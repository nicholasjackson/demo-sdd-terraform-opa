# Creating Rego Policy for Terraform using with Spec Driven Development

## Prerequisites

### Installing Bob

Bob is the AI coding assistant used to run the plan and implementation prompts.

```bash
npm install -g @bob-ai/cli
```

### Installing Tessl

Tessl manages skills and plugins used by Bob in this project.

```bash
npm install -g tessl
```

After installing, authenticate and install the project's plugins:

```bash
tessl login
tessl install
```

### Installing the Terraform MCP Server (CLI version)

The Terraform MCP server provides Terraform context to the AI agent via the Model Context Protocol. Install the CLI binary:

```bash
go install github.com/hashicorp/terraform-mcp-server@latest
```

Or download a pre-built binary from the [releases page](https://github.com/hashicorp/terraform-mcp-server/releases) and place it on your `PATH`.

Once installed, the server is wired up automatically via [`.mcp.json`](.mcp.json) and will be started by Bob when needed — no manual configuration is required.

---

## Prompt Plan Mode

```markdown
You an expert in OPA (Open Policy Agent) and Rego, with experience in writing policies for Terraform. 
You are tasked with creating a detailed plan to create a Rego policy for the specification:
`./examples/docker/.sdd/specs/1_no_port_22`.

The terraform code that will be evaluated by the policy is located in `./examples/docker/terraform`.

The plan should be saved into the folder `./examples/docker/.sdd/plans`
```

## Prompt Implementation Mode

```markdown
You are an expert in OPA (Open Policy Agent) and Rego, with experience in writing policies for Terraform. 
You are tasked with implementing the Rego policy for the detailed plan:
`./examples/docker/.sdd/plans/1_no_port_22`.

The terraform code that will be evaluated by the policy is located in `./examples/docker/terraform`.

The policies should be saved into the folder `./examples/docker/policies`
```

## Running the Tests

```bash
opa test policies/ -v
```

## Running the policy against the Terraform code

```bash
# From examples/docker/terraform/
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Evaluate the policy, outputs json with any violations
opa eval -i tfplan.json -d ../policies/ "data.docker.security.deny" --format pretty
```

An empty set [] means the plan is compliant. Any violations return human-readable messages, e.g.:

```json
["container 'vault' does not have a read-only root filesystem"]
```

You can also check individual rules:

```bash
opa eval -i tfplan.json -d ../policies/ "data.docker.security.deny_port_22" --format pretty
opa eval -i tfplan.json -d ../policies/ "data.docker.security.deny_privileged" --format pretty
```

### Testing with conftest

For a more human readable output, conftest can be used to run the tests:

```bash
conftest test tfplan.json --policy ../policies/ --namespace docker.security
```

## Installing the OPA Tessl tile

```bash
tessl init
tessl install file:///home/nicj/code/github.com/tesslio/demo-opa-tile-public
```

## Commands to generate plan and implementation

### Claude
```bash
 claude -p "$(cat plan.md)" --dangerously-skip-permissions --verbose --output-format stream-json > plan.log
 claude -p "$(cat implement.md)" --dangerously-skip-permissions --verbose --output-format stream-json > implement.log
```

### Bob
```bash
bob -p "$(cat plan.md)" --yolo -o stream-json > plan.log
bob -p "$(cat implement.md)" --yolo -o stream-json > implement.log
```