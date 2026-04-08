output "vault_addr" {
  description = "Vault server address"
  value       = "http://localhost:${var.vault_port}"
}

output "container_name" {
  description = "Name of the Vault container"
  value       = docker_container.vault.name
}

output "container_id" {
  description = "ID of the Vault container"
  value       = docker_container.vault.id
}

output "root_token" {
  description = "Root token (dev mode only)"
  value       = var.dev_mode ? var.root_token : "N/A - not in dev mode"
  sensitive   = true
}

output "usage" {
  sensitive = true
  description = "How to connect to Vault"
  value       = <<-EOT
    Export these environment variables:
      export VAULT_ADDR=http://localhost:${var.vault_port}
      export VAULT_TOKEN=${var.dev_mode ? var.root_token : "<your-token>"}

    Then run:
      vault status
  EOT
}
