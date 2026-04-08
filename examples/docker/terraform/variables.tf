variable "vault_version" {
  description = "Version of Vault to run"
  type        = string
  default     = "1.15"
}

variable "container_name" {
  description = "Name of the Vault container"
  type        = string
  default     = "vault"
}

variable "vault_port" {
  description = "External port to expose Vault on"
  type        = number
  default     = 8200
}

variable "dev_mode" {
  description = "Run Vault in development mode (unsealed, in-memory storage)"
  type        = bool
  default     = true
}

variable "root_token" {
  description = "Root token for dev mode"
  type        = string
  default     = "root"
  sensitive   = true
}
