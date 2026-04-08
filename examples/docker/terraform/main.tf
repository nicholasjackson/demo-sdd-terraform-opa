terraform {
  required_version = ">= 1.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

# Pull the Vault image
resource "docker_image" "vault" {
  name         = "hashicorp/vault:${var.vault_version}"
  keep_locally = true
}

# Create a network for Vault
resource "docker_network" "vault" {
  name   = "${var.container_name}-network"
  driver = "bridge"
}

# Create a volume for Vault data persistence
resource "docker_volume" "vault_data" {
  name = "${var.container_name}-data"
}

# Create a volume for Vault logs
resource "docker_volume" "vault_logs" {
  name = "${var.container_name}-logs"
}

# Run Vault container
resource "docker_container" "vault" {
  name  = var.container_name
  image = docker_image.vault.image_id

  # Development mode runs unsealed with in-memory storage
  # For production, remove -dev and configure proper storage backend
  command = var.dev_mode ? ["server", "-dev", "-dev-root-token-id=${var.root_token}"] : ["server"]

  env = var.dev_mode ? [
    "VAULT_DEV_ROOT_TOKEN_ID=${var.root_token}",
    "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
    "VAULT_ADDR=http://127.0.0.1:8200",
  ] : [
    "VAULT_ADDR=http://127.0.0.1:8200",
  ]

  ports {
    internal = 8200
    external = var.vault_port
  }

  networks_advanced {
    name = docker_network.vault.name
  }

  volumes {
    volume_name    = docker_volume.vault_data.name
    container_path = "/vault/data"
  }

  volumes {
    volume_name    = docker_volume.vault_logs.name
    container_path = "/vault/logs"
  }

  # Mount config file if not in dev mode
  dynamic "upload" {
    for_each = var.dev_mode ? [] : [1]
    content {
      content = templatefile("${path.module}/vault-config.hcl.tpl", {
        api_addr     = "http://0.0.0.0:8200"
        cluster_addr = "http://0.0.0.0:8201"
      })
      file = "/vault/config/vault.hcl"
    }
  }

  read_only = true

  capabilities {
    add  = ["IPC_LOCK"]
    drop = ["ALL"]
  }

  restart = "unless-stopped"

  healthcheck {
    test         = ["CMD", "vault", "status", "-address=http://127.0.0.1:8200"]
    interval     = "10s"
    timeout      = "5s"
    retries      = 3
    start_period = "10s"
  }
}
