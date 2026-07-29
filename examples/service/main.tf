##############################################################################
# Самый короткий вариант: одна запись — политика billing и роль
# auth/jwt/role/billing, связанные между собой.
##############################################################################

terraform {
  required_version = ">= 1.12"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.4"
    }
  }
}

provider "vault" {
  address = var.vault_address
}

variable "vault_address" {
  description = "Адрес Vault."
  type        = string
}

module "access" {
  source = "../.."

  kv_mount   = "secret"
  kv_version = 2

  policy_files_dir = null
  jwt_path         = "jwt"

  services = {
    "billing" = {
      read_paths = ["apps/billing/prod", "apps/billing/common"]
      list_paths = ["apps/billing"]

      bound_audiences = ["https://vault.example.internal"]
      bound_claims = {
        project_path = "platform/billing"
        ref          = "main"
      }

      token_ttl = 900
    }
  }
}

output "policies" {
  value = module.access.policies
}

output "jwt_roles" {
  value = module.access.jwt_roles
}
