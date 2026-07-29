##############################################################################
# Политика + роль в уже существующем JWT-бэкенде (auth/jwt).
# Сам бэкенд не трогаем: manage_jwt_backend остаётся false.
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
  kv_version = 1

  policy_files_dir = null

  policies = {
    "billing-ro" = {
      read_paths = ["apps/billing/prod"]
      list_paths = ["apps/billing"]
    }
  }

  # Роли лягут в auth/jwt/role/<имя>.
  jwt_path = "jwt"

  jwt_roles = {
    "billing-ci" = {
      policies = ["billing-ro"]

      # Чьё имя увидит Vault в аудите.
      user_claim = "sub"

      # Кому предназначен токен — так роль не примет JWT, выписанный для другого сервиса.
      bound_audiences = ["https://vault.example.internal"]

      # Что ещё должно совпасть. Значения — точные; для шаблонов
      # (ветки, окружения) поставить bound_claims_type = "glob".
      bound_claims = {
        project_path  = "platform/billing"
        ref           = "main"
        ref_protected = "true"
      }

      token_ttl = 900
    }
  }
}

output "jwt_roles" {
  value = module.access.jwt_roles
}
