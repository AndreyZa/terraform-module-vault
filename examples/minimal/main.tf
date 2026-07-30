##############################################################################
# Минимальный пример: одна политика на чтение, одна роль kubernetes,
# одна AppRole для CI. Применять не обязательно — служит проверяемым образцом
# вызова (terraform init && terraform validate).
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
  # Токен — из VAULT_TOKEN.
}

variable "vault_address" {
  description = "Адрес Vault."
  type        = string
}

variable "cluster_ca_cert" {
  description = "PEM CA API-сервера кластера."
  type        = string
  default     = ""
}

module "access" {
  source = "../.."

  kv_mount = "secret"

  # Версия KV-движка маунта: 1 (по умолчанию) или 2. Должна совпадать с реальной,
  # иначе политика применится без ошибок и не даст прав.
  kv_version = 1

  # Рукописных политик в примере нет.
  policy_files_dir = null

  policies = {
    "demo-app-ro" = {
      read_paths = ["apps/demo/prod"]
    }

    # Полный доступ, включая безвозвратное удаление.
    "demo-admin" = {
      write_paths   = ["apps/demo/*"]
      allow_destroy = true
    }
  }

  clusters = {
    "demo" = {
      host    = "https://api.demo.example.tech:6443"
      ca_cert = var.cluster_ca_cert
    }
  }

  k8s_roles = {
    "demo" = {
      "demo-app" = {
        namespaces       = ["demo"]
        service_accounts = ["demo-app"]
        policies         = ["demo-app-ro"]
        # Vault валидирует логин самим клиентским JWT (reviewer'а модуль не
        # настраивает) — под должен проекцировать токен с этой аудиторией.
        audience = "https://vault.example.tech"
      }
    }
  }

  approle_roles = {
    "demo-ci" = {
      policies      = ["demo-app-ro"]
      secret_id_ttl = 600
    }
  }
}

output "kubernetes_roles" {
  value = module.access.kubernetes_roles
}

output "approle_role_ids" {
  value = module.access.approle_role_ids
}
