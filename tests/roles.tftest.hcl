# Роли: что ролям вообще удаётся спланировать. Главный смысл файла — регрессия
# на 1.7.0, где auth_approle.tf читал поля, которых не было в approle_roles:
# любой конфиг с непустым approle_roles падал на plan, а terraform validate это
# не ловил (Terraform не типизирует each.value статически).

provider "vault" {
  address          = "http://127.0.0.1:8200"
  token            = "dummy"
  skip_child_token = true
}

variables {
  kv_mount         = "secret"
  kv_version       = 2
  policy_files_dir = null
}

run "approle_plans" {
  command = plan

  variables {
    policies = { "ci-ro" = { read_paths = ["apps/ci"] } }
    approle_roles = {
      "ci" = {
        policies      = ["ci-ro"]
        secret_id_ttl = 600
      }
    }
  }

  assert {
    condition     = length(vault_auth_backend.approle) == 1
    error_message = "при непустом approle_roles бэкенд должен создаваться"
  }

  assert {
    condition     = vault_approle_auth_backend_role.this["ci"].backend == "approle"
    error_message = "роль должна лечь под approle_path"
  }

  assert {
    condition     = vault_approle_auth_backend_role.this["ci"].token_ttl == 600
    error_message = "не подставился default_token_ttl"
  }
}

# Периодический токен для AppRole: до 2.0 поля token_period просто не было
# в переменной, хотя ресурс его читал.
run "approle_periodic_token" {
  command = plan

  variables {
    approle_roles = {
      "ci" = {
        policies               = ["default"]
        token_period           = 86400
        token_ttl              = 0
        token_max_ttl          = 0
        token_explicit_max_ttl = 0
      }
    }
  }

  assert {
    condition     = vault_approle_auth_backend_role.this["ci"].token_period == 86400
    error_message = "token_period должен доезжать до ресурса"
  }

  assert {
    condition     = vault_approle_auth_backend_role.this["ci"].token_no_default_policy == false
    error_message = "token_no_default_policy должен доезжать до ресурса"
  }
}

# manage_approle_backend = false — бэкенд уже поднят, роли всё равно ложатся.
run "approle_backend_not_managed" {
  command = plan

  variables {
    manage_approle_backend = false
    approle_roles = {
      "ci" = { policies = ["default"] }
    }
  }

  assert {
    condition     = length(vault_auth_backend.approle) == 0
    error_message = "при manage_approle_backend = false бэкенд создаваться не должен"
  }

  assert {
    condition     = vault_approle_auth_backend_role.this["ci"].backend == "approle"
    error_message = "роль должна лечь под существующий бэкенд по approle_path"
  }

  assert {
    condition     = output.approle_login_path == "auth/approle/login"
    error_message = "approle_login_path не должен зависеть от того, управляем ли мы бэкендом"
  }
}

# Одна запись services = политика + JWT-роль под тем же именем.
run "service_creates_policy_and_role" {
  command = plan

  variables {
    default_bound_audiences = ["https://vault.example.internal"]
    services = {
      "billing" = {
        read_paths     = ["apps/billing/prod"]
        extra_policies = ["shared-ro"]
      }
    }
    external_policies = ["shared-ro"]
  }

  assert {
    condition     = strcontains(vault_policy.this["billing"].policy, "path \"secret/data/apps/billing/prod\"")
    error_message = "services должен порождать политику из своих путей"
  }

  assert {
    condition     = vault_jwt_auth_backend_role.this["billing"].token_policies == toset(["billing", "shared-ro"])
    error_message = "роль должна получить одноимённую политику плюс extra_policies"
  }

  # Аудитория не задана в записи — берётся общая.
  assert {
    condition     = vault_jwt_auth_backend_role.this["billing"].bound_audiences == toset(["https://vault.example.internal"])
    error_message = "bound_audiences должен наследоваться из default_bound_audiences"
  }
}

# bound_audiences = [] — сознательный отказ от проверки aud; ограничением
# тогда служат bound_claims.
run "empty_bound_audiences_opts_out" {
  command = plan

  variables {
    default_bound_audiences = ["https://vault.example.internal"]
    jwt_roles = {
      "r" = {
        policies        = ["default"]
        bound_audiences = []
        bound_claims    = { project_id = "42" }
      }
    }
  }

  assert {
    condition     = vault_jwt_auth_backend_role.this["r"].bound_audiences == null
    error_message = "пустой список должен снимать ограничение, а не наследовать общий"
  }
}

run "kubernetes_roles_and_outputs" {
  command = plan

  variables {
    clusters = {
      "prod" = { host = "https://api.prod:6443", auth_path = "kubernetes/prod", disable_local_ca_jwt = false }
    }
    policies = { "app-ro" = { read_paths = ["apps/app"] } }
    k8s_roles = {
      "prod" = {
        "app" = {
          namespaces       = ["app"]
          service_accounts = ["app"]
          policies         = ["app-ro"]
        }
      }
    }
  }

  assert {
    condition     = output.kubernetes_auth_paths["prod"] == "kubernetes/prod"
    error_message = "путь auth-маунта кластера собран неверно"
  }

  assert {
    condition     = output.kubernetes_roles["prod/app"].login_path == "auth/kubernetes/prod/login"
    error_message = "login_path собран неверно"
  }

  # null → общий список; порядок не важен, провайдер хранит множеством.
  assert {
    condition     = vault_kubernetes_auth_backend_role.this["prod/app"].token_bound_cidrs == toset(["127.0.0.0/8", "10.0.0.0/8"])
    error_message = "token_bound_cidrs должен наследоваться из default_token_bound_cidrs"
  }
}

run "token_bound_cidrs_opt_out" {
  command = plan

  variables {
    jwt_roles = {
      "r" = {
        policies          = ["default"]
        bound_subject     = "sub"
        token_bound_cidrs = []
      }
    }
  }

  # Пустой список провайдер отдаёт как null — то есть «ограничения нет».
  # Главное, что он не наследует default_token_bound_cidrs.
  assert {
    condition     = vault_jwt_auth_backend_role.this["r"].token_bound_cidrs == null
    error_message = "пустой список должен снимать ограничение по сети, а не наследовать общее"
  }
}
