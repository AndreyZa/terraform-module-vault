# Проверки, которые должны валить plan. Каждый run — регрессия на конкретную
# дыру, найденную при аудите 2.0: раньше все эти конфиги планировались успешно.

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

##############################################################################
# Опечатка в capability. Неизвестное право не отбрасывалось с ошибкой, а молча
# выпадало при сборке правил — на выходе получалась строфа capabilities = [],
# которую Vault принимает и которая не даёт ничего.
##############################################################################

run "bad_capability_in_policies" {
  command = plan

  variables {
    policies = { "p" = { path_capabilities = { "a" = ["raed"] } } }
  }

  expect_failures = [var.policies]
}

run "bad_capability_in_policies_raw" {
  command = plan

  variables {
    policies = { "p" = { raw_path_capabilities = { "sys/mounts" = ["reed"] } } }
  }

  expect_failures = [var.policies]
}

run "bad_capability_in_policies_mounts" {
  command = plan

  variables {
    policies = {
      "p" = { mounts = [{ mount = "other", path_capabilities = { "b" = ["nonsense"] } }] }
    }
  }

  expect_failures = [var.policies]
}

run "bad_capability_in_services" {
  command = plan

  variables {
    services = { "s" = { path_capabilities = { "a" = ["raed"] }, bound_subject = "sub" } }
  }

  expect_failures = [var.services]
}

run "bad_capability_in_services_mounts" {
  command = plan

  variables {
    services = {
      "s" = {
        bound_subject = "sub"
        mounts        = [{ mount = "other", path_capabilities = { "b" = ["nonsense"] } }]
      }
    }
  }

  expect_failures = [var.services]
}

##############################################################################
# Версия KV во вложенном маунте. Верхнеуровневый kv_version валидировался,
# вложенный — нет, и любое значение кроме 2 молча трактовалось как v1.
##############################################################################

run "bad_kv_version_in_policies_mounts" {
  command = plan

  variables {
    policies = {
      "p" = { mounts = [{ mount = "other", kv_version = 9, read_paths = ["a"] }] }
    }
  }

  expect_failures = [var.policies]
}

run "bad_kv_version_in_services_mounts" {
  command = plan

  variables {
    services = {
      "s" = {
        bound_subject = "sub"
        mounts        = [{ mount = "other", kv_version = 9, read_paths = ["a"] }]
      }
    }
  }

  expect_failures = [var.services]
}

##############################################################################
# Имя маунта. Пустая строка слэшей не содержит, поэтому проверку на них
# проходила, а пути вырождались в "/data/…" — Vault принимает и не матчит.
##############################################################################

run "empty_kv_mount" {
  command = plan

  variables {
    kv_mount = ""
    policies = { "p" = { read_paths = ["a"] } }
  }

  expect_failures = [var.kv_mount]
}

run "empty_mount_in_policies_mounts" {
  command = plan

  variables {
    policies = { "p" = { mounts = [{ mount = "", read_paths = ["a"] }] } }
  }

  expect_failures = [var.policies]
}

run "slashed_mount_in_services_mounts" {
  command = plan

  variables {
    services = {
      "s" = {
        bound_subject = "sub"
        mounts        = [{ mount = "/legacy/", read_paths = ["a"] }]
      }
    }
  }

  expect_failures = [var.services]
}

##############################################################################
# Политика без единой path-строфы. Vault такую принимает молча, а прав она
# не даёт. Шапка-комментарий у сгенерированной политики есть всегда, поэтому
# проверкой на непустое тело этот случай не ловился.
##############################################################################

run "generated_policy_without_rules" {
  command = plan

  variables {
    policies = { "p" = {} }
  }

  expect_failures = [vault_policy.this["p"]]
}

run "raw_policy_with_only_comments" {
  command = plan

  variables {
    raw_policies = { "p" = "# всё выписали, честно\n# правда\n" }
  }

  expect_failures = [vault_policy.this["p"]]
}

# Обратная сторона: комментарий со словом path не должен сходить за правило,
# а нормальная политика — проходить.
run "commented_out_path_is_not_a_rule" {
  command = plan

  variables {
    raw_policies = { "p" = "# path \"secret/a\" { capabilities = [\"read\"] }\n" }
  }

  expect_failures = [vault_policy.this["p"]]
}

##############################################################################
# Коллизии имён. До 2.0 это был check — предупреждение, которое apply не
# останавливало: побеждал последний источник, остальные определения терялись.
##############################################################################

run "policy_name_from_two_sources" {
  command = plan

  variables {
    policies     = { "dup" = { read_paths = ["a"] } }
    raw_policies = { "dup" = "path \"secret/data/b\" { capabilities = [\"read\"] }" }
  }

  expect_failures = [vault_policy.this["dup"]]
}

run "jwt_role_name_from_two_sources" {
  command = plan

  variables {
    services  = { "dup" = { read_paths = ["a"], bound_subject = "sub" } }
    jwt_roles = { "dup" = { policies = ["dup"], bound_subject = "sub" } }
  }

  expect_failures = [vault_jwt_auth_backend_role.this["dup"]]
}

##############################################################################
# Ссылка на несуществующую политику: Vault создаёт такую роль молча, логин
# проходит, прав нет.
##############################################################################

run "role_refers_to_unknown_policy" {
  command = plan

  variables {
    jwt_roles = { "r" = { policies = ["missing"], bound_subject = "sub" } }
  }

  expect_failures = [vault_jwt_auth_backend_role.this["r"]]
}

run "external_policies_allow_the_reference" {
  command = plan

  variables {
    external_policies = ["managed-elsewhere"]
    jwt_roles         = { "r" = { policies = ["managed-elsewhere"], bound_subject = "sub" } }
  }

  assert {
    condition     = vault_jwt_auth_backend_role.this["r"].token_policies == toset(["managed-elsewhere"])
    error_message = "политика из external_policies должна проходить проверку и попадать в роль"
  }
}

run "unbounded_jwt_role" {
  command = plan

  variables {
    jwt_roles = { "r" = { policies = ["default"] } }
  }

  expect_failures = [vault_jwt_auth_backend_role.this["r"]]
}

##############################################################################
# TTL-проверки. До 2.0 они были только у JWT-ролей, хотя те же поля есть
# у kubernetes- и approle-ролей.
##############################################################################

run "k8s_role_ttl_above_explicit_max" {
  command = plan

  variables {
    clusters = {
      "c" = { host = "https://api.c:6443", disable_local_ca_jwt = false }
    }
    k8s_roles = {
      "c" = {
        "r" = {
          namespaces             = ["ns"]
          service_accounts       = ["sa"]
          policies               = ["default"]
          token_ttl              = 3600
          token_explicit_max_ttl = 900
        }
      }
    }
  }

  expect_failures = [vault_kubernetes_auth_backend_role.this["c/r"]]
}

run "k8s_role_period_with_explicit_max" {
  command = plan

  variables {
    clusters = {
      "c" = { host = "https://api.c:6443", disable_local_ca_jwt = false }
    }
    k8s_roles = {
      "c" = {
        "r" = {
          namespaces       = ["ns"]
          service_accounts = ["sa"]
          policies         = ["default"]
          token_period     = 86400
        }
      }
    }
  }

  expect_failures = [vault_kubernetes_auth_backend_role.this["c/r"]]
}

# token_max_ttl прижимает периодический токен ничуть не слабее жёсткого
# потолка. Проверено на живом Vault: при period = 86400 и max_ttl = 900
# выдаётся ttl = 899, и renew его не поднимает.
run "k8s_role_period_with_max_ttl" {
  command = plan

  variables {
    clusters = {
      "c" = { host = "https://api.c:6443", disable_local_ca_jwt = false }
    }
    k8s_roles = {
      "c" = {
        "r" = {
          namespaces             = ["ns"]
          service_accounts       = ["sa"]
          policies               = ["default"]
          token_period           = 86400
          token_explicit_max_ttl = 0
          token_max_ttl          = 900
        }
      }
    }
  }

  expect_failures = [vault_kubernetes_auth_backend_role.this["c/r"]]
}

run "jwt_role_period_with_max_ttl" {
  command = plan

  variables {
    jwt_roles = {
      "r" = {
        policies               = ["default"]
        bound_subject          = "sub"
        token_period           = 86400
        token_explicit_max_ttl = 0
        token_max_ttl          = 900
      }
    }
  }

  expect_failures = [vault_jwt_auth_backend_role.this["r"]]
}

run "approle_period_with_max_ttl" {
  command = plan

  variables {
    approle_roles = {
      "ci" = {
        policies               = ["default"]
        token_period           = 86400
        token_explicit_max_ttl = 0
        token_max_ttl          = 900
      }
    }
  }

  expect_failures = [vault_approle_auth_backend_role.this["ci"]]
}

run "approle_ttl_above_explicit_max" {
  command = plan

  variables {
    approle_roles = {
      "ci" = {
        policies               = ["default"]
        token_ttl              = 3600
        token_explicit_max_ttl = 900
      }
    }
  }

  expect_failures = [vault_approle_auth_backend_role.this["ci"]]
}

run "approle_period_with_explicit_max" {
  command = plan

  variables {
    approle_roles = {
      "ci" = {
        policies     = ["default"]
        token_period = 86400
      }
    }
  }

  expect_failures = [vault_approle_auth_backend_role.this["ci"]]
}
