# Раскладка путей — главная работа модуля и то, что нельзя проверить глазами:
# ошибка здесь даёт синтаксически верную политику, которая не даёт прав.
#
# Vault не нужен: все run'ы — command = plan, тело политики известно до apply.

provider "vault" {
  address = "http://127.0.0.1:8200"
  token   = "dummy"
  # Иначе провайдер при конфигурации полезет за дочерним токеном в живой Vault.
  skip_child_token = true
}

variables {
  kv_mount         = "secret"
  policy_files_dir = null
}

run "kv1_read_write_list" {
  command = plan

  variables {
    kv_version = 1
    policies = {
      "p" = {
        read_paths  = ["ro"]
        write_paths = ["rw"]
        list_paths  = ["ls"]
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/ro\" {\n  capabilities = [\"read\"]\n}")
    error_message = "v1 read: ожидался secret/ro с [read]"
  }

  # В v1 мягкого удаления нет, поэтому write без allow_destroy не даёт delete.
  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/rw\" {\n  capabilities = [\"create\", \"read\", \"update\", \"list\"]\n}")
    error_message = "v1 write: ожидался secret/rw с [create, read, update, list] и без delete"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/ls\" {\n  capabilities = [\"list\"]\n}")
    error_message = "v1 list: ожидался secret/ls с [list]"
  }

  # Префикса data/ в v1 быть не должно — это и есть «политика есть, а 403».
  assert {
    condition     = !strcontains(vault_policy.this["p"].policy, "secret/data/")
    error_message = "v1: в политику просочился путь v2 (secret/data/…)"
  }
}

run "kv2_read_write_list" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        read_paths  = ["ro"]
        write_paths = ["rw"]
        list_paths  = ["ls"]
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/data/ro\" {\n  capabilities = [\"read\"]\n}")
    error_message = "v2 read: ожидался secret/data/ro с [read]"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/metadata/ro\" {\n  capabilities = [\"read\", \"list\"]\n}")
    error_message = "v2 read: ожидался secret/metadata/ro с [read, list]"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/data/rw\" {\n  capabilities = [\"create\", \"read\", \"update\", \"patch\"]\n}")
    error_message = "v2 write: ожидался secret/data/rw с [create, read, update, patch]"
  }

  # Мягкое удаление входит в write, безвозвратное — нет.
  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/delete/rw\" {\n  capabilities = [\"update\"]\n}")
    error_message = "v2 write: ожидался secret/delete/rw (мягкое удаление версии)"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/undelete/rw\" {\n  capabilities = [\"update\"]\n}")
    error_message = "v2 write: ожидался secret/undelete/rw (откат мягкого удаления)"
  }

  assert {
    condition     = !strcontains(vault_policy.this["p"].policy, "secret/destroy/")
    error_message = "v2 write без allow_destroy не должен давать destroy/"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/metadata/ls\" {\n  capabilities = [\"list\"]\n}")
    error_message = "v2 list: ожидался secret/metadata/ls с [list]"
  }
}

run "allow_destroy_v1" {
  command = plan

  variables {
    kv_version = 1
    policies = {
      "p" = {
        write_paths   = ["rw"]
        allow_destroy = true
      }
    }
  }

  # В v1 delete сразу безвозвратен, отдельного destroy/ нет.
  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/rw\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}")
    error_message = "v1 allow_destroy: ожидался delete в наборе прав на secret/rw"
  }
}

run "allow_destroy_v2" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        write_paths   = ["rw"]
        allow_destroy = true
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/destroy/rw\" {\n  capabilities = [\"update\"]\n}")
    error_message = "v2 allow_destroy: ожидался secret/destroy/rw"
  }

  # delete по metadata сносит все версии секрета — только по allow_destroy.
  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/metadata/rw\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}")
    error_message = "v2 allow_destroy: ожидался delete по secret/metadata/rw"
  }
}

# Пересечение наборов путей — из двух path-строф на один путь Vault оставляет
# последнюю, поэтому модуль обязан слить их в одну с объединёнными правами.
run "overlapping_paths_merge_into_one_stanza" {
  command = plan

  variables {
    kv_version = 1
    policies = {
      "p" = {
        read_paths  = ["shared"]
        write_paths = ["shared"]
        list_paths  = ["shared"]
      }
    }
  }

  assert {
    condition     = length(regexall("path \"secret/shared\"", vault_policy.this["p"].policy)) == 1
    error_message = "на один путь должна приходиться ровно одна path-строфа"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/shared\" {\n  capabilities = [\"create\", \"read\", \"update\", \"list\"]\n}")
    error_message = "права на пересекающихся путях должны объединяться в каноническом порядке"
  }
}

run "path_capabilities_land_on_data_path" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        path_capabilities = { "writeonly" = ["create", "update"] }
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/data/writeonly\" {\n  capabilities = [\"create\", \"update\"]\n}")
    error_message = "path_capabilities должны ложиться на путь данных с учётом версии KV"
  }
}

# raw_path_capabilities — единственное поле, которое не трогает ни префикс
# маунта, ни версию KV.
run "raw_path_capabilities_are_verbatim" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        raw_path_capabilities = { "auth/token/create" = ["update"] }
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"auth/token/create\" {\n  capabilities = [\"update\"]\n}")
    error_message = "raw_path_capabilities должны попадать в политику как есть"
  }

  assert {
    condition     = !strcontains(vault_policy.this["p"].policy, "secret/data/auth")
    error_message = "raw_path_capabilities не должны получать префикс маунта"
  }
}

run "mixed_mounts_and_versions_in_one_policy" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        read_paths = ["new"]
        mounts = [{
          mount      = "legacy"
          kv_version = 1
          read_paths = ["old"]
        }]
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"secret/data/new\" {\n  capabilities = [\"read\"]\n}")
    error_message = "верхнеуровневые пути должны раскрываться по общему kv_version"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"legacy/old\" {\n  capabilities = [\"read\"]\n}")
    error_message = "mounts[*] со своим kv_version должен раскрываться по своей версии"
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "# Маунты: secret (kv2), legacy (kv1).")
    error_message = "в шапке смешанной политики должны быть перечислены оба маунта с версиями"
  }
}

# kv_version внутри mounts необязателен. Отдельный прогон, потому что null здесь
# — самый обычный случай, а не краевой: на Terraform 1.9 валидация вида
# "m.kv_version == null || contains(...)" на нём падала (оба операнда || всегда
# вычисляются, а contains(..., null) — ошибка).
run "mount_without_kv_version_inherits_the_general_one" {
  command = plan

  variables {
    kv_version = 2
    policies = {
      "p" = {
        mounts = [{
          mount      = "other"
          read_paths = ["a"]
        }]
      }
    }
  }

  assert {
    condition     = strcontains(vault_policy.this["p"].policy, "path \"other/data/a\" {\n  capabilities = [\"read\"]\n}")
    error_message = "mounts без kv_version должен раскрываться по общему kv_version"
  }
}

# Пустая политика применяется без ошибок и молча лишает прав всех, кто на неё
# ссылается, — precondition обязан её поймать.
run "empty_policy_is_rejected" {
  command = plan

  variables {
    kv_version   = 1
    raw_policies = { "p" = "   \n" }
  }

  expect_failures = [vault_policy.this["p"]]
}

run "uppercase_policy_name_is_rejected" {
  command = plan

  variables {
    kv_version = 1
    policies   = { "Caps" = { read_paths = ["ro"] } }
  }

  expect_failures = [vault_policy.this["Caps"]]
}
