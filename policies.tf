resource "vault_policy" "this" {
  for_each = local.all_policies

  name   = each.key
  policy = each.value

  lifecycle {
    precondition {
      condition     = trimspace(each.value) != ""
      error_message = "Политика ${each.key} отрендерилась пустой — Vault примет её и молча лишит прав всех, кто на неё ссылается."
    }

    precondition {
      condition     = lower(each.key) == each.key
      error_message = "Имя политики ${each.key} должно быть в нижнем регистре: Vault приводит имена к lowercase, иначе Terraform будет вечно видеть diff."
    }
  }
}

# Одно имя из нескольких источников (services / policies / policy_files_dir /
# raw_policies) merge() схлопнул бы молча, оставив последний.
check "policy_name_collisions" {
  assert {
    condition = length(local.duplicate_policy_names) == 0
    error_message = format(
      "Имена политик заданы больше чем в одном источнике: %s",
      join(", ", local.duplicate_policy_names)
    )
  }
}

check "jwt_role_name_collisions" {
  assert {
    condition = length(local.duplicate_jwt_role_names) == 0
    error_message = format(
      "Имена JWT-ролей заданы и в services, и в jwt_roles: %s",
      join(", ", local.duplicate_jwt_role_names)
    )
  }
}

# Пересечение read_paths / write_paths / list_paths специально НЕ запрещено:
# правила складываются по путям (см. local.policy_rules), поэтому одна
# path-строфа на путь и объединённые capabilities. Раньше здесь стоял check,
# ловивший пересечение, — он больше не нужен.
