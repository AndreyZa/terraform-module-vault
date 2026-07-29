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

    # Одно имя из нескольких источников (services / policies / policy_files_dir /
    # raw_policies) merge() схлопывает молча, оставляя последний.
    # До 2.0 здесь стоял check — то есть предупреждение, которое apply не
    # останавливало: лишние определения терялись, а plan показывал успех.
    precondition {
      condition = !contains(local.duplicate_policy_names, each.key)
      error_message = format(
        "Имя политики %s задано больше чем в одном источнике (%s). Останется только последний — остальные определения потеряются молча; переименуйте лишние.",
        each.key,
        join(", ", [for src, names in local.policy_sources : src if contains(names, each.key)])
      )
    }
  }
}

# Пересечение read_paths / write_paths / list_paths специально НЕ запрещено:
# правила складываются по путям (см. local.policy_rules), поэтому одна
# path-строфа на путь и объединённые capabilities. Раньше здесь стоял check,
# ловивший пересечение, — он больше не нужен.
