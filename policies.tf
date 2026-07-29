resource "vault_policy" "this" {
  for_each = local.all_policies

  name   = each.key
  policy = each.value

  lifecycle {
    # Не trimspace() != "": у сгенерированной политики всегда есть шапка-
    # комментарий, поэтому «пустой» она не бывает никогда, и проверка ловила
    # только raw_policies и файловые. Считаем path-строфы: политика без единой
    # из них — хоть с комментариями, хоть без — не даёт вообще ничего, а Vault
    # принимает её молча. Регексп якорится на начало строки, чтобы «path "»
    # внутри комментария не сходило за правило.
    precondition {
      condition     = length(regexall("(?m)^[ \t]*path[ \t]+\"", each.value)) > 0
      error_message = "Политика ${each.key} не содержит ни одной path-строфы — Vault примет её и молча лишит прав всех, кто на неё ссылается."
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
