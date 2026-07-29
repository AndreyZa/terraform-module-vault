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

# Одно имя из двух источников (var.policies / policy_files_dir / var.raw_policies)
# merge() схлопнул бы молча, оставив последний.
check "policy_name_collisions" {
  assert {
    condition = length(local.duplicate_policy_names) == 0
    error_message = format(
      "Имена политик заданы больше чем в одном источнике: %s",
      join(", ", local.duplicate_policy_names)
    )
  }
}

# Путь, попавший и в read_paths, и в write_paths, даёт две path-строфы на один путь;
# Vault оставит последнюю, и права окажутся не теми, что написано.
check "policy_path_overlap" {
  assert {
    condition = alltrue([
      for name, p in var.policies :
      length(setintersection(toset(p.read_paths), toset(p.write_paths))) == 0
    ])
    error_message = format(
      "В политиках %s один и тот же путь указан и в read_paths, и в write_paths — оставить только write_paths (он включает чтение).",
      join(", ", [
        for name, p in var.policies :
        name if length(setintersection(toset(p.read_paths), toset(p.write_paths))) > 0
      ])
    )
  }
}
