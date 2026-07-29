locals {
  kv_v2 = var.kv_version == 2

  # Правила политики считаются здесь, а не в шаблоне: KV v1 и v2 живут в разных
  # пространствах путей (v1 — <mount>/<path>, v2 — <mount>/data/ + <mount>/metadata/),
  # и разводить это ветками внутри HCL-шаблона нечитаемо.
  policy_rules = {
    for name, p in var.policies : name => concat(
      # --- чтение ---
      flatten([
        for path in p.read_paths : local.kv_v2 ? [
          {
            path         = "${var.kv_mount}/data/${path}"
            capabilities = ["read"]
            note         = ""
          },
          {
            path         = "${var.kv_mount}/metadata/${path}"
            capabilities = ["read", "list"]
            note         = "версии и обход дерева"
          },
          ] : [
          {
            path         = "${var.kv_mount}/${path}"
            capabilities = ["read"]
            note         = ""
          },
        ]
      ]),

      # --- запись ---
      flatten([
        for path in p.write_paths : local.kv_v2 ? concat([
          {
            path         = "${var.kv_mount}/data/${path}"
            capabilities = ["create", "read", "update", "patch"]
            note         = ""
          },
          {
            path = "${var.kv_mount}/metadata/${path}"
            capabilities = concat(
              ["create", "read", "update", "list"],
              p.allow_destroy ? ["delete"] : [],
            )
            note = p.allow_destroy ? "delete по metadata сносит все версии секрета" : ""
          },
          {
            path         = "${var.kv_mount}/delete/${path}"
            capabilities = ["update"]
            note         = "мягкое удаление версии"
          },
          {
            path         = "${var.kv_mount}/undelete/${path}"
            capabilities = ["update"]
            note         = "откат мягкого удаления"
          },
          ], p.allow_destroy ? [
          {
            path         = "${var.kv_mount}/destroy/${path}"
            capabilities = ["update"]
            note         = "безвозвратное стирание версии"
          },
          ] : []) : [
          {
            path = "${var.kv_mount}/${path}"
            capabilities = concat(
              ["create", "read", "update", "list"],
              # В KV v1 удаление сразу безвозвратное: мягкого удаления там нет.
              p.allow_destroy ? ["delete"] : [],
            )
            note = ""
          },
        ]
      ]),

      # --- только обход дерева ---
      flatten([
        for path in p.list_paths : local.kv_v2 ? [
          {
            path         = "${var.kv_mount}/metadata/${path}"
            capabilities = ["list"]
            note         = ""
          },
          ] : [
          {
            path         = "${var.kv_mount}/${path}"
            capabilities = ["list"]
            note         = ""
          },
        ]
      ]),
    )
  }

  generated_policies = {
    for name, p in var.policies : name => templatefile("${path.module}/templates/kv_policy.hcl.tftpl", {
      name        = name
      kv_version  = var.kv_version
      rules       = local.policy_rules[name]
      extra_rules = p.extra_rules
    })
  }

  # Политики, написанные руками: <policy_files_dir>/<имя>.hcl → политика <имя>.
  # Каталог принадлежит вызывающему конфигу, поэтому path.root, а не path.module.
  policy_files_path = (
    var.policy_files_dir == null || var.policy_files_dir == ""
    ? null
    : "${path.root}/${var.policy_files_dir}"
  )

  file_policies = local.policy_files_path == null ? {} : {
    for f in fileset(local.policy_files_path, "*.hcl") :
    trimsuffix(f, ".hcl") => templatefile("${local.policy_files_path}/${f}", {
      mount      = var.kv_mount
      kv_version = var.kv_version
      # Префикс данных: "" для v1, "data/" для v2 — чтобы рукописная политика
      # не переписывалась при смене версии маунта.
      data_prefix     = local.kv_v2 ? "data/" : ""
      metadata_prefix = local.kv_v2 ? "metadata/" : ""
    })
  }

  all_policies = merge(local.generated_policies, local.file_policies, var.raw_policies)

  # Три источника политик сливаются merge()'ем — имя, заданное дважды, молча
  # потерялось бы: побеждает последний источник.
  policy_sources = {
    "var.policies"     = keys(local.generated_policies)
    "policy_files_dir" = keys(local.file_policies)
    "var.raw_policies" = keys(var.raw_policies)
  }

  duplicate_policy_names = [
    for n in distinct(concat(values(local.policy_sources)...)) : n
    if length([for src, names in local.policy_sources : src if contains(names, n)]) > 1
  ]

  # На что роли имеют право ссылаться: своё + чужое из external_policies + встроенные.
  known_policy_names = toset(concat(keys(local.all_policies), var.external_policies, ["default", "root"]))

  # Путь auth-маунта по каждому кластеру.
  cluster_auth_paths = {
    for name, c in var.clusters : name => coalesce(c.auth_path, "kubernetes/${name}")
  }

  # { "<кластер>" = { "<роль>" = {...} } } → плоская карта "<кластер>/<роль>".
  k8s_roles_flat = merge([
    for cluster, roles in var.k8s_roles : {
      for role, cfg in roles : "${cluster}/${role}" => merge(cfg, {
        cluster = cluster
        role    = role
      })
    }
  ]...)
}
