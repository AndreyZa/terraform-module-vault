locals {
  kv_v2 = var.kv_version == 2

  ############################################################################
  # Сервис = одна политика + одна роль под тем же именем. Разложим его на те же
  # два описания, что принимают policies и jwt_roles, — дальше код общий.
  ############################################################################

  service_policy_specs = {
    for name, s in var.services : name => {
      read_paths    = s.read_paths
      write_paths   = s.write_paths
      list_paths    = s.list_paths
      allow_destroy = s.allow_destroy
      extra_rules   = s.extra_rules
    }
  }

  service_jwt_roles = {
    for name, s in var.services : name => {
      policies                     = concat([name], s.extra_policies)
      role_type                    = s.role_type
      user_claim                   = s.user_claim
      bound_audiences              = s.bound_audiences
      bound_subject                = s.bound_subject
      bound_claims                 = s.bound_claims
      bound_claims_type            = s.bound_claims_type
      claim_mappings               = s.claim_mappings
      groups_claim                 = s.groups_claim
      allowed_redirect_uris        = s.allowed_redirect_uris
      clock_skew_leeway            = s.clock_skew_leeway
      expiration_leeway            = s.expiration_leeway
      not_before_leeway            = s.not_before_leeway
      disable_bound_claims_parsing = s.disable_bound_claims_parsing
      token_ttl                    = s.token_ttl
      token_max_ttl                = s.token_max_ttl
      token_explicit_max_ttl       = s.token_explicit_max_ttl
      token_bound_cidrs            = s.token_bound_cidrs
    }
  }

  policy_specs = merge({
    for name, p in var.policies : name => {
      read_paths    = p.read_paths
      write_paths   = p.write_paths
      list_paths    = p.list_paths
      allow_destroy = p.allow_destroy
      extra_rules   = p.extra_rules
    }
  }, local.service_policy_specs)

  all_jwt_roles = merge({
    for name, r in var.jwt_roles : name => {
      policies                     = r.policies
      role_type                    = r.role_type
      user_claim                   = r.user_claim
      bound_audiences              = r.bound_audiences
      bound_subject                = r.bound_subject
      bound_claims                 = r.bound_claims
      bound_claims_type            = r.bound_claims_type
      claim_mappings               = r.claim_mappings
      groups_claim                 = r.groups_claim
      allowed_redirect_uris        = r.allowed_redirect_uris
      clock_skew_leeway            = r.clock_skew_leeway
      expiration_leeway            = r.expiration_leeway
      not_before_leeway            = r.not_before_leeway
      disable_bound_claims_parsing = r.disable_bound_claims_parsing
      token_ttl                    = r.token_ttl
      token_max_ttl                = r.token_max_ttl
      token_explicit_max_ttl       = r.token_explicit_max_ttl
      token_bound_cidrs            = r.token_bound_cidrs
    }
  }, local.service_jwt_roles)

  ############################################################################
  # Правила политики
  #
  # Считаются здесь, а не в шаблоне: KV v1 и v2 живут в разных пространствах
  # путей (v1 — <mount>/<path>, v2 — <mount>/data/ + <mount>/metadata/),
  # и разводить это ветками внутри HCL-шаблона нечитаемо.
  ############################################################################

  policy_rules_raw = {
    for name, p in local.policy_specs : name => concat(
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

  # Порядок capabilities в выводе — канонический, чтобы политика не «дрожала»
  # в diff от перестановки прав.
  capability_order = ["create", "read", "update", "patch", "delete", "list", "sudo"]

  # Один путь = одна path-строфа. Vault из двух строф на один путь оставляет
  # последнюю, поэтому пересечение read_paths / write_paths / list_paths молча
  # урезало бы права — вместо этого объединяем capabilities.
  policy_rules = {
    for name, rules in local.policy_rules_raw : name => [
      for p in distinct([for r in rules : r.path]) : {
        path = p
        capabilities = [
          for c in local.capability_order : c
          if contains(distinct(flatten([for r in rules : r.capabilities if r.path == p])), c)
        ]
        note = join("; ", compact(distinct([for r in rules : r.note if r.path == p])))
      }
    ]
  }

  generated_policies = {
    for name, p in local.policy_specs : name => templatefile("${path.module}/templates/kv_policy.hcl.tftpl", {
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

  # Источники политик сливаются merge()'ем — имя, заданное дважды, молча
  # потерялось бы: побеждает последний источник.
  policy_sources = {
    "var.policies"     = keys(var.policies)
    "var.services"     = keys(var.services)
    "policy_files_dir" = keys(local.file_policies)
    "var.raw_policies" = keys(var.raw_policies)
  }

  duplicate_policy_names = [
    for n in distinct(concat(values(local.policy_sources)...)) : n
    if length([for src, names in local.policy_sources : src if contains(names, n)]) > 1
  ]

  duplicate_jwt_role_names = setintersection(keys(var.jwt_roles), keys(var.services))

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
