locals {
  kv_v2 = var.kv_version == 2

  ############################################################################
  # Сервис = одна политика + одна роль под тем же именем. Разложим его на те же
  # два описания, что принимают policies и jwt_roles, — дальше код общий.
  ############################################################################

  service_policy_specs = {
    for name, s in var.services : name => {
      read_paths            = s.read_paths
      write_paths           = s.write_paths
      list_paths            = s.list_paths
      allow_destroy         = s.allow_destroy
      extra_rules           = s.extra_rules
      path_capabilities     = s.path_capabilities
      raw_path_capabilities = s.raw_path_capabilities
      mounts                = s.mounts
    }
  }

  service_jwt_roles = {
    for name, s in var.services : name => {
      policies                     = concat([name], s.extra_policies)
      role_type                    = s.role_type
      user_claim                   = s.user_claim
      bound_audiences              = s.bound_audiences == null ? var.default_bound_audiences : s.bound_audiences
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
      token_period                 = s.token_period
      token_no_default_policy      = s.token_no_default_policy
      token_bound_cidrs            = s.token_bound_cidrs
    }
  }

  policy_specs = merge({
    for name, p in var.policies : name => {
      read_paths            = p.read_paths
      write_paths           = p.write_paths
      list_paths            = p.list_paths
      allow_destroy         = p.allow_destroy
      extra_rules           = p.extra_rules
      path_capabilities     = p.path_capabilities
      raw_path_capabilities = p.raw_path_capabilities
      mounts                = p.mounts
    }
  }, local.service_policy_specs)

  all_jwt_roles = merge({
    for name, r in var.jwt_roles : name => {
      policies                     = r.policies
      role_type                    = r.role_type
      user_claim                   = r.user_claim
      bound_audiences              = r.bound_audiences == null ? var.default_bound_audiences : r.bound_audiences
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
      token_period                 = r.token_period
      token_no_default_policy      = r.token_no_default_policy
      token_bound_cidrs            = r.token_bound_cidrs
    }
  }, local.service_jwt_roles)

  ############################################################################
  # Правила политики
  #
  # Политика раскладывается на блоки «маунт + версия KV»: верхнеуровневые пути
  # относятся к kv_mount, каждый элемент mounts — к своему. Так одна политика
  # может смешивать пути из kv1 и kv2, и код при этом остаётся общим.
  ############################################################################

  policy_blocks = {
    for name, p in local.policy_specs : name => concat(
      [{
        mount             = var.kv_mount
        v2                = local.kv_v2
        read_paths        = p.read_paths
        write_paths       = p.write_paths
        list_paths        = p.list_paths
        allow_destroy     = p.allow_destroy
        path_capabilities = p.path_capabilities
      }],
      [
        for m in p.mounts : {
          mount             = m.mount
          v2                = coalesce(m.kv_version, var.kv_version) == 2
          read_paths        = m.read_paths
          write_paths       = m.write_paths
          list_paths        = m.list_paths
          allow_destroy     = m.allow_destroy
          path_capabilities = m.path_capabilities
        }
      ],
    )
  }

  policy_rules_raw = {
    for name, blocks in local.policy_blocks : name => concat(
      [
        for path, caps in local.policy_specs[name].raw_path_capabilities : {
          path         = path
          capabilities = caps
          note         = ""
        }
      ],
      flatten([
        for b in blocks : concat(
          # --- чтение ---
          flatten([
            for path in b.read_paths : b.v2 ? [
              {
                path         = "${b.mount}/data/${path}"
                capabilities = ["read"]
                note         = ""
              },
              {
                path         = "${b.mount}/metadata/${path}"
                capabilities = ["read", "list"]
                note         = "версии и обход дерева"
              },
              ] : [
              {
                path         = "${b.mount}/${path}"
                capabilities = ["read"]
                note         = ""
              },
            ]
          ]),

          # --- запись ---
          flatten([
            for path in b.write_paths : b.v2 ? concat([
              {
                path = "${b.mount}/data/${path}"
                # delete здесь — мягкое удаление последней версии, а не стирание:
                # `vault kv delete <path>` без -versions шлёт DELETE на data/, и
                # без этого права самая обычная команда удаления отвечала 403,
                # хотя delete/<path> модуль выдавал. Проверено на живом Vault:
                # после такого delete секрет скрыт, undelete возвращает прежнее
                # значение, а destroy остаётся запрещённым.
                capabilities = ["create", "read", "update", "patch", "delete"]
                note         = ""
              },
              {
                path = "${b.mount}/metadata/${path}"
                # Запись в metadata писателю НЕ выдаётся: create/update на
                # metadata позволяют `vault kv metadata put -max-versions=1`,
                # после чего следующая запись безвозвратно вытесняет всю
                # историю — обход allow_destroy = false (проверено на живом
                # Vault: версии исчезают из metadata целиком). Кому нужны
                # custom-metadata — точечно через raw_path_capabilities.
                capabilities = concat(
                  ["read", "list"],
                  b.allow_destroy ? ["create", "update", "delete"] : [],
                )
                note = b.allow_destroy ? "delete по metadata сносит все версии секрета" : ""
              },
              {
                path         = "${b.mount}/delete/${path}"
                capabilities = ["update"]
                note         = "мягкое удаление версии"
              },
              {
                path         = "${b.mount}/undelete/${path}"
                capabilities = ["update"]
                note         = "откат мягкого удаления"
              },
              ], b.allow_destroy ? [
              {
                path         = "${b.mount}/destroy/${path}"
                capabilities = ["update"]
                note         = "безвозвратное стирание версии"
              },
              ] : []) : [
              {
                path = "${b.mount}/${path}"
                capabilities = concat(
                  ["create", "read", "update", "list"],
                  # В KV v1 удаление сразу безвозвратное: мягкого удаления там нет.
                  b.allow_destroy ? ["delete"] : [],
                )
                note = ""
              },
            ]
          ]),

          # --- только обход дерева ---
          flatten([
            for path in b.list_paths : b.v2 ? [
              {
                path         = "${b.mount}/metadata/${path}"
                capabilities = ["list"]
                note         = ""
              },
              ] : [
              {
                path         = "${b.mount}/${path}"
                capabilities = ["list"]
                note         = ""
              },
            ]
          ]),

          # --- точный набор прав ---
          [
            for path, caps in b.path_capabilities : {
              path         = b.v2 ? "${b.mount}/data/${path}" : "${b.mount}/${path}"
              capabilities = caps
              note         = ""
            }
          ],
        )
      ]),
    )
  }

  # Все права, которые Vault принимает в path-строфе (проверено на живом
  # Vault 2.0.3, включая subscribe и recover). Список один на модуль: он же —
  # белый список для validation-блоков variables.tf (Terraform >= 1.9 разрешает
  # ссылаться на locals из validation), он же — канонический порядок прав
  # в выводе, чтобы политика не «дрожала» в diff от перестановки.
  valid_capabilities = ["create", "read", "update", "patch", "delete", "list", "subscribe", "recover", "sudo", "deny"]

  # Один путь = одна path-строфа. Vault из двух строф на один путь оставляет
  # последнюю, поэтому пересечение read_paths / write_paths / list_paths молча
  # урезало бы права — вместо этого объединяем capabilities.
  policy_rules = {
    for name, rules in local.policy_rules_raw : name => [
      for p in distinct([for r in rules : r.path]) : {
        path = p
        capabilities = [
          for c in local.valid_capabilities : c
          if contains(distinct(flatten([for r in rules : r.capabilities if r.path == p])), c)
        ]
        note = join("; ", compact(distinct([for r in rules : r.note if r.path == p])))
      }
    ]
  }

  # Путь, на котором deny смешан с другими правами. Deny в Vault побеждает всё,
  # то есть право, добавленное через *_paths, молча превращается в полный запрет —
  # такой конфликт требуем разрешить явно (precondition в policies.tf).
  # Ловится только слияние на ОДНОМ пути: deny на более специфичном пути при
  # гранте на глобе — легальный приём, он живёт в разных строфах.
  deny_conflicts = {
    for name, rules in local.policy_rules : name => [
      for r in rules : r.path if contains(r.capabilities, "deny") && length(r.capabilities) > 1
    ]
  }

  # Шапка политики: какие маунты и каких версий в неё попали. Для смешанной
  # политики одной версии в заголовке уже не хватает. Маунт без единого правила
  # (политика только из raw_path_capabilities / extra_rules) в шапку не попадает.
  policy_mounts_note = {
    for name, blocks in local.policy_blocks : name => join(", ", [
      for b in blocks : "${b.mount} (kv${b.v2 ? 2 : 1})"
      if length(b.read_paths) + length(b.write_paths) + length(b.list_paths) + length(b.path_capabilities) > 0
    ])
  }

  generated_policies = {
    for name, p in local.policy_specs : name => templatefile("${path.module}/templates/kv_policy.hcl.tftpl", {
      name        = name
      mounts_note = local.policy_mounts_note[name]
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
