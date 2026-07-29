##############################################################################
# По отдельному kubernetes auth backend на кластер: у каждого свой API-сервер,
# свой CA и свой token reviewer, в один маунт они не складываются.
##############################################################################

resource "vault_auth_backend" "kubernetes" {
  for_each = var.clusters

  type        = "kubernetes"
  path        = local.cluster_auth_paths[each.key]
  description = trimspace(each.value.description) != "" ? each.value.description : "Kubernetes auth, кластер ${each.key} (managed by Terraform)"

  tune {
    default_lease_ttl = each.value.default_lease_ttl
    max_lease_ttl     = each.value.max_lease_ttl
    # Машинный auth — на форме логина в UI ему делать нечего.
    listing_visibility = "hidden"
  }

  # Смена path пересоздаёт маунт: все роли под ним исчезают, поды перестают логиниться
  # до следующего apply. Меняем осознанно и вместе с ролями.
}

resource "vault_kubernetes_auth_backend_config" "this" {
  for_each = var.clusters

  backend            = vault_auth_backend.kubernetes[each.key].path
  kubernetes_host    = each.value.host
  kubernetes_ca_cert = each.value.ca_cert != "" ? each.value.ca_cert : null
  token_reviewer_jwt = lookup(var.token_reviewer_jwts, each.key, null)

  # true, когда Vault живёт вне кластера: локального CA/JWT у него нет.
  disable_local_ca_jwt = each.value.disable_local_ca_jwt

  lifecycle {
    precondition {
      condition     = can(regex("^https?://", each.value.host))
      error_message = "clusters[\"${each.key}\"].host должен быть полным URL API-сервера, например https://api.${each.key}:6443."
    }

    precondition {
      condition = (
        !each.value.disable_local_ca_jwt
        || (each.value.ca_cert != "" && lookup(var.token_reviewer_jwts, each.key, "") != "")
      )
      error_message = "Кластер ${each.key}: при disable_local_ca_jwt = true Vault снаружи кластера и обязан иметь ca_cert и token_reviewer_jwts[\"${each.key}\"], иначе TokenReview вернёт 401 на каждый логин."
    }
  }
}

resource "vault_kubernetes_auth_backend_role" "this" {
  for_each = local.k8s_roles_flat

  backend   = vault_auth_backend.kubernetes[each.value.cluster].path
  role_name = each.value.role

  bound_service_account_names      = each.value.service_accounts
  bound_service_account_namespaces = each.value.namespaces
  audience                         = each.value.audience

  token_policies         = each.value.policies
  token_ttl              = coalesce(each.value.token_ttl, var.default_token_ttl)
  token_max_ttl          = coalesce(each.value.token_max_ttl, var.default_token_max_ttl)
  token_explicit_max_ttl = coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl)

  # null — берём общий список; [] — роль сознательно снимает ограничение.
  token_bound_cidrs = (
    each.value.token_bound_cidrs == null
    ? var.default_token_bound_cidrs
    : each.value.token_bound_cidrs
  )

  # Политики — раньше ролей: иначе в одном apply роль может появиться первой
  # и короткое время выдавать токены со ссылкой на ещё несуществующую политику.
  depends_on = [
    vault_kubernetes_auth_backend_config.this,
    vault_policy.this,
  ]

  lifecycle {
    precondition {
      condition     = contains(keys(var.clusters), each.value.cluster)
      error_message = "Роль ${each.key} привязана к кластеру ${each.value.cluster}, которого нет в var.clusters."
    }

    # Ссылка на несуществующую политику Vault не смущает: роль создастся,
    # логин пройдёт, а прав не будет — ловим это до apply.
    precondition {
      condition     = length(setsubtract(each.value.policies, local.known_policy_names)) == 0
      error_message = "Роль ${each.key} ссылается на политики, которых нет в конфиге: ${join(", ", setsubtract(each.value.policies, local.known_policy_names))}. Описать их в var.policies / policies/*.hcl либо перечислить в var.external_policies."
    }

    precondition {
      condition     = length(each.value.service_accounts) > 0 && length(each.value.namespaces) > 0
      error_message = "Роль ${each.key}: пустой список namespaces или service_accounts."
    }

    # "*" в обоих полях = токен по этой роли получает любой под кластера.
    precondition {
      condition     = !(contains(each.value.service_accounts, "*") && contains(each.value.namespaces, "*"))
      error_message = "Роль ${each.key} разрешает вход любому сервисаккаунту в любом namespace. Ограничить хотя бы одно из полей."
    }
  }
}
