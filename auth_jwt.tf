##############################################################################
# JWT / OIDC auth. Один бэкенд (обычно уже поднят на auth/jwt), роли — под ним.
#
# Сам бэкенд по умолчанию не управляется: его конфиг (issuer, ключи, discovery)
# заводят один раз, а роли меняются постоянно. Чтобы забрать конфиг под Terraform,
# поставить manage_jwt_backend = true и импортировать существующий маунт.
##############################################################################

resource "vault_jwt_auth_backend" "this" {
  count = var.manage_jwt_backend ? 1 : 0

  path        = var.jwt_path
  type        = var.jwt_backend.type
  description = coalesce(var.jwt_backend.description, "JWT/OIDC auth, managed by Terraform")

  oidc_discovery_url    = var.jwt_backend.oidc_discovery_url
  oidc_discovery_ca_pem = var.jwt_backend.oidc_discovery_ca_pem
  jwks_url              = var.jwt_backend.jwks_url
  jwks_ca_pem           = var.jwt_backend.jwks_ca_pem
  # trimspace: file("key.pem") оставляет хвостовой перевод строки, Vault хранит
  # PEM без него — без обрезки plan показывает diff на каждом прогоне вечно
  # (проверено на живом Vault).
  jwt_validation_pubkeys = (
    length(var.jwt_backend.jwt_validation_pubkeys) > 0
    ? [for k in var.jwt_backend.jwt_validation_pubkeys : trimspace(k)]
    : null
  )
  bound_issuer       = var.jwt_backend.bound_issuer
  jwt_supported_algs = length(var.jwt_backend.jwt_supported_algs) > 0 ? var.jwt_backend.jwt_supported_algs : null
  default_role       = var.jwt_backend.default_role

  lifecycle {
    # Уничтожение бэкенда сносит ВСЕ роли под ним и ломает логин всем сразу —
    # проверено на живом Vault: toggle manage_* true -> false тихо это и делал,
    # рапортуя «1 destroyed». Снять бэкенд с управления, не трогая его в Vault:
    #   terraform state rm 'module.<имя>.vault_jwt_auth_backend.this[0]'
    # и только потом manage_jwt_backend = false.
    prevent_destroy = true

    precondition {
      condition = length(compact([
        var.jwt_backend.oidc_discovery_url,
        var.jwt_backend.jwks_url,
        length(var.jwt_backend.jwt_validation_pubkeys) > 0 ? "pubkeys" : "",
      ])) == 1
      error_message = "jwt_backend: ровно один способ проверки подписи — oidc_discovery_url, либо jwks_url, либо jwt_validation_pubkeys."
    }
  }
}

resource "vault_jwt_auth_backend_role" "this" {
  # services и jwt_roles сведены в одну карту в locals.
  for_each = local.all_jwt_roles

  backend   = var.jwt_path
  role_name = each.key
  role_type = each.value.role_type

  # Кого пускаем.
  user_claim      = each.value.user_claim
  bound_audiences = length(each.value.bound_audiences) > 0 ? each.value.bound_audiences : null
  bound_subject   = each.value.bound_subject
  bound_claims    = length(each.value.bound_claims) > 0 ? each.value.bound_claims : null

  # "glob" разрешает * в значениях bound_claims (ветки, окружения, репозитории).
  bound_claims_type = each.value.bound_claims_type
  claim_mappings    = length(each.value.claim_mappings) > 0 ? each.value.claim_mappings : null
  groups_claim      = each.value.groups_claim

  # Для role_type = "oidc" Vault требует список redirect URI.
  allowed_redirect_uris = length(each.value.allowed_redirect_uris) > 0 ? each.value.allowed_redirect_uris : null

  clock_skew_leeway            = each.value.clock_skew_leeway
  expiration_leeway            = each.value.expiration_leeway
  not_before_leeway            = each.value.not_before_leeway
  disable_bound_claims_parsing = each.value.disable_bound_claims_parsing

  token_policies          = each.value.policies
  token_ttl               = coalesce(each.value.token_ttl, var.default_token_ttl)
  token_max_ttl           = coalesce(each.value.token_max_ttl, var.default_token_max_ttl)
  token_explicit_max_ttl  = coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl)
  token_period            = each.value.token_period
  token_no_default_policy = each.value.token_no_default_policy

  # null — берём общий список; [] — роль сознательно снимает ограничение.
  token_bound_cidrs = (
    each.value.token_bound_cidrs == null
    ? var.default_token_bound_cidrs
    : each.value.token_bound_cidrs
  )

  # Политики — раньше ролей (см. комментарий в auth_kubernetes.tf).
  depends_on = [vault_policy.this, vault_jwt_auth_backend.this]

  lifecycle {
    precondition {
      condition     = length(setsubtract(each.value.policies, local.known_policy_names)) == 0
      error_message = "JWT-роль ${each.key} ссылается на политики, которых нет в конфиге: ${join(", ", setsubtract(each.value.policies, local.known_policy_names))}. Описать их в policies / policy_files_dir либо перечислить в external_policies."
    }

    # Роль без единого ограничения выдаёт токен любому валидному JWT этого issuer'а.
    precondition {
      condition = (
        length(each.value.bound_audiences) > 0
        || each.value.bound_subject != null
        || length(each.value.bound_claims) > 0
      )
      error_message = "JWT-роль ${each.key} ничем не ограничена: нужен хотя бы один из bound_audiences, bound_subject, bound_claims — иначе токен получит любой предъявитель валидного JWT от этого issuer'а."
    }

    precondition {
      condition     = each.value.role_type != "oidc" || length(each.value.allowed_redirect_uris) > 0
      error_message = "JWT-роль ${each.key} с role_type = \"oidc\" обязана задать allowed_redirect_uris."
    }

    # Имя из services и jwt_roles одновременно merge() схлопывает молча, оставляя
    # определение из services. До 2.0 здесь был check — предупреждение, apply шёл.
    precondition {
      condition     = !contains(tolist(local.duplicate_jwt_role_names), each.key)
      error_message = "JWT-роль ${each.key} задана и в services, и в jwt_roles. Останется определение из services, второе потеряется молча; переименуйте одно из них."
    }

    # token_explicit_max_ttl — жёсткий потолок: токен умрёт раньше, чем отработает
    # свой token_ttl, и продление не поможет.
    precondition {
      condition = (
        coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl) == 0
        || coalesce(each.value.token_ttl, var.default_token_ttl) <= coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl)
      )
      error_message = "JWT-роль ${each.key}: token_ttl больше token_explicit_max_ttl — токен будет отозван раньше, чем истечёт его собственный TTL."
    }

    # Периодический токен продлевается бесконечно, но любой из двух потолков
    # всё равно его прижмёт. Проверено на живом Vault: при period = 86400
    # и token_max_ttl = 900 выдаётся ttl = 899, и renew его не поднимает —
    # период задавлен полностью. token_period = 0 — это «не периодический»
    # (как его понимает провайдер), а не период в ноль секунд.
    precondition {
      condition = (
        coalesce(each.value.token_period, 0) == 0
        || (
          coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl) == 0
          && coalesce(each.value.token_max_ttl, var.default_token_max_ttl) == 0
        )
      )
      error_message = "JWT-роль ${each.key}: token_period задан вместе с ненулевым token_max_ttl или token_explicit_max_ttl — потолок прижмёт токен, сколько его ни продлевай. Для периодического токена оба поля должны быть 0."
    }
  }
}
