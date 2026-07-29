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
  jwt_validation_pubkeys = (
    length(var.jwt_backend.jwt_validation_pubkeys) > 0
    ? var.jwt_backend.jwt_validation_pubkeys
    : null
  )
  bound_issuer       = var.jwt_backend.bound_issuer
  jwt_supported_algs = length(var.jwt_backend.jwt_supported_algs) > 0 ? var.jwt_backend.jwt_supported_algs : null
  default_role       = var.jwt_backend.default_role

  lifecycle {
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
  for_each = var.jwt_roles

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

  token_policies    = each.value.policies
  token_ttl         = coalesce(each.value.token_ttl, var.default_token_ttl)
  token_max_ttl     = coalesce(each.value.token_max_ttl, var.default_token_max_ttl)
  token_bound_cidrs = each.value.token_bound_cidrs

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
  }
}
