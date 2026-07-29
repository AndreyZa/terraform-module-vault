##############################################################################
# AppRole — для CI и того, что живёт вне Kubernetes.
##############################################################################

resource "vault_auth_backend" "approle" {
  count = var.manage_approle_backend && length(var.approle_roles) > 0 ? 1 : 0

  type        = "approle"
  path        = var.approle_path
  description = "AppRole для CI и внешних потребителей (managed by Terraform)"
}

resource "vault_approle_auth_backend_role" "this" {
  for_each = var.approle_roles

  # Путь берём из переменной, а не из ресурса: при manage_approle_backend = false
  # ресурса нет, а роли всё равно ложатся под уже поднятый бэкенд.
  backend   = var.approle_path
  role_name = each.key

  token_policies          = each.value.policies
  token_ttl               = coalesce(each.value.token_ttl, var.default_token_ttl)
  token_max_ttl           = coalesce(each.value.token_max_ttl, var.default_token_max_ttl)
  token_explicit_max_ttl  = coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl)
  token_period            = each.value.token_period
  token_no_default_policy = each.value.token_no_default_policy

  token_bound_cidrs = (
    each.value.token_bound_cidrs == null
    ? var.default_token_bound_cidrs
    : each.value.token_bound_cidrs
  )

  secret_id_ttl         = each.value.secret_id_ttl
  secret_id_num_uses    = each.value.secret_id_num_uses
  secret_id_bound_cidrs = each.value.secret_id_bound_cidrs

  # Политики — раньше ролей (см. комментарий в auth_kubernetes.tf).
  # Бэкенд — раньше ролей: связь через var.approle_path неявной зависимости не даёт.
  depends_on = [vault_policy.this, vault_auth_backend.approle]

  lifecycle {
    precondition {
      condition     = length(setsubtract(each.value.policies, local.known_policy_names)) == 0
      error_message = "AppRole ${each.key} ссылается на политики, которых нет в конфиге: ${join(", ", setsubtract(each.value.policies, local.known_policy_names))}."
    }

    # token_explicit_max_ttl — жёсткий потолок: токен умрёт раньше, чем отработает
    # свой token_ttl, и продление не поможет.
    precondition {
      condition = (
        coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl) == 0
        || coalesce(each.value.token_ttl, var.default_token_ttl) <= coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl)
      )
      error_message = "AppRole ${each.key}: token_ttl больше token_explicit_max_ttl — токен будет отозван раньше, чем истечёт его собственный TTL."
    }

    # Периодический токен продлевается бесконечно, но жёсткий потолок всё равно
    # его прикончит — вместе эти два поля не работают.
    precondition {
      condition = (
        each.value.token_period == null
        || coalesce(each.value.token_explicit_max_ttl, var.default_token_explicit_max_ttl) == 0
      )
      error_message = "AppRole ${each.key}: token_period задан вместе с token_explicit_max_ttl — потолок отзовёт токен, сколько его ни продлевай. Для периодического токена поставить token_explicit_max_ttl = 0."
    }
  }
}

# secret_id здесь сознательно не создаётся: он бы лёг в state открытым текстом
# и жил до следующего apply. Выдавать его нужно из CI при выкате:
#   vault write -f auth/${var.approle_path}/role/<role>/secret-id
