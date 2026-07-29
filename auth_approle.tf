##############################################################################
# AppRole — для CI и того, что живёт вне Kubernetes.
##############################################################################

resource "vault_auth_backend" "approle" {
  count = length(var.approle_roles) > 0 ? 1 : 0

  type        = "approle"
  path        = var.approle_path
  description = "AppRole для CI и внешних потребителей (managed by Terraform)"
}

resource "vault_approle_auth_backend_role" "this" {
  for_each = var.approle_roles

  backend   = vault_auth_backend.approle[0].path
  role_name = each.key

  token_policies    = each.value.policies
  token_ttl         = each.value.token_ttl
  token_max_ttl     = each.value.token_max_ttl
  token_bound_cidrs = each.value.token_bound_cidrs

  secret_id_ttl         = each.value.secret_id_ttl
  secret_id_num_uses    = each.value.secret_id_num_uses
  secret_id_bound_cidrs = each.value.secret_id_bound_cidrs

  # Политики — раньше ролей (см. комментарий в auth_kubernetes.tf).
  depends_on = [vault_policy.this]

  lifecycle {
    precondition {
      condition     = length(setsubtract(each.value.policies, local.known_policy_names)) == 0
      error_message = "AppRole ${each.key} ссылается на политики, которых нет в конфиге: ${join(", ", setsubtract(each.value.policies, local.known_policy_names))}."
    }
  }
}

# secret_id здесь сознательно не создаётся: он бы лёг в state открытым текстом
# и жил до следующего apply. Выдавать его нужно из CI при выкате:
#   vault write -f auth/${var.approle_path}/role/<role>/secret-id
