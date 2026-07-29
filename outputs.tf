output "policies" {
  description = "Имена политик, которыми управляет модуль."
  value       = sort(keys(local.all_policies))
}

output "kubernetes_auth_paths" {
  description = "Кластер → путь auth-маунта (его подставляют в VAULT_AUTH_URL / vault-agent)."
  value       = local.cluster_auth_paths
}

output "kubernetes_roles" {
  description = "Роли kubernetes auth: кластер/роль → login-путь и выданные политики."
  value = {
    for k, r in local.k8s_roles_flat : k => {
      login_path = "auth/${local.cluster_auth_paths[r.cluster]}/login"
      role       = r.role
      policies   = r.policies
      namespaces = r.namespaces
    }
  }
}

output "jwt_login_path" {
  description = "Путь логина JWT/OIDC (null, если ролей нет)."
  value       = length(local.all_jwt_roles) > 0 ? "auth/${var.jwt_path}/login" : null
}

output "jwt_roles" {
  description = "Роли JWT: имя → путь роли, выданные политики и ограничения."
  value = {
    for k, r in local.all_jwt_roles : k => {
      role_path       = "auth/${var.jwt_path}/role/${k}"
      policies        = r.policies
      bound_audiences = r.bound_audiences
      bound_claims    = r.bound_claims
    }
  }
}

output "approle_login_path" {
  description = "Путь логина AppRole (null, если ролей нет и бэкенд не поднимался)."
  value       = length(var.approle_roles) > 0 ? "auth/${vault_auth_backend.approle[0].path}/login" : null
}

output "approle_role_ids" {
  description = "role_id по каждой AppRole (не секрет; секрет — secret_id, он тут не выдаётся)."
  value       = { for k, r in vault_approle_auth_backend_role.this : k => r.role_id }
}
