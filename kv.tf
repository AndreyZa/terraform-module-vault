# Маунт с секретами. По умолчанию не управляется отсюда (var.manage_kv_mount = false):
# он почти наверняка уже создан, а пересоздание маунта уничтожает все секреты.
resource "vault_mount" "kv" {
  count = var.manage_kv_mount ? 1 : 0

  path = var.kv_mount
  type = "kv"

  # Смена version на существующем маунте — не переименование параметра, а апгрейд
  # движка v1 → v2, и он необратим. Менять отдельно и осознанно, а не заодно
  # с правкой политик.
  options = { version = tostring(var.kv_version) }

  description = coalesce(var.kv_description, "KV v${var.kv_version}, managed by Terraform")

  lifecycle {
    prevent_destroy = true
  }
}
