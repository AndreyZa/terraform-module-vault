# Фикстура для теста policy_files_dir: рукописная политика, переживающая
# смену версии маунта через data_prefix, плюс путь вне KV и экранированный
# доллар — $${NOT_TF} должен дойти до Vault литеральным долларом со скобками.
path "${mount}/${data_prefix}fixture/app" {
  capabilities = ["read"]
}

path "sys/health" {
  capabilities = ["read"]
}
