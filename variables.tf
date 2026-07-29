##############################################################################
# KV-хранилище
##############################################################################

variable "kv_mount" {
  description = <<-EOT
    Путь KV-маунта, на который выписываются права (без слэшей).
    Обязателен: имя маунта — свойство конкретной установки Vault, дефолта у него
    в общем модуле быть не может, а промах даст политику без прав.
  EOT
  type        = string

  validation {
    condition     = !startswith(var.kv_mount, "/") && !endswith(var.kv_mount, "/")
    error_message = "kv_mount пишется без ведущего и завершающего слэша."
  }
}

variable "kv_version" {
  description = <<-EOT
    Версия KV-движка на kv_mount: 1 или 2. От неё зависит, во что раскрываются
    пути политик:
      v1 — <mount>/<path>;
      v2 — <mount>/data/<path> (секрет) и <mount>/metadata/<path> (версии, list),
           плюс delete/ и undelete/ для мягкого удаления.
    Значение обязано совпадать с реальной версией маунта: политика, выписанная
    не под ту версию, синтаксически верна, применяется без ошибок и не даёт прав.
    Проверить: `vault read sys/mounts/<kv_mount>` → options.version.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = contains([1, 2], var.kv_version)
    error_message = "kv_version — 1 или 2."
  }
}

variable "kv_description" {
  description = "Описание маунта, если модуль его создаёт. null — нейтральное «KV vN, managed by Terraform»."
  type        = string
  default     = null
}

variable "manage_kv_mount" {
  description = <<-EOT
    Управлять самим маунтом из Terraform. Если маунт уже существует — оставить false
    либо сделать `terraform import module.<имя>.vault_mount.kv[0] <kv_mount>`,
    иначе apply упадёт на "path is already in use".
  EOT
  type        = bool
  default     = false
}

##############################################################################
# Политики
##############################################################################

variable "policies" {
  description = <<-EOT
    Политики, генерируемые из путей: раскладка правил зависит от kv_version.
    Пути — относительно kv_mount, glob'ы Vault (* и +) поддерживаются.
  EOT
  type = map(object({
    read_paths  = optional(list(string), []) # чтение секрета (в v2 — и метаданных)
    write_paths = optional(list(string), []) # запись (в v2 — плюс мягкое удаление версии)
    list_paths  = optional(list(string), []) # только обход дерева
    extra_rules = optional(string, "")       # произвольный HCL, вставляется как есть

    # Разрешить безвозвратное удаление по write_paths: в v2 это destroy/ и снос
    # metadata, в v1 — обычный delete (мягкого удаления там нет).
    # По умолчанию выключено: стирание секрета выписывается осознанно.
    allow_destroy = optional(bool, false)
  }))
  default = {}
}

variable "policy_files_dir" {
  description = <<-EOT
    Каталог с политиками, написанными руками (путь ОТНОСИТЕЛЬНО корневого конфига,
    не модуля). Каждый <имя>.hcl становится политикой <имя>. Файл прогоняется через
    templatefile, ему доступны mount, kv_version, data_prefix и metadata_prefix
    ("" / "" для v1, "data/" / "metadata/" для v2) — так рукописная политика
    переживает смену версии маунта. Литеральный доллар экранируется удвоением.
    Каталога может не быть — тогда файловых политик просто нет, как и при null или "".
  EOT
  type        = string
  default     = "policies"
  nullable    = true
}

variable "raw_policies" {
  description = <<-EOT
    Политики готовым HCL: имя → тело. Для случаев, когда HCL собирается у вызывающего
    (например, templatefile со своими переменными). Складывается с policy_files_dir;
    пересечение имён валит проверку.
  EOT
  type        = map(string)
  default     = {}
}

variable "external_policies" {
  description = <<-EOT
    Имена политик, которые существуют в Vault, но управляются не этим модулем.
    Роли могут на них ссылаться — без этого списка precondition роли упадёт.
  EOT
  type        = list(string)
  default     = []
}

##############################################################################
# Kubernetes auth
##############################################################################

variable "clusters" {
  description = <<-EOT
    Кластеры, для которых поднимается отдельный kubernetes auth backend.
    Ключ — короткое имя кластера (оно же попадает в путь маунта по умолчанию).
  EOT
  type = map(object({
    host                 = string               # https://api.<cluster>:6443, доступен с Vault-сервера
    auth_path            = optional(string)     # по умолчанию kubernetes/<ключ>
    ca_cert              = optional(string, "") # PEM API-сервера; "" — Vault возьмёт свой локальный CA
    disable_local_ca_jwt = optional(bool, true) # true, когда Vault снаружи кластера
    description          = optional(string, "")
    default_lease_ttl    = optional(string, "1h")
    max_lease_ttl        = optional(string, "24h")
  }))
  default = {}
}

variable "token_reviewer_jwts" {
  description = <<-EOT
    JWT сервисаккаунта vault-tokenreviewer по каждому кластеру: ключ — имя кластера.
    Нужен долгоживущий токен (Secret типа kubernetes.io/service-account-token),
    у SA должно быть право на system:auth-delegator.
    Кластер, которого нет в карте, конфигурируется без reviewer JWT — тогда Vault
    валидирует токен через сам клиентский JWT (требует TokenRequest-аудиторию).
  EOT
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "k8s_roles" {
  description = <<-EOT
    Роли kubernetes auth: { "<кластер>" = { "<роль>" = {...} } }.
    Логин выдаёт токен с token_policies тому, кто предъявил JWT сервисаккаунта
    из namespaces × service_accounts.
  EOT
  type = map(map(object({
    namespaces        = list(string)
    service_accounts  = list(string)
    policies          = list(string)
    audience          = optional(string) # ожидаемый aud в JWT, если включён TokenRequest
    token_ttl         = optional(number) # сек; null → default_token_ttl
    token_max_ttl     = optional(number)
    token_bound_cidrs = optional(list(string), [])
  })))
  default = {}
}

variable "default_token_ttl" {
  description = "TTL токена по умолчанию для ролей, где он не задан явно (сек)."
  type        = number
  default     = 3600
}

variable "default_token_max_ttl" {
  description = "Максимальный TTL токена по умолчанию (сек)."
  type        = number
  default     = 14400
}

##############################################################################
# AppRole (CI и внешние потребители)
##############################################################################

variable "approle_path" {
  description = "Путь AppRole-бэкенда."
  type        = string
  default     = "approle"
}

variable "approle_roles" {
  description = "Роли AppRole: ключ — имя роли."
  type = map(object({
    policies              = list(string)
    secret_id_ttl         = optional(number, 3600)
    secret_id_num_uses    = optional(number, 0) # 0 — без ограничения по количеству логинов
    token_ttl             = optional(number, 1800)
    token_max_ttl         = optional(number, 3600)
    token_bound_cidrs     = optional(list(string), [])
    secret_id_bound_cidrs = optional(list(string), [])
  }))
  default = {}
}
