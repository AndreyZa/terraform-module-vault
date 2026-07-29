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
# Сервисы: одна запись — политика + роль
##############################################################################

variable "services" {
  description = <<-EOT
    Обычный случай: сервису нужны свои пути и свой вход. Одна запись создаёт
    политику <ключ> и JWT-роль <ключ>, уже связанные между собой, — не нужно
    повторять имя политики в роли и следить, чтобы они не разъехались.

    Раздельные policies / jwt_roles остаются для остального: политика без роли,
    роль на несколько политик, роль на чужую политику.
  EOT
  type = map(object({
    # --- права (как в policies) ---
    read_paths    = optional(list(string), [])
    write_paths   = optional(list(string), [])
    list_paths    = optional(list(string), [])
    allow_destroy = optional(bool, false)
    extra_rules   = optional(string, "")

    # Точный набор прав на путь, когда read/write-наборов недостаточно:
    # "<путь>" = ["create", "update"]. Права ложатся на путь данных
    # (<mount>/<путь> в v1, <mount>/data/<путь> в v2) и складываются
    # с остальными правилами на тот же путь.
    path_capabilities = optional(map(list(string)), {})

    # Пути с ДРУГИХ маунтов в этой же политике — в том числе другой версии KV.
    # Верхнеуровневые *_paths относятся к kv_mount / kv_version.
    mounts = optional(list(object({
      mount             = string
      kv_version        = optional(number) # null → var.kv_version
      read_paths        = optional(list(string), [])
      write_paths       = optional(list(string), [])
      list_paths        = optional(list(string), [])
      allow_destroy     = optional(bool, false)
      path_capabilities = optional(map(list(string)), {})
    })), [])

    # Дополнительные, уже существующие политики этой же роли.
    extra_policies = optional(list(string), [])

    # --- вход (как в jwt_roles) ---
    role_type       = optional(string, "jwt")
    user_claim      = optional(string, "project_id")
    bound_audiences = optional(list(string)) # null → default_bound_audiences, [] → без проверки aud
    bound_subject   = optional(string)

    bound_claims      = optional(map(string), {})
    bound_claims_type = optional(string, "string")

    claim_mappings = optional(map(string), {})
    groups_claim   = optional(string)

    allowed_redirect_uris = optional(list(string), [])

    clock_skew_leeway            = optional(number)
    expiration_leeway            = optional(number)
    not_before_leeway            = optional(number)
    disable_bound_claims_parsing = optional(bool, false)

    token_ttl              = optional(number) # сек; null → default_token_ttl
    token_max_ttl          = optional(number)
    token_explicit_max_ttl = optional(number)

    # Периодический токен: живёт бесконечно, пока его продлевают не реже
    # token_period. Требует token_explicit_max_ttl = 0 — жёсткий потолок
    # прикончил бы его независимо от продлений.
    token_period      = optional(number)
    token_bound_cidrs = optional(list(string)) # null → default_token_bound_cidrs, [] → без ограничения
  }))
  default = {}

  validation {
    condition     = alltrue([for s in values(var.services) : contains(["jwt", "oidc"], s.role_type)])
    error_message = "role_type — \"jwt\" или \"oidc\"."
  }

  validation {
    condition     = alltrue([for s in values(var.services) : contains(["string", "glob"], s.bound_claims_type)])
    error_message = "bound_claims_type — \"string\" или \"glob\"."
  }
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

    # Точный набор прав на путь, когда read/write-наборов недостаточно:
    # "<путь>" = ["create", "update"]. Права ложатся на путь данных
    # (<mount>/<путь> в v1, <mount>/data/<путь> в v2) и складываются
    # с остальными правилами на тот же путь.
    path_capabilities = optional(map(list(string)), {})

    # Пути с ДРУГИХ маунтов в этой же политике — в том числе другой версии KV.
    # Верхнеуровневые *_paths относятся к kv_mount / kv_version.
    mounts = optional(list(object({
      mount             = string
      kv_version        = optional(number) # null → var.kv_version
      read_paths        = optional(list(string), [])
      write_paths       = optional(list(string), [])
      list_paths        = optional(list(string), [])
      allow_destroy     = optional(bool, false)
      path_capabilities = optional(map(list(string)), {})
    })), [])
  }))
  default = {}

  validation {
    condition = alltrue([
      for p in values(var.policies) : alltrue([
        for caps in values(p.path_capabilities) : alltrue([
          for c in caps : contains(["create", "read", "update", "patch", "delete", "list", "sudo", "deny"], c)
        ])
      ])
    ])
    error_message = "path_capabilities: допустимы только create, read, update, patch, delete, list, sudo, deny."
  }
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
    namespaces             = list(string)
    service_accounts       = list(string)
    policies               = list(string)
    audience               = optional(string) # ожидаемый aud в JWT, если включён TokenRequest
    token_ttl              = optional(number) # сек; null → default_token_ttl
    token_max_ttl          = optional(number)
    token_explicit_max_ttl = optional(number)

    # Периодический токен: живёт бесконечно, пока его продлевают не реже
    # token_period. Требует token_explicit_max_ttl = 0 — жёсткий потолок
    # прикончил бы его независимо от продлений.
    token_period      = optional(number)
    token_bound_cidrs = optional(list(string))
  })))
  default = {}
}

variable "default_token_ttl" {
  description = "TTL токена по умолчанию для ролей, где он не задан явно (сек)."
  type        = number
  default     = 600 # 10 минут
}

variable "default_token_max_ttl" {
  description = "Максимальный TTL токена по умолчанию (сек) — предел продления."
  type        = number
  default     = 900 # 15 минут
}

variable "default_token_explicit_max_ttl" {
  description = <<-EOT
    Жёсткий предел жизни токена по умолчанию (сек). В отличие от token_max_ttl
    его нельзя обойти продлением: по истечении токен отзывается, чем бы его
    ни продлевали. 0 — без жёсткого предела.
  EOT
  type        = number
  default     = 900 # 15 минут
}

variable "default_token_bound_cidrs" {
  description = <<-EOT
    Откуда токен принимается по умолчанию. Пустой список — без ограничения.
    Роль может задать свой список; чтобы снять ограничение точечно, указать
    в роли token_bound_cidrs = [].
  EOT
  type        = list(string)
  default     = ["127.0.0.0/8", "10.0.0.0/8"]
}

variable "default_bound_audiences" {
  description = <<-EOT
    Аудитория токена по умолчанию — как правило адрес самого Vault: issuer
    выписывает JWT именно для него, и роль не должна принимать токен, выписанный
    кому-то другому. Модуль не может взять его сам: адрес живёт в конфигурации
    провайдера, а её модуль не видит.
    Роль наследует список, если не задала bound_audiences; чтобы отказаться
    точечно — bound_audiences = [] (и тогда роль должна ограничиваться
    bound_claims или bound_subject).
  EOT
  type        = list(string)
  default     = []
}

##############################################################################
# JWT / OIDC auth
##############################################################################

variable "jwt_path" {
  description = "Путь JWT/OIDC-бэкенда. Роли лягут в auth/<jwt_path>/role/<имя>."
  type        = string
  default     = "jwt"
}

variable "manage_jwt_backend" {
  description = <<-EOT
    Управлять самим бэкендом (его issuer/ключами) из Terraform. По умолчанию false:
    роли меняются часто, а конфиг метода заводят один раз, и перетереть его чужим
    apply — значит уронить логин всем сразу.
    Чтобы забрать под Terraform существующий: manage_jwt_backend = true и
    `terraform import module.<имя>.vault_jwt_auth_backend.this[0] <jwt_path>`.
  EOT
  type        = bool
  default     = false
}

variable "jwt_backend" {
  description = <<-EOT
    Конфиг бэкенда — используется только при manage_jwt_backend = true.
    Способ проверки подписи ровно один: oidc_discovery_url (по нему Vault сам
    заберёт JWKS), jwks_url или жёстко заданные jwt_validation_pubkeys.
  EOT
  type = object({
    type                   = optional(string, "jwt") # "jwt" — машинный вход, "oidc" — вход человека через браузер
    description            = optional(string)
    oidc_discovery_url     = optional(string)
    oidc_discovery_ca_pem  = optional(string)
    jwks_url               = optional(string)
    jwks_ca_pem            = optional(string)
    jwt_validation_pubkeys = optional(list(string), [])
    bound_issuer           = optional(string)
    jwt_supported_algs     = optional(list(string), [])
    default_role           = optional(string)
  })
  default = {}
}

variable "jwt_roles" {
  description = <<-EOT
    Роли JWT/OIDC: ключ — имя роли (ляжет в auth/<jwt_path>/role/<ключ>).
    user_claim — какой claim становится именем сущности в Vault (обычно "sub").
    Ограничение обязательно: bound_audiences, bound_subject или bound_claims,
    иначе токен получит любой предъявитель валидного JWT этого issuer'а.
  EOT
  type = map(object({
    policies = list(string)

    role_type       = optional(string, "jwt")
    user_claim      = optional(string, "project_id")
    bound_audiences = optional(list(string)) # null → default_bound_audiences, [] → без проверки aud
    bound_subject   = optional(string)

    # claim → допустимое значение (несколько — через запятую).
    bound_claims = optional(map(string), {})
    # "string" — точное совпадение, "glob" — разрешает * в значениях.
    bound_claims_type = optional(string, "string")

    claim_mappings = optional(map(string), {})
    groups_claim   = optional(string)

    # Только для role_type = "oidc".
    allowed_redirect_uris = optional(list(string), [])

    clock_skew_leeway            = optional(number)
    expiration_leeway            = optional(number)
    not_before_leeway            = optional(number)
    disable_bound_claims_parsing = optional(bool, false)

    token_ttl              = optional(number) # сек; null → default_token_ttl
    token_max_ttl          = optional(number)
    token_explicit_max_ttl = optional(number)

    # Периодический токен: живёт бесконечно, пока его продлевают не реже
    # token_period. Требует token_explicit_max_ttl = 0 — жёсткий потолок
    # прикончил бы его независимо от продлений.
    token_period      = optional(number)
    token_bound_cidrs = optional(list(string)) # null → default_token_bound_cidrs, [] → без ограничения
  }))
  default = {}

  validation {
    condition     = alltrue([for r in values(var.jwt_roles) : contains(["jwt", "oidc"], r.role_type)])
    error_message = "role_type — \"jwt\" или \"oidc\"."
  }

  validation {
    condition     = alltrue([for r in values(var.jwt_roles) : contains(["string", "glob"], r.bound_claims_type)])
    error_message = "bound_claims_type — \"string\" или \"glob\"."
  }
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
    policies               = list(string)
    secret_id_ttl          = optional(number, 3600)
    secret_id_num_uses     = optional(number, 0) # 0 — без ограничения по количеству логинов
    token_ttl              = optional(number)
    token_max_ttl          = optional(number)
    token_explicit_max_ttl = optional(number)
    token_bound_cidrs      = optional(list(string))
    secret_id_bound_cidrs  = optional(list(string), [])
  }))
  default = {}
}
