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

  # Пустая строка слэшей не содержит и проверку выше проходила, а пути потом
  # получались вида "/data/secret" — Vault такую политику принимает и не матчит.
  validation {
    condition     = trimspace(var.kv_mount) != ""
    error_message = "kv_mount не может быть пустым: пути выродились бы в \"/data/…\", и политика молча перестала бы что-либо разрешать."
  }

  # Vault нормализует "a//b" в "a/b" при создании маунта, а строка в политике
  # остаётся с "//" — и не матчит ни одного запроса. Проверено на живом Vault:
  # политика применяется, токен получает 403 на всё.
  validation {
    condition     = !strcontains(var.kv_mount, "//")
    error_message = "kv_mount не может содержать \"//\": Vault нормализует путь маунта, политика остаётся с \"//\" и молча не матчит запросы."
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


    # Пути ВНЕ KV-маунтов, как есть: "auth/token/create" = ["update"],
    # "sys/mounts" = ["read"]. Префикс маунта не добавляется, версия KV
    # не учитывается. Складывается с остальными правилами на тот же путь.
    raw_path_capabilities = optional(map(list(string)), {})

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
    token_period = optional(number)

    # Не подмешивать встроенную политику default. Она даёт мелочи вроде
    # auth/token/lookup-self и renew-self — отключив её, их придётся выписать
    # руками через raw_path_capabilities.
    token_no_default_policy = optional(bool, false)
    token_bound_cidrs       = optional(list(string)) # null → default_token_bound_cidrs, [] → без ограничения
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

  # Неизвестное право не отбрасывается с ошибкой, а молча выпадает при сборке
  # правил; ПУСТОЙ список прав alltrue тоже пропускает — на выходе в обоих
  # случаях строфа capabilities = [], которую Vault принимает и которая не даёт
  # ничего. Белый список — local.valid_capabilities, один на модуль.
  validation {
    condition = alltrue([
      for s in values(var.services) : alltrue(concat(
        [for caps in values(s.path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])],
        [for caps in values(s.raw_path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])],
        [for m in s.mounts : alltrue([for caps in values(m.path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])])],
      ))
    ])
    error_message = "services: в path_capabilities / raw_path_capabilities / mounts[*].path_capabilities допустимы только create, read, update, patch, delete, list, subscribe, recover, sudo, deny, и список прав не может быть пустым."
  }

  # Пути: не пустые, без ведущего/завершающего слэша, без "//". Ведущий слэш
  # или пустой элемент дают "secret/data//x" и "secret/data/" — Vault принимает
  # такую политику и молча не матчит запросы.
  validation {
    condition = alltrue([
      for s in values(var.services) : alltrue([
        for path in concat(
          s.read_paths, s.write_paths, s.list_paths,
          keys(s.path_capabilities), keys(s.raw_path_capabilities),
          flatten([for m in s.mounts : concat(m.read_paths, m.write_paths, m.list_paths, keys(m.path_capabilities))]),
        ) : path != "" && !startswith(path, "/") && !endswith(path, "/") && !strcontains(path, "//")
      ])
    ])
    error_message = "services: пути не могут быть пустыми, начинаться/заканчиваться слэшем или содержать \"//\" — такой путь молча не сматчится."
  }

  validation {
    condition     = alltrue([for k in keys(var.services) : k != ""])
    error_message = "services: пустой ключ карты — это политика и роль с пустым именем; plan пройдёт, apply упадёт посреди прогона."
  }

  validation {
    condition = alltrue([
      for s in values(var.services) : alltrue([
        for v in [s.token_ttl, s.token_max_ttl, s.token_explicit_max_ttl, s.token_period] : v == null || v >= 0
      ])
    ])
    error_message = "services: TTL и token_period не могут быть отрицательными — plan прошёл бы, apply упал бы с 400."
  }

  validation {
    condition     = alltrue([for s in values(var.services) : s.user_claim != ""])
    error_message = "services: user_claim не может быть пустым — apply упадёт с \"a user claim must be defined on the role\"."
  }

  validation {
    condition = alltrue([
      for s in values(var.services) : alltrue([
        for m in s.mounts : m.kv_version == null || contains([1, 2], m.kv_version)
      ])
    ])
    error_message = "services: mounts[*].kv_version — 1 или 2 (либо null, чтобы взять общий kv_version). Иное значение молча трактовалось бы как v1."
  }

  # То же требование, что и к kv_mount: пустое имя, слэши по краям или "//"
  # дают путь, который Vault принимает и не матчит.
  validation {
    condition = alltrue([
      for s in values(var.services) : alltrue([
        for m in s.mounts : trimspace(m.mount) != "" && !startswith(m.mount, "/") && !endswith(m.mount, "/") && !strcontains(m.mount, "//")
      ])
    ])
    error_message = "services: mounts[*].mount не может быть пустым, со слэшами по краям или с \"//\"."
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


    # Пути ВНЕ KV-маунтов, как есть: "auth/token/create" = ["update"],
    # "sys/mounts" = ["read"]. Префикс маунта не добавляется, версия KV
    # не учитывается. Складывается с остальными правилами на тот же путь.
    raw_path_capabilities = optional(map(list(string)), {})

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

  # Неизвестное право не отбрасывается с ошибкой, а молча выпадает при сборке
  # правил; ПУСТОЙ список прав alltrue тоже пропускает — на выходе в обоих
  # случаях строфа capabilities = [], которую Vault принимает и которая не даёт
  # ничего. Белый список — local.valid_capabilities, один на модуль.
  validation {
    condition = alltrue([
      for p in values(var.policies) : alltrue(concat(
        [for caps in values(p.path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])],
        [for caps in values(p.raw_path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])],
        [for m in p.mounts : alltrue([for caps in values(m.path_capabilities) : length(caps) > 0 && alltrue([for c in caps : contains(local.valid_capabilities, c)])])],
      ))
    ])
    error_message = "policies: в path_capabilities / raw_path_capabilities / mounts[*].path_capabilities допустимы только create, read, update, patch, delete, list, subscribe, recover, sudo, deny, и список прав не может быть пустым."
  }

  # Пути: не пустые, без ведущего/завершающего слэша, без "//". Ведущий слэш
  # или пустой элемент дают "secret/data//x" и "secret/data/" — Vault принимает
  # такую политику и молча не матчит запросы.
  validation {
    condition = alltrue([
      for p in values(var.policies) : alltrue([
        for path in concat(
          p.read_paths, p.write_paths, p.list_paths,
          keys(p.path_capabilities), keys(p.raw_path_capabilities),
          flatten([for m in p.mounts : concat(m.read_paths, m.write_paths, m.list_paths, keys(m.path_capabilities))]),
        ) : path != "" && !startswith(path, "/") && !endswith(path, "/") && !strcontains(path, "//")
      ])
    ])
    error_message = "policies: пути не могут быть пустыми, начинаться/заканчиваться слэшем или содержать \"//\" — такой путь молча не сматчится."
  }

  validation {
    condition     = alltrue([for k in keys(var.policies) : k != ""])
    error_message = "policies: пустой ключ карты — это политика с пустым именем; plan пройдёт, apply упадёт с криптичным 405."
  }

  validation {
    condition = alltrue([
      for p in values(var.policies) : alltrue([
        for m in p.mounts : m.kv_version == null || contains([1, 2], m.kv_version)
      ])
    ])
    error_message = "policies: mounts[*].kv_version — 1 или 2 (либо null, чтобы взять общий kv_version). Иное значение молча трактовалось бы как v1."
  }

  # То же требование, что и к kv_mount: пустое имя, слэши по краям или "//"
  # дают путь, который Vault принимает и не матчит.
  validation {
    condition = alltrue([
      for p in values(var.policies) : alltrue([
        for m in p.mounts : trimspace(m.mount) != "" && !startswith(m.mount, "/") && !endswith(m.mount, "/") && !strcontains(m.mount, "//")
      ])
    ])
    error_message = "policies: mounts[*].mount не может быть пустым, со слэшами по краям или с \"//\"."
  }
}

variable "policy_files_dir" {
  description = <<-EOT
    Каталог с политиками, написанными руками (путь ОТНОСИТЕЛЬНО корневого конфига,
    не модуля). Каждый <имя>.hcl становится политикой <имя>. Читается ТОЛЬКО
    верхний уровень каталога: policies/team/x.hcl молча не попадёт. Файл
    прогоняется через templatefile, ему доступны mount, kv_version, data_prefix
    и metadata_prefix ("" / "" для v1, "data/" / "metadata/" для v2) — так
    рукописная политика переживает смену версии маунта. Литеральный доллар
    экранируется удвоением.
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
    пересечение имён валит plan (precondition на vault_policy).
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.raw_policies) : k != ""])
    error_message = "raw_policies: пустой ключ карты — это политика с пустым именем; plan пройдёт, apply упадёт с криптичным 405."
  }
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

  validation {
    condition     = alltrue([for k in keys(var.clusters) : k != ""])
    error_message = "clusters: пустой ключ карты недопустим — из него строится путь auth-маунта."
  }

  # Go-длительность: "1h", "30m", "1h30m". Иной формат переживает plan
  # и падает только на apply при tune маунта.
  validation {
    condition = alltrue([
      for c in values(var.clusters) : alltrue([
        for d in [c.default_lease_ttl, c.max_lease_ttl] : can(regex("^([0-9]+(ns|us|ms|s|m|h))+$", d))
      ])
    ])
    error_message = "clusters: default_lease_ttl / max_lease_ttl — Go-длительность вида \"1h\", \"30m\", \"1h30m\"."
  }

  # auth_path: null — дефолт kubernetes/<ключ>. Пустая строка недопустима:
  # coalesce() пропускает "" так же, как null, и путь молча подменялся бы
  # дефолтом — конфиг выглядел бы применённым не так, как написан.
  validation {
    condition = alltrue([
      for c in values(var.clusters) : c.auth_path == null || (
        trimspace(c.auth_path) != ""
        && !startswith(c.auth_path, "/")
        && !endswith(c.auth_path, "/")
        && !strcontains(c.auth_path, "//")
      )
    ])
    error_message = "clusters: auth_path — либо null (дефолт kubernetes/<ключ>), либо непустой путь без слэшей по краям и без \"//\"."
  }
}

variable "k8s_roles" {
  description = <<-EOT
    Роли kubernetes auth: { "<кластер>" = { "<роль>" = {...} } }.
    Логин выдаёт токен с token_policies тому, кто предъявил JWT сервисаккаунта
    из namespaces × service_accounts.
  EOT
  type = map(map(object({
    namespaces       = list(string)
    service_accounts = list(string)
    policies         = list(string)
    # Ожидаемый aud клиентского JWT. Модуль не настраивает reviewer JWT,
    # поэтому Vault валидирует логин самим клиентским токеном — для
    # TokenRequest-токенов задавайте audience и проекцируйте том с ним.
    audience               = optional(string)
    token_ttl              = optional(number) # сек; null → default_token_ttl
    token_max_ttl          = optional(number)
    token_explicit_max_ttl = optional(number)

    # Периодический токен: живёт бесконечно, пока его продлевают не реже
    # token_period. Требует token_explicit_max_ttl = 0 — жёсткий потолок
    # прикончил бы его независимо от продлений.
    token_period = optional(number)

    # Не подмешивать встроенную политику default. Она даёт мелочи вроде
    # auth/token/lookup-self и renew-self — отключив её, их придётся выписать
    # руками через raw_path_capabilities.
    token_no_default_policy = optional(bool, false)
    token_bound_cidrs       = optional(list(string))
  })))
  default = {}

  validation {
    condition = alltrue([
      for cluster, roles in var.k8s_roles : cluster != "" && alltrue([for role in keys(roles) : role != ""])
    ])
    error_message = "k8s_roles: пустые ключи (имя кластера или роли) недопустимы — из них строятся пути."
  }

  validation {
    condition = alltrue([
      for roles in values(var.k8s_roles) : alltrue([
        for r in values(roles) : alltrue([
          for v in [r.token_ttl, r.token_max_ttl, r.token_explicit_max_ttl, r.token_period] : v == null || v >= 0
        ])
      ])
    ])
    error_message = "k8s_roles: TTL и token_period не могут быть отрицательными — plan прошёл бы, apply упал бы с 400."
  }
}

variable "default_token_ttl" {
  description = "TTL токена по умолчанию для ролей, где он не задан явно (сек)."
  type        = number
  default     = 600 # 10 минут

  validation {
    condition     = var.default_token_ttl >= 0
    error_message = "default_token_ttl не может быть отрицательным."
  }
}

variable "default_token_max_ttl" {
  description = "Максимальный TTL токена по умолчанию (сек) — предел продления."
  type        = number
  default     = 900 # 15 минут

  validation {
    condition     = var.default_token_max_ttl >= 0
    error_message = "default_token_max_ttl не может быть отрицательным."
  }
}

variable "default_token_explicit_max_ttl" {
  description = <<-EOT
    Жёсткий предел жизни токена по умолчанию (сек). В отличие от token_max_ttl
    его нельзя обойти продлением: по истечении токен отзывается, чем бы его
    ни продлевали. 0 — без жёсткого предела.
  EOT
  type        = number
  default     = 900 # 15 минут

  validation {
    condition     = var.default_token_explicit_max_ttl >= 0
    error_message = "default_token_explicit_max_ttl не может быть отрицательным."
  }
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

  validation {
    condition     = trimspace(var.jwt_path) != "" && !startswith(var.jwt_path, "/") && !endswith(var.jwt_path, "/") && !strcontains(var.jwt_path, "//")
    error_message = "jwt_path не может быть пустым, со слэшами по краям или с \"//\": роли легли бы в auth//role/…, plan прошёл бы, apply упал."
  }
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
    token_period = optional(number)

    # Не подмешивать встроенную политику default. Она даёт мелочи вроде
    # auth/token/lookup-self и renew-self — отключив её, их придётся выписать
    # руками через raw_path_capabilities.
    token_no_default_policy = optional(bool, false)
    token_bound_cidrs       = optional(list(string)) # null → default_token_bound_cidrs, [] → без ограничения
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

  validation {
    condition     = alltrue([for k in keys(var.jwt_roles) : k != ""])
    error_message = "jwt_roles: пустой ключ карты — это роль с пустым именем; plan пройдёт, apply упадёт."
  }

  validation {
    condition = alltrue([
      for r in values(var.jwt_roles) : alltrue([
        for v in [r.token_ttl, r.token_max_ttl, r.token_explicit_max_ttl, r.token_period] : v == null || v >= 0
      ])
    ])
    error_message = "jwt_roles: TTL и token_period не могут быть отрицательными — plan прошёл бы, apply упал бы с 400."
  }

  validation {
    condition     = alltrue([for r in values(var.jwt_roles) : r.user_claim != ""])
    error_message = "jwt_roles: user_claim не может быть пустым — apply упадёт с \"a user claim must be defined on the role\"."
  }
}

##############################################################################
# AppRole (CI и внешние потребители)
##############################################################################

variable "approle_path" {
  description = "Путь AppRole-бэкенда."
  type        = string
  default     = "approle"

  validation {
    condition     = trimspace(var.approle_path) != "" && !startswith(var.approle_path, "/") && !endswith(var.approle_path, "/") && !strcontains(var.approle_path, "//")
    error_message = "approle_path не может быть пустым, со слэшами по краям или с \"//\"."
  }
}

variable "manage_approle_backend" {
  description = <<-EOT
    Создавать сам AppRole-бэкенд (только когда approle_roles непуст).
    В отличие от manage_kv_mount и manage_jwt_backend по умолчанию true: до 2.0
    бэкенд создавался безусловно, и дефолт false снёс бы его при обновлении
    вместе со всеми ролями под ним.
    Если бэкенд уже поднят — поставить false либо сделать
    `terraform import module.<имя>.vault_auth_backend.approle[0] <approle_path>`,
    иначе apply упадёт на "path is already in use".
  EOT
  type        = bool
  default     = true
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

    # Периодический токен: живёт бесконечно, пока его продлевают не реже
    # token_period. Требует token_explicit_max_ttl = 0 — жёсткий потолок
    # прикончил бы его независимо от продлений.
    token_period = optional(number)

    # Не подмешивать встроенную политику default. Она даёт мелочи вроде
    # auth/token/lookup-self и renew-self — отключив её, их придётся выписать
    # руками через raw_path_capabilities.
    token_no_default_policy = optional(bool, false)
    token_bound_cidrs       = optional(list(string)) # null → default_token_bound_cidrs, [] → без ограничения
    secret_id_bound_cidrs   = optional(list(string), [])
  }))
  default = {}

  validation {
    condition     = alltrue([for k in keys(var.approle_roles) : k != ""])
    error_message = "approle_roles: пустой ключ карты — это роль с пустым именем; plan пройдёт, apply упадёт."
  }

  validation {
    condition = alltrue([
      for r in values(var.approle_roles) : alltrue([
        for v in [r.token_ttl, r.token_max_ttl, r.token_explicit_max_ttl, r.token_period, r.secret_id_ttl, r.secret_id_num_uses] : v == null || v >= 0
      ])
    ])
    error_message = "approle_roles: TTL, token_period, secret_id_ttl и secret_id_num_uses не могут быть отрицательными."
  }
}
