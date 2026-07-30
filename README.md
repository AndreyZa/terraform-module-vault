# terraform-module-vault

Terraform-модуль для прав доступа в Vault: политики и роли (`jwt`/`oidc`, `kubernetes`, `approle`). Значения секретов в KV модуль не трогает — только права на них.

Провайдер модуль не конфигурирует: адрес, CA и способ логина задаёт корневой конфиг. Один вызов модуля = один Vault.

Требования: Terraform >= 1.12, провайдер `hashicorp/vault` ~> 4.4.

Граница именно 1.12, а не 1.5 как в 1.x: до неё Terraform вычислял оба операнда `||`, и проверка входов вида `m.kv_version == null || contains([1, 2], m.kv_version)` падала на самом обычном случае — маунте без явно заданной версии. Проверено прогоном тестов: 1.9, 1.10 и 1.11 валятся, 1.12.0 проходит.

## Вызов

Обычный случай — сервису нужны свои пути и свой вход. Одна запись в `services` создаёт политику и роль под одним именем, уже связанные между собой:

```hcl
module "access" {
  source = "git::https://github.com/AndreyZa/terraform-module-vault.git?ref=v2.1.0"

  kv_mount   = "secret" # обязателен, дефолта нет
  kv_version = 2        # 1 или 2, должно совпадать с маунтом

  services = {
    "billing" = {
      # что можно
      read_paths = ["apps/billing/prod", "apps/billing/common"]
      list_paths = ["apps/billing"]

      # кому можно — роль ляжет в auth/jwt/role/billing
      bound_audiences = ["https://vault.example.internal"]
      bound_claims = {
        project_path = "platform/billing"
        ref          = "main"
      }
    }
  }
}
```

Добавить сервис — одна запись; имя политики нигде не повторяется, разъехаться нечему.

Раздельные `policies` и `jwt_roles` остаются для остального: политика без роли, роль на несколько политик, роль на чужую политику. Там же живут `kubernetes` и `approle`:

```hcl
  policies = {
    "billing-prod-ro" = { read_paths = ["apps/billing/prod"] }
  }

  clusters = {
    "prod-a" = {
      host    = "https://api.prod-a.example.internal:6443"
      ca_cert = var.cluster_ca_certs["prod-a"]
    }
  }

  k8s_roles = {
    "prod-a" = {
      "billing" = {
        namespaces       = ["billing"]
        service_accounts = ["billing"]
        policies         = ["billing-prod-ro"]
      }
    }
  }
```

## Входы

| Переменная | Тип | По умолчанию | Назначение |
|---|---|---|---|
| `kv_mount` | `string` | — обязателен | KV-маунт, на который выписываются права |
| `kv_version` | `number` | `1` | версия KV-движка: `1` или `2` |
| `manage_kv_mount` | `bool` | `false` | создавать ли сам маунт (обычно он уже есть) |
| `kv_description` | `string` | `null` | описание маунта, если модуль его создаёт |
| `services` | `map(object)` | `{}` | одна запись = политика + JWT-роль под тем же именем |
| `policies` | `map(object)` | `{}` | политики из путей: `read_paths` / `write_paths` / `list_paths` / `allow_destroy` / `path_capabilities` / `raw_path_capabilities` / `mounts` / `extra_rules` |
| `policy_files_dir` | `string` | `"policies"` | каталог с рукописными `*.hcl`, **путь от корневого конфига** |
| `raw_policies` | `map(string)` | `{}` | политики готовым HCL, если он собирается у вызывающего |
| `external_policies` | `list(string)` | `[]` | чужие политики, на которые ролям разрешено ссылаться |
| `clusters` | `map(object)` | `{}` | кластеры: `host`, `ca_cert`, `auth_path`, `disable_local_ca_jwt`, TTL маунта |
| `token_reviewer_jwts` | `map(string)`, sensitive | `{}` | JWT `vault-tokenreviewer` по кластерам |
| `k8s_roles` | `map(map(object))` | `{}` | `{ кластер = { роль = { namespaces, service_accounts, policies, … } } }` |
| `default_token_ttl` | `number` | `600` | TTL токена (10 мин) |
| `default_token_max_ttl` | `number` | `900` | предел продления (15 мин) |
| `default_token_explicit_max_ttl` | `number` | `900` | жёсткий предел жизни токена (15 мин) |
| `default_token_bound_cidrs` | `list(string)` | `["127.0.0.0/8", "10.0.0.0/8"]` | откуда токен принимается |
| `default_bound_audiences` | `list(string)` | `[]` | аудитория токена — обычно адрес самого Vault |
| `jwt_path` | `string` | `"jwt"` | путь JWT/OIDC-бэкенда; роли лягут в `auth/<jwt_path>/role/<имя>` |
| `manage_jwt_backend` | `bool` | `false` | управлять ли конфигом самого метода (issuer, ключи) |
| `jwt_backend` | `object` | `{}` | конфиг метода — только при `manage_jwt_backend = true` |
| `jwt_roles` | `map(object)` | `{}` | роли JWT/OIDC: `policies`, `user_claim`, `bound_audiences`, `bound_claims`, … |
| `approle_path` | `string` | `"approle"` | путь AppRole-бэкенда |
| `manage_approle_backend` | `bool` | `true` | создавать ли сам AppRole-бэкенд |
| `approle_roles` | `map(object)` | `{}` | роли AppRole: `policies`, TTL, `token_period`, ограничения по CIDR |

Политики приходят из четырёх источников — `services`, `policies`, `policy_files_dir`, `raw_policies` — и складываются. Одно имя в двух источниках валит `plan`: `merge()` оставил бы только последний, а остальные определения потерялись бы молча.

⚠️ `policy_files_dir` по умолчанию `"policies"`, то есть модуль **сам читает `<корневой конфиг>/policies/*.hcl`**, ничего не спрашивая. Отсутствие каталога безопасно — файловых политик просто не будет. Но если каталог с таким именем у вас уже есть под что-то постороннее, его файлы молча станут политиками Vault. Не пользуетесь файловыми политиками — поставьте `policy_files_dir = null` явно, как во всех примерах. Дефолт оставлен прежним намеренно: смена его на `null` тихо удалила бы политики у тех, кто на неявный подхват полагается, а пропавшая политика хуже лишней.

## Выходы

`policies`, `kubernetes_auth_paths`, `kubernetes_roles`, `jwt_login_path`, `jwt_roles`, `approle_login_path`, `approle_role_ids`.

## JWT / OIDC роли

Если роли уже живут в `auth/jwt/role`, бэкенд трогать не нужно — модуль по умолчанию только кладёт под него роли:

```hcl
module "access" {
  source = "git::https://github.com/AndreyZa/terraform-module-vault.git?ref=v2.1.0"

  kv_mount   = "secret"
  kv_version = 1

  policies = {
    "billing-ro" = { read_paths = ["apps/billing/prod"] }
  }

  jwt_path = "jwt"          # где уже стоит метод

  jwt_roles = {
    "billing-ci" = {
      policies        = ["billing-ro"]
      user_claim      = "sub"                              # что попадёт в аудит
      bound_audiences = ["https://vault.example.internal"] # кому выписан токен
      bound_claims = {                                     # что ещё должно совпасть
        project_path = "platform/billing"
        ref          = "main"
      }
    }
  }
}
```

Роль обязана быть чем-то ограничена — `bound_audiences`, `bound_subject` или `bound_claims`. Иначе токен получит любой предъявитель валидного JWT от этого issuer'а; модуль валит такой `plan`.

Для шаблонов в значениях (ветки, окружения, репозитории) — `bound_claims_type = "glob"`, тогда работает `ref = "release/*"`. Режим общий для всей карты, не для отдельного claim'а.

### Путь движка

Роли всегда ложатся в `auth/<jwt_path>/role/<имя>`. Если метод поднят не на `jwt`, а, скажем, на `jwt_v2`:

```hcl
jwt_path = "jwt_v2"   # → auth/jwt_v2/role/test-terraform-ro, логин: auth/jwt_v2/login
```

Один вызов модуля работает с одним путём. Нужны роли сразу в нескольких (`jwt` и `jwt_v2`) — два вызова модуля с разными `jwt_path`.

### Аудитория

`aud` в токене — это адрес того Vault, для которого issuer его выписал. Он один на всю установку, поэтому задаётся один раз, а роли наследуют:

```hcl
default_bound_audiences = ["https://vault.example.internal"]

services = {
  "billing" = {
    read_paths   = ["apps/billing/prod"]
    bound_claims = { project_id = "42" }
    # bound_audiences не пишем — берётся общий
  }
}
```

Модуль не может подставить адрес сам: он живёт в конфигурации провайдера, а её модуль не видит.

Роль может задать свой список или отказаться от проверки — `bound_audiences = []`; тогда ограничением обязаны служить `bound_claims` или `bound_subject`, иначе `plan` не пройдёт.

### Токены: дефолты

| | значение | что делает |
|---|---|---|
| `token_ttl` | 10 мин | сколько живёт свежий токен |
| `token_max_ttl` | 15 мин | докуда его можно продлевать |
| `token_explicit_max_ttl` | 15 мин | жёсткий потолок: по истечении токен отзывается, продление не спасает |
| `token_bound_cidrs` | `127.0.0.0/8`, `10.0.0.0/8` | откуда токен вообще принимается |
| `user_claim` | `project_id` | что становится именем сущности в аудите |

Меняются глобально через `default_token_*` / `default_token_bound_cidrs` либо точечно в роли. Снять ограничение по сети у одной роли — `token_bound_cidrs = []` (пустой список, не `null`: `null` означает «взять общий»).

Порядок в `token_bound_cidrs` ни на что не влияет: провайдер отдаёт список множеством, и Vault хранит его в своём порядке независимо от того, как написано в конфиге. Diff от перестановки не возникает.

### Долгоживущий токен

Токен, выданный ролью, ограничен её же настройками — «продлить подольше» на стороне клиента нельзя. Долгая жизнь бывает двух видов.

**Периодический** — живёт бесконечно, пока его продлевают не реже `token_period`. Дефолтные потолки нужно снять, иначе они его прижмут:

```hcl
jwt_roles = {
  "gitlab-role-terraform-periodic" = {
    policies     = ["ro-stg-gitlab-terraform"]
    bound_claims = { project_id = "42" }

    token_period           = 86400 # сутки
    token_ttl              = 0     # иначе TTL возьмётся из дефолта
    token_max_ttl          = 0     # иначе прижмёт до 15 минут
    token_explicit_max_ttl = 0     # иначе отзовёт, сколько ни продлевай
  }
}
```

`token_period` вместе с ненулевым `token_max_ttl` **или** `token_explicit_max_ttl` валит `plan`: любой из потолков сильнее продления — на живом Vault роль с `period = 86400` и `token_max_ttl = 900` выдаёт токен с `ttl = 899`, и `renew` его не поднимает. `token_period = 0` — «не периодический», такой конфиг легален и ничего не требует.

**Просто длинный** — конечный срок, дальше перелогин:

```hcl
    token_ttl              = 604800  # 7 дней
    token_max_ttl          = 2592000 # 30 дней
    token_explicit_max_ttl = 0
```

Обе формы всё равно требуют логина по JWT, то есть валидного токена от issuer'а. Если нужен статичный токен, не привязанный к пайплайну, — его выдают не ролью, а напрямую под политику:

```bash
vault token create -policy=ro-stg-gitlab-terraform -period=768h -display-name=terraform-static
```

Такой токен придётся хранить и вовремя отзывать (`vault token revoke`), поэтому для CI обычно оставляют короткий логин на каждый прогон.

`token_ttl` больше `token_explicit_max_ttl` валит `plan`: иначе токен отзывался бы раньше, чем истекал его собственный TTL.

### bound_claims: значения

`bound_claims` — это `map(string)`; несколько допустимых значений перечисляются через запятую и работают как ИЛИ:

```hcl
bound_claims = {
  project_id    = "42"        # Vault покажет map[project_id:[42]]
  ref           = "main"
  ref_protected = "true"
}
```

```hcl
bound_claims = {
  project_id = "42,57,91"     # Vault покажет map[project_id:[42 57 91]]
}
```

**Тип значения в токене должен совпадать.** Сравнение не приводит число к строке: если issuer положил `"project_id": 42` числом, а в политике написано `"42"`, логин отвалится с `claim "project_id" does not match any associated bound claim values`. GitLab отдаёт `project_id` строкой, но проверять стоит по факту:

```bash
cut -d. -f2 <<< "$TOKEN" | base64 -d 2>/dev/null | python3 -m json.tool
```

Вложенный claim адресуется через `/`: `bound_claims = { "metadata/team" = "platform" }`.

Конфиг самого метода (issuer, ключи, discovery) можно забрать под Terraform: `manage_jwt_backend = true` + `jwt_backend = {...}` и `terraform import module.<имя>.vault_jwt_auth_backend.this[0] jwt`. По умолчанию выключено намеренно: роли меняются часто, а конфиг метода заводят один раз, и перетереть его чужим apply — уронить логин всем сразу.

## KV v1 и v2

Версия движка меняет не синтаксис политики, а пространство путей, поэтому одна и та же запись `read_paths = ["apps/demo/prod"]` при `kv_mount = "secret"` разворачивается по-разному:

| | KV v1 (`kv_version = 1`, по умолчанию) | KV v2 (`kv_version = 2`) |
|---|---|---|
| чтение | `secret/apps/demo/prod` → `read` | `secret/data/…` → `read`, `secret/metadata/…` → `read`, `list` |
| запись | `…` → `create`, `read`, `update`, `list` | `data/…` → `create`, `read`, `update`, `patch`, `delete`; `metadata/…` → `read`, `list`; `delete/…` и `undelete/…` → `update` |
| обход дерева | `…` → `list` | `metadata/…` → `list` |
| `allow_destroy = true` | добавляет `delete` (в v1 оно сразу безвозвратное) | добавляет `destroy/…` → `update` и `create`, `update`, `delete` по `metadata/…` |

**`kv_version` обязан совпадать с реальной версией маунта.** Политика, выписанная не под ту версию, синтаксически верна, применяется без единой ошибки и не даёт никаких прав — это самая частая причина «политика есть, а 403». Проверить: `vault read sys/mounts/<kv_mount>` → `options.version` (у v1 поле обычно пустое).

Мягкого удаления в v1 нет, поэтому `write_paths` там не выдаёт `delete` — только с явным `allow_destroy = true`. В v2 `write_paths` даёт мягкое удаление во всех трёх его формах, а безвозвратные `destroy/` и снос `metadata` — лишь по `allow_destroy`.

Форм мягкого удаления в v2 действительно три, и права им нужны разные:

| команда | эндпоинт | нужное право |
|---|---|---|
| `vault kv delete <path>` | `DELETE data/<path>` | `delete` на `data/` |
| `vault kv delete -versions=N <path>` | `POST delete/<path>` | `update` на `delete/` |
| `vault kv undelete -versions=N <path>` | `POST undelete/<path>` | `update` на `undelete/` |

Первая строка — самая обычная команда, и именно её легко упустить: право на `delete/<path>` её не покрывает, потому что CLI без `-versions` бьёт в `data/`. Все три `write_paths` выдаёт разом. `delete` на `data/` при этом остаётся мягким: секрет скрывается, `undelete` возвращает прежнее значение, `destroy` без `allow_destroy` по-прежнему запрещён.

**Запись в `metadata/` писателю не выдаётся** — только чтение и `list`. Причина проверена на живом Vault: `create`/`update` на `metadata/` позволяют `vault kv metadata put -max-versions=1`, после чего следующая запись безвозвратно вытесняет всю историю секрета — то есть обходят `allow_destroy = false` целиком. Кому нужно писать custom-metadata — выдайте точечно:

```hcl
raw_path_capabilities = {
  "secret/metadata/apps/demo" = ["update"]
}
```

С `allow_destroy = true` запись в `metadata/` есть: там стирание уже разрешено явно.

### Микс маунтов в одной политике

Верхнеуровневые `*_paths` относятся к `kv_mount`. Пути с других маунтов — включая другую версию KV — добавляются через `mounts`:

```hcl
policies = {
  "ro-stg-gitlab-terraform" = {
    read_paths = ["k8s/test"]          # platform-infra, kv2

    mounts = [
      {
        mount      = "legacy"
        kv_version = 1
        read_paths = ["old/app"]       # legacy, kv1
      }
    ]
  }
}
```

Раскрывается в одну политику, где каждый маунт разложен по своим правилам:

```hcl
path "platform-infra/data/k8s/test"     { capabilities = ["read"] }
path "platform-infra/metadata/k8s/test" { capabilities = ["read", "list"] }
path "legacy/old/app"                   { capabilities = ["read"] }
```

`kv_version` внутри `mounts` необязателен — без него берётся общий.

### Точный набор прав

`read_paths` / `write_paths` — готовые наборы. Когда нужен именно свой (например, писать, но не читать), есть `path_capabilities`: путь → capabilities как есть.

```hcl
policies = {
  "drop-box" = {
    path_capabilities = {
      "k8s/writeonly" = ["create", "update"]
    }
  }
}
```

Права ложатся на путь данных (`<mount>/<путь>` в v1, `<mount>/data/<путь>` в v2) и складываются с остальными правилами на тот же путь. Внутри `mounts` поле тоже доступно. Допустимые значения — `create`, `read`, `update`, `patch`, `delete`, `list`, `sudo`, `deny`; опечатка валит `plan`.

Метаданные (`metadata/`, `delete/`, `destroy/`) этим полем не затрагиваются — если нужны и они, добавьте путь в `write_paths` или опишите строфу в `extra_rules`.

### Пути вне KV

`auth/`, `sys/`, `transit/` и прочее живут не в KV-маунте, поэтому для них отдельное поле — `raw_path_capabilities`: путь берётся как есть, без префикса и без оглядки на версию.

```hcl
policies = {
  "ro-stg-gitlab-terraform" = {
    read_paths = ["k8s/test"]

    raw_path_capabilities = {
      "auth/token/create" = ["create", "update"]
    }
  }
}
```

Правила складываются с остальными по тому же слиянию путей.

Заметьте: встроенная политика `default` **уже даёт** `auth/token/lookup-self`, `renew-self`, `revoke-self` и `sys/capabilities-self`, а её получает каждый токен. Выписывать их отдельно нужно только при `token_no_default_policy = true` на роли.

`auth/token/create` — право выпускать дочерние токены; именно оно нужно провайдеру `vault`, когда у него не выставлен `skip_child_token`.

### claim_mappings и шаблонные пути

`claim_mappings` кладёт claim'ы из токена в метаданные, имена ключей — любые свои:

```hcl
claim_mappings = {
  project_path  = "project" # claim → ключ метаданных
  ref           = "branch"
  user_login    = "actor"
  ref_protected = "protected"
}
```

После логина они видны и в токене, и в alias сущности:

```
actor: andrey   branch: main   project: platform/test-terraform   protected: true
```

По ним можно строить путь прямо в политике — один шаблон вместо политики на каждый проект:

```hcl
extra_rules = <<-EOT
  path "platform-infra/data/{{identity.entity.aliases.auth_jwt_326da3fe.metadata.project}}/*" {
    capabilities = ["read"]
  }
EOT
```

Accessor метода берётся из `vault auth list -format=json`. Значение со слэшем (`platform/test-terraform`) работает — путь просто становится глубже.

Шаблон Vault пишется в **двойных фигурных скобках** и доллара не содержит, поэтому экранировать в `extra_rules` нечего. `$${...}` — синтаксис Terraform; Vault его не понимает и молча не сматчит путь, политика при этом выглядит правдоподобно.

Пути из `read_paths`, `write_paths` и `list_paths` можно пересекать: правила складываются по путям, и на один путь всегда приходится ровно одна `path`-строфа с объединёнными capabilities в каноническом порядке. (Современный Vault и сам объединяет повторные строфы — проверено на 2.0.3, — но это поведение менялось между версиями; единая строфа не полагается на него и не «дрожит» в diff.)

Исключение — `deny`: он побеждает все остальные права строфы, поэтому путь, попавший и в `*_paths`, и в `path_capabilities` с `deny`, после слияния молча терял бы добавленные права. Такой конфликт валит `plan`. `deny` на отдельном пути легален — это другая строфа, и там он работает как задумано.

Всё, что не ложится в шаблон (`sys/`, `transit/`, шаблоны с `{{identity.*}}`), пишется файлом в `policy_files_dir`. Читается только верхний уровень каталога — `policies/team/x.hcl` молча не попадёт. Файлу через `templatefile` передаются `mount`, `kv_version`, `data_prefix` и `metadata_prefix` (`""`/`""` для v1, `"data/"`/`"metadata/"` для v2), литеральный доллар экранируется удвоением. Права на KV лучше описывать через `policies`, а файлом — то, что от версии не зависит: файловые политики модуль не разбирает, и их пересечения с генерируемыми строфами никак не проверяются.

## Что проверяется до применения

Всё перечисленное валит `plan`. Мягких предупреждений модуль не использует: `check` в Terraform не останавливает `apply`, и до 2.0 коллизии имён так и уезжали в прод.

`validation` — на входах:

- неизвестное право или **пустой список прав** в `path_capabilities` / `raw_path_capabilities` / `mounts[*].path_capabilities` (и то и другое молча давало бы строфу `capabilities = []`, которую Vault принимает и которая не даёт ничего). Допустимые права: `create`, `read`, `update`, `patch`, `delete`, `list`, `subscribe`, `recover`, `sudo`, `deny`;
- `kv_version` не `1`/`2` — в том числе внутри `mounts[*]`, где иное значение молча трактовалось бы как v1;
- `role_type` не `jwt`/`oidc`, `bound_claims_type` не `string`/`glob`;
- `kv_mount` или `mounts[*].mount` пустой, с ведущим/завершающим слэшем либо с `//` — Vault нормализует путь маунта, политика остаётся как написана и молча не матчит;
- элементы `read_paths` / `write_paths` / `list_paths` и ключи `path_capabilities` / `raw_path_capabilities` пустые, со слэшами по краям или с `//` — по той же причине;
- пустые ключи карт (`policies`, `services`, `jwt_roles`, `raw_policies`, `approle_roles`, `clusters`, `k8s_roles`) — plan проходил, apply падал посреди прогона с криптичным 405;
- отрицательные TTL, `token_period`, `secret_id_ttl`, `secret_id_num_uses`;
- пустой `user_claim`, пустые или со слэшами по краям `jwt_path` / `approle_path`;
- `default_lease_ttl` / `max_lease_ttl` кластера не Go-длительность (`"1h"`, `"30m"`).

`precondition` — на ресурсах:

- роль ссылается на политику, которой нет в конфиге (Vault такую роль создаёт молча, логин проходит, прав нет) — описать политику либо внести имя в `external_policies`;
- JWT-роль ничем не ограничена (нет ни `bound_audiences`, ни `bound_subject`, ни `bound_claims`);
- JWT-роль с `role_type = "oidc"` без `allowed_redirect_uris`;
- `jwt_backend` не задаёт ровно один способ проверки подписи (ноль способов — тоже ошибка);
- роль привязана к кластеру, которого нет в `clusters`;
- `disable_local_ca_jwt = true` без `ca_cert`/`token_reviewer_jwt` — Vault снаружи кластера получит 401 на каждом TokenReview;
- `bound_service_account_names = ["*"]` вместе с `namespaces = ["*"]`;
- имя политики не в нижнем регистре (Vault приводит к lowercase → вечный diff);
- политика без единой `path`-строфы — хоть пустая, хоть из одних комментариев: Vault принимает такую молча, а прав она не даёт;
- `deny` смешан с другими правами на одном пути — deny побеждает, добавленные права молча не работали бы;
- одно имя политики из двух источников; одно имя роли и в `services`, и в `jwt_roles`;
- `token_ttl` больше `token_explicit_max_ttl` — для всех трёх типов ролей;
- `token_period` вместе с ненулевым `token_max_ttl` **или** `token_explicit_max_ttl` — для всех трёх типов ролей. Прижимают оба: на живом Vault роль с `period = 86400` и `token_max_ttl = 900` выдаёт токен с `ttl = 899`, и `renew` его не поднимает. `token_period = 0` — «не периодический», это не ошибка.

Пересечение `read_paths` / `write_paths` / `list_paths` **не** запрещено: правила складываются по путям, на один путь всегда приходится ровно одна `path`-строфа с объединёнными capabilities.

Порядок гарантирован: роли зависят от `vault_policy.this`, поэтому в одном apply политика создаётся раньше роли.

## Импорт существующих объектов

Если политика и роль уже заведены руками, их нужно забрать в стейт — иначе `apply` создаст их заново поверх (политику перепишет, роль перетрёт).

Одна запись `services` — это два объекта, импортируются оба:

```bash
terraform import 'module.access.vault_policy.this["test-terraform-ro"]' test-terraform-ro
terraform import 'module.access.vault_jwt_auth_backend_role.this["test-terraform-ro"]' auth/jwt_v2/role/test-terraform-ro
```

Идентификаторы по типам:

| Ресурс | ID для импорта |
|---|---|
| `vault_policy.this["<имя>"]` | `<имя>` |
| `vault_jwt_auth_backend_role.this["<имя>"]` | `auth/<jwt_path>/role/<имя>` |
| `vault_jwt_auth_backend.this[0]` | `<jwt_path>` |
| `vault_auth_backend.approle[0]` | `<approle_path>` |
| `vault_approle_auth_backend_role.this["<имя>"]` | `auth/<approle_path>/role/<имя>` |
| `vault_auth_backend.kubernetes["<кластер>"]` | `<auth_path>` (по умолчанию `kubernetes/<кластер>`) |
| `vault_kubernetes_auth_backend_config.this["<кластер>"]` | `auth/<auth_path>/config` |
| `vault_kubernetes_auth_backend_role.this["<кластер>/<роль>"]` | `auth/<auth_path>/role/<роль>` |
| `vault_mount.kv[0]` | `<kv_mount>` |

`module.<имя>.` в адресе — имя вашего `module` блока.

После импорта сделайте `terraform plan`: он покажет, чем живой объект отличается от описанного. У политики почти всегда будет расхождение в шапке — модуль добавляет комментарий «сгенерирована Terraform», — а вот отличия в `path` или `capabilities` означают, что описание разошлось с реальностью, и стоит разобраться до `apply`.

Что уже есть в Vault: `vault policy list`, `vault list auth/<jwt_path>/role`, `vault read auth/<jwt_path>/role/<имя>`.

## Снять объект с управления, не удаляя из Vault

Переключить `manage_kv_mount` / `manage_jwt_backend` / `manage_approle_backend` в `false` — это **не** «перестать управлять»: Terraform планирует destroy, а уничтожение auth-бэкенда сносит все роли под ним и ломает логин всем сразу (проверено на живом Vault — apply бодро рапортовал «1 destroyed», роли исчезали, state о них ещё помнил). Поэтому на KV-маунте и обоих бэкендах стоит `prevent_destroy`: такой plan упирается в ошибку `Instance cannot be destroyed` вместо тихой катастрофы.

Правильный порядок — сначала забыть объект в state, потом выключить флаг:

```bash
terraform state rm 'module.<имя>.vault_mount.kv[0]'              # для manage_kv_mount
terraform state rm 'module.<имя>.vault_jwt_auth_backend.this[0]' # для manage_jwt_backend
terraform state rm 'module.<имя>.vault_auth_backend.approle[0]'  # для manage_approle_backend
```

Kubernetes-бэкендов это не касается: удаление кластера из `clusters` — штатный teardown, он и должен удалять маунт (вместе с ролями этого кластера — убирайте их из `k8s_roles` тем же коммитом). Помните, что смена ключа кластера или `auth_path` — это тоже destroy+create.

## Обновление с 2.0.0 на 2.1.0

Адреса ресурсов не менялись. Два изменения затрагивают выданные права и поведение plan:

- **Писатель теряет запись в `metadata/`** (KV v2, `allow_destroy = false`): `plan` покажет in-place правку политик — `metadata/…` сужается до `read, list`. Это закрытие обхода: `create`/`update` на `metadata/` позволяли безвозвратно стереть историю секрета через `max-versions=1`. Если чей-то workflow писал custom-metadata — верните право точечно через `raw_path_capabilities` (пример в разделе про KV).
- **Toggle `manage_*` в `false` теперь блокируется** `prevent_destroy` вместо тихого уничтожения бэкенда со всеми ролями. Порядок отключения — раздел «Снять объект с управления».

Остальное строже только там, где раньше был молчаливый отказ или падение на apply: deny-конфликт, пустые списки прав, кривые элементы путей, пустые ключи карт, отрицательные TTL валят `plan`. Единственное послабление: `token_period = 0` больше не считается периодическим токеном — в 2.0.0 такой конфиг ложно валил `plan`.

`jwt_validation_pubkeys` теперь обрезаются `trimspace`: у кого ключ шёл из `file()`, исчезнет вечный diff на `vault_jwt_auth_backend`.

## Обновление с 1.x на 2.0

**Поднялась нижняя граница Terraform: с 1.5 до 1.12.** Причина — в разделе «Требования» выше. Обновлять Terraform придётся до перехода на 2.0.

Адреса ресурсов не изменились — `moved`-блоки и импорт не нужны. Но `plan` теперь падает там, где 1.x молча продолжал, поэтому обновляться стоит не в тот же заход, что и правку прав.

**Что чинить перед обновлением:**

| Что | Было в 1.x | Стало в 2.0 |
|---|---|---|
| AppRole с непустым `approle_roles` | `plan` падал с `Unsupported attribute` на `token_period` — метод был нерабочим целиком | работает; появились `token_period` и `token_no_default_policy` |
| Опечатка в capability | правило молча превращалось в `capabilities = []`: политика применялась, прав не давала | валит `plan` |
| `mounts[*].kv_version` кроме `1`/`2` | молча трактовалось как v1 | валит `plan` |
| Одно имя политики или роли из двух источников | `Warning` в plan, `apply` шёл, побеждал последний источник | валит `plan` |
| `token_ttl` > `token_explicit_max_ttl`, `token_period` с потолком | проверялось только у JWT-ролей | проверяется у kubernetes и AppRole тоже |

Прогоните `terraform plan` до мержа: если модуль ругается на коллизию имён или на capability, значит в 1.x эта часть конфига уже не работала так, как выглядела.

**`manage_approle_backend`** появился со значением `true`, а не `false` как у `manage_kv_mount` и `manage_jwt_backend`, — именно чтобы обновление ничего не сломало: в 1.x бэкенд создавался безусловно, и дефолт `false` снёс бы его вместе со всеми ролями. Если AppRole-бэкенд у вас заведён вне Terraform, поставьте `false` явно.

## Версионирование

Релизы помечаются тегами `vX.Y.Z`; в `source` всегда указывается `?ref=` на тег, а не на ветку — иначе очередной коммит в `main` уедет в прод при ближайшем `terraform init -upgrade`.

- **major** — несовместимая правка входов/выходов или изменение адресов ресурсов (потребителю нужны `moved`-блоки или импорт);
- **minor** — новые входы с дефолтами, новые проверки;
- **patch** — правки, не меняющие поведение.

## Примеры

- [examples/service](examples/service) — одна запись `services`: политика + роль;
- [examples/jwt](examples/jwt) — то же раздельными `policies` и `jwt_roles`;
- [examples/minimal](examples/minimal) — политика, роль kubernetes и AppRole.

Все три проверяются через `terraform init && terraform validate`; применять не обязательно.

## Локальная разработка модуля

Чтобы не тегировать каждый шаг, у потребителя временно подменяют источник на путь:

```hcl
module "access" {
  source = "../../terraform-module-vault"  # временно, вернуть на git:: перед мержем
}
```

После правок:

```bash
terraform fmt -recursive
terraform test          # в корне модуля
```

`terraform test` живого Vault не требует: все прогоны — `command = plan`, тело политики известно до `apply`. В [tests/](tests) проверяются раскладка путей v1/v2, слияние пересекающихся путей, микс маунтов и все `precondition`/`validation`.

CI гоняет тесты на двух версиях — `1.12.0` (объявленная нижняя граница) и `latest`. Прогон на границе здесь не формальность: расхождение в вычислении `||` между 1.11 и 1.12 ловится только так.

**`terraform validate` одного его не заменяет.** Terraform не типизирует `each.value` статически, поэтому обращение к несуществующему полю объекта `validate` проходит и падает только на `plan` — ровно так в 1.7.0 уехал сломанный AppRole. Тесты этот класс ошибок ловят, `validate` — нет.

## Лицензия

MIT, см. [LICENSE](LICENSE).
