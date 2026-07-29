# terraform-module-vault

Terraform-модуль для прав доступа в Vault: политики и роли (`jwt`/`oidc`, `kubernetes`, `approle`). Значения секретов в KV модуль не трогает — только права на них.

Провайдер модуль не конфигурирует: адрес, CA и способ логина задаёт корневой конфиг. Один вызов модуля = один Vault.

Требования: Terraform >= 1.5, провайдер `hashicorp/vault` ~> 4.4.

## Вызов

Обычный случай — сервису нужны свои пути и свой вход. Одна запись в `services` создаёт политику и роль под одним именем, уже связанные между собой:

```hcl
module "access" {
  source = "git::https://github.com/AndreyZa/terraform-module-vault.git?ref=v1.2.0"

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
| `policies` | `map(object)` | `{}` | политики из путей: `read_paths` / `write_paths` / `list_paths` / `allow_destroy` / `extra_rules` |
| `policy_files_dir` | `string` | `"policies"` | каталог с рукописными `*.hcl`, **путь от корневого конфига** |
| `raw_policies` | `map(string)` | `{}` | политики готовым HCL, если он собирается у вызывающего |
| `external_policies` | `list(string)` | `[]` | чужие политики, на которые ролям разрешено ссылаться |
| `clusters` | `map(object)` | `{}` | кластеры: `host`, `ca_cert`, `auth_path`, `disable_local_ca_jwt`, TTL маунта |
| `token_reviewer_jwts` | `map(string)`, sensitive | `{}` | JWT `vault-tokenreviewer` по кластерам |
| `k8s_roles` | `map(map(object))` | `{}` | `{ кластер = { роль = { namespaces, service_accounts, policies, … } } }` |
| `default_token_ttl` / `default_token_max_ttl` | `number` | `3600` / `14400` | TTL для ролей, где он не задан |
| `jwt_path` | `string` | `"jwt"` | путь JWT/OIDC-бэкенда; роли лягут в `auth/<jwt_path>/role/<имя>` |
| `manage_jwt_backend` | `bool` | `false` | управлять ли конфигом самого метода (issuer, ключи) |
| `jwt_backend` | `object` | `{}` | конфиг метода — только при `manage_jwt_backend = true` |
| `jwt_roles` | `map(object)` | `{}` | роли JWT/OIDC: `policies`, `user_claim`, `bound_audiences`, `bound_claims`, … |
| `approle_path` | `string` | `"approle"` | путь AppRole-бэкенда |
| `approle_roles` | `map(object)` | `{}` | роли AppRole: `policies`, TTL, ограничения по CIDR |

Три источника политик (`policies`, `policy_files_dir`, `raw_policies`) складываются; одно имя в двух источниках ловит `check`.

## Выходы

`policies`, `kubernetes_auth_paths`, `kubernetes_roles`, `jwt_login_path`, `jwt_roles`, `approle_login_path`, `approle_role_ids`.

## JWT / OIDC роли

Если роли уже живут в `auth/jwt/role`, бэкенд трогать не нужно — модуль по умолчанию только кладёт под него роли:

```hcl
module "access" {
  source = "git::https://github.com/AndreyZa/terraform-module-vault.git?ref=v1.1.0"

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

Для шаблонов в значениях (ветки, окружения, репозитории) — `bound_claims_type = "glob"`, тогда работает `ref = "release/*"`.

Конфиг самого метода (issuer, ключи, discovery) можно забрать под Terraform: `manage_jwt_backend = true` + `jwt_backend = {...}` и `terraform import module.<имя>.vault_jwt_auth_backend.this[0] jwt`. По умолчанию выключено намеренно: роли меняются часто, а конфиг метода заводят один раз, и перетереть его чужим apply — уронить логин всем сразу.

## KV v1 и v2

Версия движка меняет не синтаксис политики, а пространство путей, поэтому одна и та же запись `read_paths = ["apps/demo/prod"]` при `kv_mount = "secret"` разворачивается по-разному:

| | KV v1 (`kv_version = 1`, по умолчанию) | KV v2 (`kv_version = 2`) |
|---|---|---|
| чтение | `secret/apps/demo/prod` → `read` | `secret/data/…` → `read`, `secret/metadata/…` → `read`, `list` |
| запись | `…` → `create`, `read`, `update`, `list` | `data/…` → `create`, `read`, `update`, `patch`; `metadata/…` → `create`, `read`, `update`, `list`; `delete/…` и `undelete/…` → `update` |
| обход дерева | `…` → `list` | `metadata/…` → `list` |
| `allow_destroy = true` | добавляет `delete` (в v1 оно сразу безвозвратное) | добавляет `destroy/…` → `update` и `delete` по `metadata/…` |

**`kv_version` обязан совпадать с реальной версией маунта.** Политика, выписанная не под ту версию, синтаксически верна, применяется без единой ошибки и не даёт никаких прав — это самая частая причина «политика есть, а 403». Проверить: `vault read sys/mounts/<kv_mount>` → `options.version` (у v1 поле обычно пустое).

Мягкого удаления в v1 нет, поэтому `write_paths` там не выдаёт `delete` — только с явным `allow_destroy = true`. В v2 `write_paths` даёт `delete/` и `undelete/` (пометить версию удалённой и откатить), а безвозвратные `destroy/` и снос `metadata` — тоже лишь по `allow_destroy`.

Пути из `read_paths`, `write_paths` и `list_paths` можно пересекать: правила складываются по путям, и на один путь всегда приходится ровно одна `path`-строфа с объединёнными capabilities. (Из двух строф на один путь Vault оставляет последнюю — то есть без такой сборки пересечение молча урезало бы права.)

Всё, что не ложится в шаблон (`sys/`, `transit/`, шаблоны с `{{identity.*}}`), пишется файлом в `policy_files_dir`. Файлу через `templatefile` передаются `mount`, `kv_version`, `data_prefix` и `metadata_prefix` (`""`/`""` для v1, `"data/"`/`"metadata/"` для v2), литеральный доллар экранируется удвоением. Осторожно с путями KV в таких файлах: в v1 оба префикса пусты, и версионно-нейтральная запись даёт две одинаковые `path`-строфы, из которых Vault оставит последнюю. Права на KV лучше описывать через `policies`, а файлом — то, что от версии не зависит.

## Что проверяется до применения

`precondition` — валят `plan`:

- роль ссылается на политику, которой нет в конфиге (Vault такую роль создаёт молча, логин проходит, прав нет) — описать политику либо внести имя в `external_policies`;
- JWT-роль ничем не ограничена (нет ни `bound_audiences`, ни `bound_subject`, ни `bound_claims`);
- JWT-роль с `role_type = "oidc"` без `allowed_redirect_uris`;
- `jwt_backend` задаёт больше одного способа проверки подписи;
- роль привязана к кластеру, которого нет в `clusters`;
- `disable_local_ca_jwt = true` без `ca_cert`/`token_reviewer_jwt` — Vault снаружи кластера получит 401 на каждом TokenReview;
- `bound_service_account_names = ["*"]` вместе с `namespaces = ["*"]`;
- имя политики не в нижнем регистре (Vault приводит к lowercase → вечный diff);
- пустое тело политики.

`check` — предупреждают в plan: одно имя политики из двух источников; один путь и в `read_paths`, и в `write_paths` (вторая `path`-строфа перетирает первую).

Порядок гарантирован: роли зависят от `vault_policy.this`, поэтому в одном apply политика создаётся раньше роли.

## Версионирование

Релизы помечаются тегами `vX.Y.Z`; в `source` всегда указывается `?ref=` на тег, а не на ветку — иначе очередной коммит в `main` уедет в прод при ближайшем `terraform init -upgrade`.

- **major** — несовместимая правка входов/выходов или изменение адресов ресурсов (потребителю нужны `moved`-блоки или импорт);
- **minor** — новые входы с дефолтами, новые проверки;
- **patch** — правки, не меняющие поведение.

## Пример

- [examples/service](examples/service) — одна запись `services`: политика + роль;
- [examples/jwt](examples/jwt) — то же раздельными `policies` и `jwt_roles`;
- [examples/minimal](examples/minimal) — политика, роль kubernetes и AppRole.

Оба проверяются через `terraform init && terraform validate`; применять не обязательно.

## Локальная разработка модуля

Чтобы не тегировать каждый шаг, у потребителя временно подменяют источник на путь:

```hcl
module "access" {
  source = "../../terraform-module-vault"  # временно, вернуть на git:: перед мержем
}
```

После правок — `terraform fmt -recursive`, `terraform validate` в `examples/minimal` и у потребителя.
