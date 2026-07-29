terraform {
  required_version = ">= 1.5"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.4"
    }
  }
}

# Провайдер здесь сознательно не конфигурируется: адрес, CA и способ логина —
# дело вызывающего корневого конфига (envs/*), иначе модуль нельзя применить
# к двум разным Vault из одного стейта.
