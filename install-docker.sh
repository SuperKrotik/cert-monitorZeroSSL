#!/usr/bin/env bash
#
# Установка cert_monitor в Docker (VM cloud.ru).
# Запуск от root:  sudo bash install-docker.sh
#
# Требования: установленный Docker (docker compose plugin).
#
set -euo pipefail

CONFIG_DIR="/etc/cert-monitor"
SECRETS_FILE="$CONFIG_DIR/secrets.env"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo -e "\e[1;32m[install]\e[0m $*"; }
err() { echo -e "\e[1;31m[error]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "запустите от root: sudo bash install-docker.sh"
command -v docker >/dev/null 2>&1 || err "docker не найден"
docker compose version >/dev/null 2>&1 || err "docker compose plugin не найден"

log "Каталог конфигурации: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

log "Копирование config.yaml.example -> config.yaml (если нет)..."
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    cp "$REPO_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
    chmod 600 "$CONFIG_DIR/config.yaml"
    log "Создан $CONFIG_DIR/config.yaml — заполните его."
fi

log "Копирование secrets.env.example -> secrets.env (если нет)..."
if [[ ! -f "$SECRETS_FILE" ]]; then
    cp "$REPO_DIR/secrets.env.example" "$SECRETS_FILE"
    chmod 600 "$SECRETS_FILE"
    log "Создан $SECRETS_FILE — заполните секреты."
fi

log "Сборка образа и запуск контейнера..."
docker compose build
docker compose up -d

log "=== Установка завершена ==="
log "1. Заполните:     $CONFIG_DIR/config.yaml"
log "2. Заполните:     $SECRETS_FILE"
log "3. После правки:  docker compose exec cert-monitor python -m cert_monitor --duckdns-only"
log "4. Логи:          docker compose logs -f cert-monitor"
log "5. dry-run:       docker compose exec cert-monitor python -m cert_monitor --renew-dry-run"
log "6. Weekly:        docker compose exec cert-monitor python -m cert_monitor --weekly-report"