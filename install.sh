#!/usr/bin/env bash
#
# Установка cert_monitor на Ubuntu (VM cloud.ru).
# Запуск от root:  sudo bash install.sh
#
set -euo pipefail

APP_DIR="/opt/cert-monitor"
CONFIG_DIR="/etc/cert-monitor"
STATE_DIR="/var/lib/cert-monitor"
LOG_DIR="/var/log/cert-monitor"
SECRETS_FILE="$CONFIG_DIR/secrets.env"
USER="certmon"

log() { echo -e "\e[1;32m[install]\e[0m $*"; }
err() { echo -e "\e[1;31m[error]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "запустите от root: sudo bash install.sh"

log "Обновление пакетов и установка зависимостей..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip certbot nginx curl

log "Создание пользователя $USER..."
if ! id "$USER" >/dev/null 2>&1; then
    useradd --system --create-home --shell /usr/sbin/nologin "$USER"
fi

log "Создание каталогов..."
mkdir -p "$APP_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" /var/www/certbot
chown -R "$USER:$USER" "$STATE_DIR" "$LOG_DIR"
chmod 750 "$STATE_DIR" "$LOG_DIR"

log "Копирование исходников в $APP_DIR..."
# При установке из клона репозитория скрипт находится в его корне;
# если мы внутри репозитория — копируем содержимое, иначе считаем, что код уже на месте.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/cert_monitor/main.py" ]]; then
    cp -a "$SCRIPT_DIR/cert_monitor" "$APP_DIR/"
    cp -a "$SCRIPT_DIR/systemd" "$APP_DIR/systemd"
    [[ -f "$SCRIPT_DIR/config.yaml.example" ]] && cp "$SCRIPT_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml.example"
else
    log "Исходники не найдены рядом со скриптом — предполагается, что код уже в $APP_DIR"
fi
chown -R root:"$USER" "$APP_DIR"
chmod -R g+rX "$APP_DIR"

log "Создание виртуального окружения и установка зависимостей..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt" || true

log "Создание конфигурации..."
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    if [[ -f "$CONFIG_DIR/config.yaml.example" ]]; then
        cp "$CONFIG_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
    else
        touch "$CONFIG_DIR/config.yaml"
    fi
    log "Создан $CONFIG_DIR/config.yaml — заполните его (копия example сохранена)."
fi
chown root:"$USER" "$CONFIG_DIR/config.yaml"
chmod 640 "$CONFIG_DIR/config.yaml"

if [[ ! -f "$SECRETS_FILE" ]]; then
    cat > "$SECRETS_FILE" <<'EOF'
# Секреты cert_monitor. Заполните реальные значения.
DUCKDNS_TOKEN=replace_me
ZEROSSL_API_KEY=replace_me
ZEROSSL_EAB_KID=replace_me
ZEROSSL_EAB_HMAC_KEY=replace_me
# Отправка писем через Brevo (SMTP relay): SMTP логин и SMTP key из Brevo -> SMTP & API.
SMTP_USERNAME=your_brevo_account@example.com
SMTP_APP_PASSWORD=your_brevo_smtp_key
NOTIFY_TO=replace_me@gmail.com
EOF
    chown root:"$USER" "$SECRETS_FILE"
    chmod 640 "$SECRETS_FILE"
    log "Создан $SECRETS_FILE — заполните секреты."
fi

log "Установка systemd-юнитов..."
cp "$APP_DIR/systemd/cert-monitor.service" /etc/systemd/system/
cp "$APP_DIR/systemd/cert-monitor.timer" /etc/systemd/system/
cp "$APP_DIR/systemd/cert-monitor-duckdns.service" /etc/systemd/system/
cp "$APP_DIR/systemd/cert-monitor-duckdns.timer" /etc/systemd/system/

# Использовать venv-интерпретатор в unit-файлах.
sed -i "s|/usr/bin/python3|$APP_DIR/.venv/bin/python3|" \
    /etc/systemd/system/cert-monitor.service \
    /etc/systemd/system/cert-monitor-duckdns.service

systemctl daemon-reload
systemctl enable --now cert-monitor.timer cert-monitor-duckdns.timer

log "=== Установка завершена ==="
log "1. Заполните:      $CONFIG_DIR/config.yaml"
log "2. Заполните:      $SECRETS_FILE"
log "3. Проверьте:      systemctl status cert-monitor"
log "4. Список таймеров: systemctl list-timers 'cert-monitor*'"
log "5. Ручной запуск:  sudo systemctl start cert-monitor"
