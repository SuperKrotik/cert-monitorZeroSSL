# cert_monitor

Автоматическое отслеживание и продление SSL-сертификатов (ZeroSSL) для доменов
DuckDNS на виртуальной машине cloud.ru с уведомлениями по email.

## Возможности

- Полуавтоматический трекинг доменов DuckDNS: список в конфиге, IP обновляется через DuckDNS API.
- Мониторинг сроков действия локальных сертификатов (`cryptography`).
- Продление через **certbot + ZeroSSL ACME (EAB)**, валидация **HTTP-01** через webroot nginx.
- Двухступенчатые уведомления: **за 7 дней** (предупреждение) и **за 1 день** (критично) до истечения.
- Автопродление на обоих событиях (7/1 день) с письмом-результатом:
  «продлено» / «продление не требуется» / ошибка (+ отдельное тревожное письмо).
- **Еженедельный отчёт**: таблица статусов всех сертификатов + **баланс и расходы Cloud.ru** за неделю.
- Установка выпущенных сертификатов в nginx (`nginx -t` + reload, с откатом при провале).
- Email-уведомления через SMTP (Brevo SMTP relay: STARTTLS 587).
- **Docker**: один контейнер (nginx + certbot + python + встроенный планировщик APScheduler),
  порты 80/443, секреты только через `secrets.env`.
- state-файл — без дублей уведомлений.

## Архитектура

```
┌──────────── cloud.ru VM (Ubuntu 22.04 + Docker) ─────────┐
│  Контейнер cert-monitor (1 шт., restart: unless-stopped)  │
│  ├─ nginx        :80 webroot (HTTP-01) + :443 HTTPS        │
│  ├─ certbot (pip): ACME ZeroSSL (EAB, webroot)             │
│  └─ cert_monitor (python)                                  │
│      └─ APScheduler                                        │
│          ├─ ежедневно 03:15 (UTC) → прогон монитора         │
│          ├─ еженедельно вс 09:00 → отчёт (сертов+cloud.ru)  │
│          └─ каждые 5 мин → IP DuckDNS                      │
└────────────────────────────────────────────────────────────┘
```

## Требования перед установкой

- VM cloud.ru с публичным IP; порты 80 и 443 открыты в security group; установлен Docker.
- Аккаунт DuckDNS и токен (`https://www.duckdns.org/domains`).
- Аккаунт ZeroSSL, API-ключ и **EAB-креды** (`https://app.zerossl.com/developer/credentials`).
- Аккаунт **Brevo** (`https://app.brevo.com`) для отправки писем через SMTP relay
  (не нужен личный почтовый аккаунт; ключ и логин — в разделе SMTP & API).
- Домены `*.duckdns.org` указывают на публичный IP VM.
- (опционально) IAM-ключ Cloud.ru для баланса и расходов в еженедельном отчёте.

## Установка на VM (Docker)

```bash
sudo bash install-docker.sh
```

Затем заполнить два файла:

1. `/etc/cert-monitor/config.yaml` — домены, пороги, пути, email адреса, секции `cloudru`/`scheduler`.
2. `/etc/cert-monitor/secrets.env` — секреты (DuckDNS, ZeroSSL, SMTP, Cloud.ru).

Скрипт соберёт образ и запустит контейнер с встроенным планировщиком.
Перезапуск после правки конфига: `docker compose restart cert-monitor`.

## Установка на VM (вручную, без Docker)

```bash
sudo bash install.sh
```
Сервисы: systemd-timer ежедневно 03:15 + таймер обновления IP каждые 5 минут.

## Проверка

```bash
docker compose ps
docker compose logs -f cert-monitor
docker compose exec cert-monitor python -m cert_monitor --duckdns-only
docker compose exec cert-monitor python -m cert_monitor --renew-dry-run   # проверка без изменений
docker compose exec cert-monitor python -m cert_monitor --weekly-report   # разовый еженедельный отчёт
```

## Структура конфига

См. `config.yaml.example`. Ключевые параметры:

| Параметр | Назначение | По умолчанию |
|---|---|---|
| `domains` | список доменов + webroot | обязателен |
| `duckdns.token` | токен DuckDNS | — |
| `zerossl.*` | API-ключ и EAB-креды | — |
| `certbot.renew_threshold_days` | порог автопродления | 14 |
| `notify.days` | пороги уведомлений | `[7, 1]` |
| `notify.smtp` | SMTP Brevo relay (логин + ключ) | — |
| `nginx.sites` | куда копировать сертификаты | пусто |
| `cloudru.*` | IAM-ключ, agreement, ручной баланс | выключено |
| `scheduler.*` | расписание встроенного планировщика | daily 03:15, weekly вс 09:00 |
| `paths` | пути к state/log/certs | /etc/... |

Секреты можно подставлять из переменных окружения как `{env:VAR}`
(в Docker — через `env_file`, ручные unit-файлы — через `EnvironmentFile`).

## Тесты (локально)

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Примечания по безопасности

- Секреты — только `/etc/cert-monitor/` с правами `600` (смонтированы read-only), в образе их нет.
- `nginx -t` перед reload; прежний сертификат сохраняется на место.
- В Docker reload nginx выполняется командой `nginx -s reload` внутри контейнера.
- Исходящий порт 25 у cloud.ru часто блокируется — поэтому SMTP на 587/465.