# cert_monitor: один контейнер (nginx + certbot + python-monitor + планировщик).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# nginx для webroot HTTP-01 и HTTPS; certbot (pip) для выпуска через ZeroSSL ACME.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx curl tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Копируем исходники и зависимости.
WORKDIR /opt/cert-monitor
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cert_monitor/ ./cert_monitor/
COPY docker/nginx-default.conf /etc/nginx/conf.d/default.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Каталоги, монтируемые как volume (конфиг/секреты/state/logs/letsencrypt/webroot).
RUN mkdir -p /etc/cert-monitor /var/lib/cert-monitor /var/log/cert-monitor \
    /etc/letsencrypt /var/www/certbot /etc/nginx/conf.d \
    && chmod 755 /entrypoint.sh

# Не слушаем по умолчанию — компиляция nginx-конфига выполняется в entrypoint.
EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:80/ >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]