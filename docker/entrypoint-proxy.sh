#!/bin/sh
set -e

DOMAIN="${DOMAIN:-autosectest.ru}"
LIVE_DIR="/etc/letsencrypt/live/${DOMAIN}"
ARCHIVE_DIR="/etc/letsencrypt/archive/${DOMAIN}"

# Если сертификата ещё нет — создаём самоподписанный, чтобы nginx мог стартовать
if [ ! -f "${LIVE_DIR}/fullchain.pem" ]; then
  echo "Certificate not found, creating self-signed for initial start..."
  mkdir -p "${ARCHIVE_DIR}" "${LIVE_DIR}"
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "${LIVE_DIR}/privkey.pem" \
    -out "${LIVE_DIR}/fullchain.pem" \
    -subj "/CN=${DOMAIN}"
  echo "Self-signed cert created. Run certbot to get a real certificate, then: docker compose exec proxy nginx -s reload"
fi

exec nginx -g "daemon off;"
