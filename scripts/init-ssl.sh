#!/bin/sh
# Первое получение SSL-сертификата Let's Encrypt для autosectest.ru
# Запускать после того, как DNS уже указывает на сервер и проект поднят (docker compose up -d).

set -e
DOMAIN="${DOMAIN:-autosectest.ru}"
EMAIL="${LETSENCRYPT_EMAIL:?Set LETSENCRYPT_EMAIL (e.g. admin@autosectest.ru)}"

echo "Getting certificate for ${DOMAIN} and www.${DOMAIN}..."
docker compose run --rm --entrypoint certbot certbot certonly --webroot \
  -w /var/www/certbot \
  -d "${DOMAIN}" \
  -d "www.${DOMAIN}" \
  --email "${EMAIL}" \
  --agree-tos \
  --non-interactive

echo "Reloading nginx to use new certificate..."
docker compose exec proxy nginx -s reload

echo "Done. Site should now be served over HTTPS."
