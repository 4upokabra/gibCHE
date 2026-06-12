# Развёртывание на HTTPS (autosectest.ru)

## 1. DNS-записи

В панели управления DNS домена **autosectest.ru** создайте записи, указывающие на IP вашего сервера:

| Тип  | Имя (хост) | Значение        | TTL (по желанию) |
|------|------------|-----------------|-------------------|
| **A**    | `@`  | `IP_ВАШЕГО_СЕРВЕРА` | 300–3600 |
| **A**    | `www`| `IP_ВАШЕГО_СЕРВЕРА` | 300–3600 |

Если у хостера есть IPv6:

| Тип     | Имя (хост) | Значение           | TTL (по желанию) |
|---------|------------|--------------------|-------------------|
| **AAAA**| `@`  | `IPv6_ВАШЕГО_СЕРВЕРА` | 300–3600 |
| **AAAA**| `www`| `IPv6_ВАШЕГО_СЕРВЕРА` | 300–3600 |

- **A** — для IPv4 (обязательно).
- **AAAA** — для IPv6 (по возможности).
- `@` — корень домена (autosectest.ru).
- `www` — поддомен (www.autosectest.ru).

Дождитесь обновления DNS (проверка: `dig autosectest.ru` или сервисы вроде dnschecker.org).

---

## 2. Запуск проекта

```bash
# Сборка и запуск
docker compose up -d
```

При первом запуске прокси поднимется с временным самоподписанным сертификатом (браузер покажет предупреждение — это нормально до получения сертификата Let's Encrypt).

---

## 3. Получение сертификата Let's Encrypt

После того как DNS указывает на сервер и контейнеры запущены:

```bash
# Укажите email для Let's Encrypt (уведомления об истечении)
export LETSENCRYPT_EMAIL=admin@autosectest.ru

# Получить сертификат (один раз)
chmod +x scripts/init-ssl.sh
./scripts/init-ssl.sh
```

Или вручную:

```bash
docker compose run --rm --entrypoint certbot certbot certonly --webroot \
  -w /var/www/certbot \
  -d autosectest.ru \
  -d www.autosectest.ru \
  --email YOUR_EMAIL@example.com \
  --agree-tos \
  --non-interactive

docker compose exec proxy nginx -s reload
```

После этого сайт будет доступен по **https://autosectest.ru** и **https://www.autosectest.ru**.

---

## 4. Продление сертификата

Автопродление можно включить, запустив контейнер certbot с профилем:

```bash
docker compose --profile certbot-renew up -d
```

Либо настройте cron на сервере:

```bash
0 3 * * * cd /path/to/gibCHE && docker compose run --rm certbot renew && docker compose exec proxy nginx -s reload
```

---

## 5. Переменные окружения

При необходимости в `.env` можно задать:

- `DOMAIN=autosectest.ru` — домен (по умолчанию уже autosectest.ru).
- `LETSENCRYPT_EMAIL` — используется скриптом `scripts/init-ssl.sh`.
