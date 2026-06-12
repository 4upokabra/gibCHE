#!/usr/bin/env bash
set -euo pipefail

# Деплой ReconScope на сервер (порт 8081)
# Использование на сервере:
#   cd /path/to/gibCHE
#   cp .env.example .env   # заполните ключи
#   bash scripts/deploy.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Сборка и запуск контейнеров..."
COMPOSE="docker-compose"
command -v docker-compose >/dev/null 2>&1 || COMPOSE="docker compose"

$COMPOSE down --remove-orphans 2>/dev/null || true
$COMPOSE build --no-cache
$COMPOSE up -d

echo "==> Ожидание backend..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8081/api/health >/dev/null 2>&1; then
    echo "OK: health"
    break
  fi
  sleep 2
done

echo "==> Проверка эндпоинтов"
curl -sf http://127.0.0.1:8081/api/ | head -c 200 && echo ""
curl -sf http://127.0.0.1:8081/api/autopentest && echo ""

echo "==> Готово: http://$(hostname -I | awk '{print $1}'):8081/"
