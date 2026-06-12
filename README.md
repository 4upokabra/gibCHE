# ReconScope

ReconScope — это операционный центр для специалистов по ИБ: мы объединяем расширенную разведку, оркестрацию атак и LLM-аналитику в единой платформе. Внедрили LLM на все этапы тестирования и разработали самостоятельного "автопентестера". Команда реализовала полный цикл «разведка → атака → анализ → рекомендации» с удобным веб-интерфейсом, Docker-инфраструктурой и наглядной отчётностью.

---

## Кратко о главном

- **Сканирование и разведка**: агрегируем данные Nmap, Shodan, VirusTotal, пассивного DNS, собственных сигнатур и cloud-инвентаризации. Для сетей/CIDR доступен массовый поиск активных хостов.
- **Автоматизированные атаки**: встроенный движок запускает Hydra-брутфорс, sqlmap, Metasploit RPC и проверку legacy-баннеров. Профили Black/Grey/White Box определяют, какие векторы разрешены.
- **LLM-пайплайн**: Playwright + Requests собирают контент, OpenRouter LLM формирует отчёты, а post-processing добавляет action summary, рекомендации и приоритизацию.
- **AutoPentest**: LLM запланирует последовательность шагов, оркестратор выполнит их (разведка → атака → отчёт), соберёт артефакты и финальную сводку.
- **Отчётность**: каждый запуск логируется, сохраняется как JSON и экспортируется в PDF/Markdown, есть кнопка «отправить в Jira/YouTrack».

---

## Архитектура

```
┌────────────┐    ┌──────────────────────┐    ┌──────────────┐
│ Frontend   │───▶│ FastAPI Backend      │───▶│ PostgreSQL DB │
└────────────┘    │ • Recon Engine       │    └──────────────┘
                  │ • Attack Engine      │            ▲
                  │ • LLM Pipeline       │            │
                  │ • AutoPentest        │            │
                  └──────────┬───────────┘            │
                             ▼                        │
                     Artifacts & Logs (volumes) ◀─────┘
```

- **Backend** (`Autoscan/src/api/backend_main.py`) — FastAPI-приложение, которое объединяет все модули и хранит историю запусков.
- **Recon Engine** (`src/recon/enhancde_passive.py`) — валидация целей, Nmap, Shodan, VirusTotal, DNS и сетевые сканы.
- **Attack Engine** (`src/attack/core.py`) — Hydra, sqlmap, Metasploit, LegacyAudit, retry-политики и SLA.
- **LLM Pipeline** (`llm/pipeline.py`) — crawler, промптинг и enrichment отчётов.
- **AutoPentest Orchestrator** (`src/autopentest/orchestrator.py`) — построение и выполнение цепочек действий.
- **Frontend** (`frontend/src/App.tsx`) — Command Hub, System Pulse, History Panel и Detail Drawer.

---

## Модули подробнее

### Recon Engine
- Поддерживает IP, домены и сетевые диапазоны.
- Запускает быстрый/полный Nmap, обращается к Shodan и VirusTotal, собирает DNS/WHOIS.
- Нормализует результаты и подсчитывает сводные Summary/action items.

### Attack Engine
- Встроенные модули: Hydra (bruteforce), sqlmap, Metasploit RPC и аудит устаревших версий.
- Профили TestingModel ограничивают векторы для Black/Grey/White Box.
- Все артефакты, команды и доказательства сохраняются в `artifacts/attack_runs`.

### LLM Pipeline
- Краулит до нескольких страниц Playwright/Requests, структуирует текст, формирует промпты и получает отчёт через OpenRouter (DeepSeek).
- Автоматически домешивает знания из контекстной базы (каталоги БДУ/ФСТЭК, CVE, MITRE).
- Генерирует action summary: короткий план remediation с приоритетами и ссылками.

### AutoPentest Orchestrator
- LLM генерирует план (audit → recon → scan → attack → report).
- Оркестратор исполняет шаги последовательно, учитывая профиль тестирования и найденные артефакты.
- По завершении формирует JSON и (опционально) LLM-репорт с итогами.

### Frontend
- Command Hub — единое место запуска сценариев (разведка, атака, LLM, авто-пентест).
- System Pulse — health-компоненты, счётчики задач, средний CVSS и статус сервисов.
- History Panel — фильтрация, поиск, скачивание JSON.
- Detail Drawer — summary, action plan, defensive/offensive действия и экспорт рекомендаций.
- AuthOverlay — парольная шторка (VITE_ACCESS_PASS) и сохранение доступа в localStorage.

---

## Работа с рисками и знаниями

- При старте загружаются словари `data/bdu_catalog.json` и `data/cve_index.json`.
- Каждая находка получает: связанные CVE, CVSS вектор, BDU ID, ссылки на PoC, упоминания в MITRE.
- Для рисков рассчитываем CVSS 3.1 + внутренний коэффициент (учитывает бизнес-важность, наличие эксплойтов и тип цели).
- Экспортный отчёт содержит блок «Как исправить» с привязкой к рекомендациям ФСТЭК/БДУ.

---

## Пользовательский опыт

- **Подсказки и пресеты** снижают порог входа: любой запуск можно сделать за несколько кликов.
- **Визуализация** — граф сервисов, диаграммы MITRE, таймлайн атак, тепловые карты рисков и сравнение «до/после».
- **Управление** — можно ставить задачи на паузу, отменять, перезапускать и клонировать; в истории видно каждое действие.
- **Аудит** — каждый event имеет UUID, timestamps, статус, источник и ссылку на артефакты.

---

## Развёртывание

### Требования
- Docker 24+ и docker compose v2.
- Порты: `417` (SPA), `8000` (API), `5432` (PostgreSQL), `55553` (Metasploit RPC, если нужен).
- Переменные окружения: `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `OPENROUTER_API_KEY`, `MSFRPC_*`, `VITE_ACCESS_PASS`.

### Быстрый старт
```bash
git clone git@github.com:alpiks/reconscope.git
cd reconscope
cp .env.example .env   # заполните ключи
docker compose up --build
```

Сервисы:
- `db` — PostgreSQL 15 (`intelligence_db`), миграции выполняются автоматически.
- `backend` — FastAPI + оркестратор атак, порт `8000`.
- `frontend` — Vite/React + Nginx, доступен по адресу http://localhost:4173.

### Конфигурация `.env`
```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/intelligence_db
SHODAN_API_KEY=xxx
VIRUSTOTAL_API_KEY=yyy
OPENROUTER_API_KEY=zzz
VITE_ACCESS_PASS=secret
MSFRPC_URL=http://metasploit:55553/api/
MSFRPC_TOKEN=token
```

### Полезные команды
- `docker compose logs -f backend` — смотреть health и прогресс задач.
- `docker compose exec backend bash` — запускать `nmap`, `hydra`, `sqlmap` из контейнера.
- `docker compose build frontend && docker compose up -d frontend` — hot reload SPA.
- Артефакты → `./artifacts`, логи → `./logs`, база → том `postgres_data`.

---

## API (фрагмент)

| Endpoint | Назначение |
| --- | --- |
| `GET /health` | Проверка компонентов (БД, Nmap, Shodan, VirusTotal, Attack Engine, LLM) |
| `POST /intelligence/basic` | Быстрая разведка IP/домен/сеть |
| `POST /scan/nmap` | Запуск quick/full/vuln/custom сканов |
| `POST /attack/execute` | Индивидуальный запуск bruteforce/sqlmap/metasploit/legacy |
| `POST /attack/run` | Пакетная атака по списку целей |
| `POST /llm/scan` | LLM-аудит веб-ресурса |
| `POST /autopentest/start` | Автоматизированный пентест с профилями тестирования |
| `GET /history` | История всех событий, экспорт JSON |

Swagger-документация доступна по `/docs`, расширенные описания в `docs/api.md`.

---

## Roadmap

| Релиз | ETA | Содержимое |
| --- | --- | --- |
| **0.3** | Декабрь 2025 | RBAC, SSO (SAML/OIDC), мульти-арендность, интеграции с Jira/YouTrack |
| **0.4** | Февраль 2026 | Поддержка ICS/OT профилей, дополнительные сигнатуры, MITRE ATT&CK for ICS |
| **0.5** | Май 2026 | SaaS-вариант, auto-scaling воркеров, каталог кастомных модулей атак |

Каждый релиз сопровождается чеклистами OWASP ASVS, автотестами и отдельным compliance-отчётом.

---

## Команда

- **Core & Integrations** — архитектура, единый формат событий, интеграции сканеров.
- **Attack Engine Lead** — Metasploit RPC, Hydra/sqlmap pipelines, профили тестирования.
- **LLM & Analytics** — Playwright crawler, prompt design, enrichment по БДУ/ФСТЭК и CVE.
- **Backend & Orchestration** — FastAPI, очередь задач, авторизация, аудит.
- **Frontend & UX** — Command Hub, визуализации, экспорт отчётов и onboarding.

---

## Дополнительные материалы

- `docs/demo_script.md` — пошаговый сценарий демонстрации (≈7 минут).
- `docs/integrations.md` — описание webhook-ов, экспортов в Jira/YouTrack.
- `artifacts/demo/` — примерные JSON/PDF-отчёты и action summary.
- `logs/attack_engine.log` — журнал действий атакующего движка.

---

ReconScope разворачивается на площадке организатора за несколько минут: нужен Docker и ключи к внешним сервисам. При адаптации под конкретный периметр достаточно описать новый профиль в `config/testing_profiles.yml` и перезапустить backend — система автоматически учтёт новые ограничения и сценарии.

