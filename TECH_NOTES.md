# Техническая шпаргалка ReconScope

## Архитектура

```
Frontend (React/Vite) → FastAPI Backend → PostgreSQL
                           ↓
        Recon Engine | Attack Engine | LLM Pipeline | AutoPentest
                           ↓
        Nmap | Shodan | VirusTotal | Hydra | sqlmap | Metasploit RPC
```

## Технологический стек

**Backend:**
- FastAPI (Python 3.11)
- SQLAlchemy async + PostgreSQL
- asyncio для параллельных задач

**Frontend:**
- React + TypeScript + Vite
- Tailwind CSS
- Lucide icons

**Интеграции:**
- `nmap`, `hydra`, `sqlmap` (CLI)
- Shodan API, VirusTotal API
- OpenRouter API (LLM: DeepSeek)
- Metasploit RPC (опционально)
- Playwright (браузерный краулинг)

## Структура проекта

```
Autoscan/src/
├── api/backend_main.py          # FastAPI app, эндпойнты
├── recon/enhancde_passive.py     # Разведка (Nmap, Shodan, VT)
├── attack/core.py                # Атаки (Hydra, sqlmap, Metasploit)
├── autopentest/orchestrator.py   # AutoPentest оркестратор
├── core/
│   ├── database.py               # SQLAlchemy модели
│   ├── summaries.py              # Генерация summary
│   └── task_manager.py           # Управление задачами
└── integrations/                 # Обёртки для внешних API

llm/
├── pipeline.py                   # LLM-пайплайн (crawl → parse → LLM → enrich)
├── llm_client.py                 # OpenRouter клиент
├── prompts.py                    # Промпты для LLM
└── enrichment.py                 # Обогащение отчётов (БДУ/CVE)

frontend/src/
├── App.tsx                       # Главный компонент
├── components/
│   ├── CommandHub.tsx           # Формы запуска задач
│   ├── SystemPulse.tsx          # Health-мониторинг
│   ├── HistoryPanel.tsx         # История запусков
│   └── DetailDrawer.tsx         # Детали результата
└── types.ts                      # TypeScript типы
```

## Ключевые компоненты

### Backend (`backend_main.py`)
- **Инициализация:** `nmap_scanner`, `recon_engine`, `attack_orchestrator`, `llm_pipeline`, `auto_pentest_orchestrator`
- **Хранилище:** `results_store` (in-memory dict), `llm_reports` (dict)
- **БД:** PostgreSQL через SQLAlchemy async, таблицы `scan_results`, `api_keys`

### Recon Engine
- Валидация целей (IP/domain/network)
- Nmap (quick/full/vuln), Shodan host lookup, VirusTotal IP/domain
- Результат: JSON с `network_scan`, `shodan`, `virustotal`, `dns_info`

### Attack Engine
- **Модули:** `BruteforceModule` (Hydra), `SqlmapModule`, `MetasploitModule`, `LegacyAuditModule`
- **Профили:** `BLACK_BOX`, `GREY_BOX`, `WHITE_BOX` (разные allowed_vectors, rate limits)
- **Retry:** экспоненциальный backoff, cancellation через `cancellations` set
- **Артефакты:** сохраняются в `artifacts/attack_runs/{event_id}/`

### LLM Pipeline
- **Crawl:** Playwright/Requests, до 5 страниц, depth=2
- **Processing:** BeautifulSoup → структурированные секции
- **LLM:** OpenRouter → DeepSeek, JSON response
- **Enrichment:** ThreatKnowledgeBase (БДУ/CVE маппинг)
- **Action Summary:** отдельный LLM-запрос для рекомендаций

### AutoPentest Orchestrator
- **План:** LLM генерирует JSON с шагами (`audit`, `recon`, `scan`, `attack`, `report`)
- **Выполнение:** последовательно через `_execute_step()`
- **Шаги:** `llm.audit`, `intelligence.basic`, `nmap.quick/full`, `shodan.host`, `attack.bruteforce`, `json.report`
- **Хранение:** `runs` dict, `results_store[run_id]`

## API Эндпойнты

**Разведка:**
- `POST /intelligence/basic` — базовая разведка
- `POST /intelligence/comprehensive` — комплексная разведка
- `POST /intelligence/batch` — пакетная разведка

**Сканирование:**
- `POST /scan/nmap` — Nmap сканирование (quick/full/vuln/custom)
- `POST /scan/comprehensive` — агрегация Nmap + Shodan + VT
- `GET /results/{scan_id}` — получить результат

**Атаки:**
- `POST /attack/execute` — выполнить атаку (bruteforce/sqli/metasploit/legacy_audit)
- `POST /attack/run` — пакетный запуск атак
- `GET /attack/modules` — список модулей

**LLM:**
- `POST /llm/scan` — LLM-аудит веб-страницы
- `GET /llm/reports/{report_id}` — получить LLM-отчёт

**AutoPentest:**
- `POST /autopentest/start` — запустить автопентест
- `GET /autopentest/{run_id}` — статус автопентеста
- `GET /autopentest` — история запусков

**Утилиты:**
- `GET /health` — проверка компонентов
- `GET /history` — история всех событий
- `GET /history/{event_id}` — детали события

## Конфигурация

**Переменные окружения:**
```bash
DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/intelligence_db
SHODAN_API_KEY=xxx
VIRUSTOTAL_API_KEY=yyy
OPENROUTER_API_KEY=zzz
MSFRPC_URL=http://metasploit:55553/api/
MSFRPC_TOKEN=token
VITE_ACCESS_PASS=пароль_для_веб_интерфейса
```

**Docker Compose:**
- `db` — PostgreSQL 15 (порт 5432)
- `backend` — FastAPI (порт 8000)
- `frontend` — nginx + React SPA (порт 417)

**Volumes:**
- `./artifacts` — артефакты атак
- `./logs` — логи
- `postgres_data` — БД

## Запуск

```bash
docker compose up --build
```

**Проверка:**
- Frontend: http://localhost:417
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Важные детали

- **Асинхронность:** все I/O операции через `asyncio`, CLI-инструменты через `asyncio.to_thread()`
- **Отмена задач:** `TaskManager` с `cancellations` set, проверка в циклах
- **Хранение:** in-memory `results_store` + PostgreSQL для персистентности
- **LLM:** OpenRouter с fallback на DeepSeek, JSON response format
- **Безопасность:** dry-run режим для атак, валидация целей, изоляция в Docker


