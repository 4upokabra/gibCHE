import { Dispatch, SetStateAction } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import clsx from "clsx";
import {
  BookOpen,
  Database,
  Loader2,
  MapPin,
  Radar,
  Radio,
  Shield,
  Shuffle,
  SlidersHorizontal,
  Sparkles,
  Target,
  Terminal,
  Workflow,
  Zap,
} from "lucide-react";
import {
  AttackFormState,
  AutoPentestForm,
  LlmFormState,
  PendingAction,
  ReconFormState,
} from "../types";

const labelClass = "text-[11px] font-semibold uppercase tracking-[0.25em] text-slate-400";
const inputClass =
  "w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white placeholder:text-slate-500 focus:border-primary/60 focus:outline-none focus:ring-2 focus:ring-primary/20 transition";
const textareaClass = `${inputClass} min-h-[120px] resize-none`;
const checkboxClass =
  "h-4 w-4 rounded border-slate-600 bg-slate-900 text-primary focus:ring-primary";

type CommandHubProps = {
  reconForm: ReconFormState;
  setReconForm: Dispatch<SetStateAction<ReconFormState>>;
  attackForm: AttackFormState;
  setAttackForm: Dispatch<SetStateAction<AttackFormState>>;
  llmForm: LlmFormState;
  setLlmForm: Dispatch<SetStateAction<LlmFormState>>;
  autopentestForm: AutoPentestForm;
  setAutopentestForm: Dispatch<SetStateAction<AutoPentestForm>>;
  pendingAction: PendingAction;
  onRecon: () => void;
  onAttack: () => void;
  onLLM: () => void;
  onAutoPentest: () => void;
};

const tabTriggerClass =
  "flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-slate-300 transition hover:text-white data-[state=active]:border-white/30 data-[state=active]:bg-gradient-to-r data-[state=active]:from-primary/30 data-[state=active]:to-accent/30 data-[state=active]:text-white";

const actionButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-primary via-primary/80 to-accent px-6 py-3 font-semibold text-slate-950 shadow-lg shadow-primary/40 transition hover:brightness-110 disabled:opacity-60 disabled:hover:brightness-100";

export function CommandHub({
  reconForm,
  setReconForm,
  attackForm,
  setAttackForm,
  llmForm,
  setLlmForm,
  autopentestForm,
  setAutopentestForm,
  pendingAction,
  onRecon,
  onAttack,
  onLLM,
  onAutoPentest,
}: CommandHubProps) {
  const isBruteforce = attackForm.attackType === "bruteforce";
  const isMetasploit = attackForm.attackType === "metasploit";
  const isSQLi = attackForm.attackType === "sqli";
  const scannerOptions = [
    { key: "nmap", label: "Nmap", icon: Radar },
    { key: "shodan", label: "Shodan", icon: Radio },
    { key: "virustotal", label: "VT", icon: Database },
    { key: "subdomains", label: "Поддомены", icon: MapPin },
    { key: "technologies", label: "Стек", icon: SlidersHorizontal },
    { key: "dorks", label: "Dorks", icon: Shuffle },
    { key: "github", label: "GitHub", icon: BookOpen },
    { key: "seo", label: "SEO", icon: Target },
    { key: "files", label: "Файлы", icon: Terminal },
  ] as const;

  return (
    <section className="shimmer-border surface p-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-3">
          <p className="chip inline-flex items-center gap-2 bg-white/5 text-slate-300">
            <Sparkles className="h-4 w-4 text-accent" />
            Command Hub
          </p>
          <h2 className="text-3xl font-semibold text-white">Центр операций</h2>
          <p className="max-w-2xl text-sm text-slate-400">
            Управляйте разведкой, атаками и LLM-аудитами в едином стекле. Форма автоматически
            сохранит последний ввод и покажет статус процесса.
          </p>
        </div>
        <div className="flex flex-col items-start gap-3 text-xs uppercase tracking-[0.4em] text-slate-400 sm:flex-row sm:items-center">
          <span className="flex items-center gap-2 rounded-full bg-white/5 px-3 py-1">
            <Shield className="h-3.5 w-3.5 text-emerald-300" />
            Safe Mode
          </span>
          <span className="flex items-center gap-2 rounded-full bg-white/5 px-3 py-1">
            <Radio className="h-3.5 w-3.5 text-sky-300" />
            Live
          </span>
        </div>
      </div>

      <Tabs.Root defaultValue="recon" className="mt-8 flex flex-col gap-6">
        <Tabs.List className="grid gap-2 sm:grid-cols-4">
          <Tabs.Trigger value="recon" className={tabTriggerClass}>
            <Target className="h-4 w-4 text-primary" />
            Разведка
          </Tabs.Trigger>
          <Tabs.Trigger value="attack" className={tabTriggerClass}>
            <Terminal className="h-4 w-4 text-rose-300" />
            Атаки
          </Tabs.Trigger>
          <Tabs.Trigger value="llm" className={tabTriggerClass}>
            <Sparkles className="h-4 w-4 text-sky-300" />
            LLM аудит
          </Tabs.Trigger>
          <Tabs.Trigger value="auto" className={tabTriggerClass}>
            <Workflow className="h-4 w-4 text-emerald-300" />
            Auto Pentest
          </Tabs.Trigger>
        </Tabs.List>

        <Tabs.Content value="recon" className="space-y-5">
          <div className="grid gap-5 md:grid-cols-2">
            <label className="block space-y-2">
              <span className={labelClass}>Цель</span>
              <input
                className={inputClass}
                value={reconForm.target}
                onChange={(e) => setReconForm((prev) => ({ ...prev, target: e.target.value }))}
              />
            </label>
            <label className="block space-y-2">
              <span className={labelClass}>Тип цели</span>
              <div className="relative">
                <MapPin className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <select
                  className={clsx(inputClass, "appearance-none pl-11")}
                  value={reconForm.targetType}
                  onChange={(e) => setReconForm((prev) => ({ ...prev, targetType: e.target.value as ReconFormState["targetType"] }))}
                >
                  <option value="ip">IP</option>
                  <option value="domain">Domain</option>
                  <option value="network">Network</option>
                </select>
              </div>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <label className="block space-y-2">
              <span className={labelClass}>Режим</span>
              <select
                className={inputClass}
                value={reconForm.comprehensive ? "full" : "quick"}
                onChange={(e) => setReconForm((prev) => ({ ...prev, comprehensive: e.target.value === "full" }))}
              >
                <option value="quick">Быстрый</option>
                <option value="full">Полный</option>
              </select>
            </label>
            <label className="flex items-center gap-2 pt-6 text-sm text-slate-400">
              <input
                type="checkbox"
                className={checkboxClass}
                checked={reconForm.useCache}
                onChange={(e) => setReconForm((prev) => ({ ...prev, useCache: e.target.checked }))}
              />
              Кэш 1ч
            </label>
          </div>

          <div className="flex flex-wrap gap-2">
            {scannerOptions.map((scanner) => {
              const enabled = reconForm.scanners[scanner.key];
              const Icon = scanner.icon;
              return (
                <button
                  key={scanner.key}
                  type="button"
                  onClick={() =>
                    setReconForm((prev) => ({
                      ...prev,
                      scanners: { ...prev.scanners, [scanner.key]: !prev.scanners[scanner.key] },
                    }))
                  }
                  className={clsx(
                    "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium transition",
                    enabled
                      ? "border-primary/50 bg-primary/15 text-white"
                      : "border-white/10 bg-white/5 text-slate-400 hover:border-white/25",
                  )}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {scanner.label}
                </button>
              );
            })}
          </div>

          <details className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-400">
            <summary className="cursor-pointer text-xs uppercase tracking-[0.25em] text-slate-300">
              Доп. параметры
            </summary>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <input
                className={inputClass}
                value={reconForm.nmapArgs}
                onChange={(e) => setReconForm((prev) => ({ ...prev, nmapArgs: e.target.value }))}
                placeholder="Nmap: -sC -sV --top-ports=100"
              />
              <input
                className={inputClass}
                value={reconForm.shodanQuery}
                onChange={(e) => setReconForm((prev) => ({ ...prev, shodanQuery: e.target.value }))}
                placeholder='Shodan dork: ssl.cert.subject.cn:"example.com"'
              />
              <input
                className={inputClass}
                value={reconForm.googleDork}
                onChange={(e) => setReconForm((prev) => ({ ...prev, googleDork: e.target.value }))}
                placeholder='Google dork: site:example.com ext:env'
              />
              <input
                className={inputClass}
                value={reconForm.virustotalFlags}
                onChange={(e) => setReconForm((prev) => ({ ...prev, virustotalFlags: e.target.value }))}
                placeholder="VirusTotal фильтры"
              />
            </div>
          </details>

          <label className="block space-y-2">
            <span className={labelClass}>Название задачи (опционально)</span>
            <input
              className={inputClass}
              value={reconForm.label}
              onChange={(e) => setReconForm((prev) => ({ ...prev, label: e.target.value }))}
              placeholder="Например, «Скан внешнего периметра»"
            />
          </label>

          <button onClick={onRecon} disabled={pendingAction === "recon"} className={actionButtonClass}>
            {pendingAction === "recon" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Сканируем...
              </>
            ) : (
              <>
                <Zap className="h-4 w-4" />
                Запустить разведку
              </>
            )}
          </button>
        </Tabs.Content>

        <Tabs.Content value="attack" className="space-y-5">
          <div className="grid gap-5 md:grid-cols-2">
            <label className="block space-y-2">
              <span className={labelClass}>Цель атаки</span>
              <input
                className={inputClass}
                value={attackForm.target}
                onChange={(e) => setAttackForm((prev) => ({ ...prev, target: e.target.value }))}
              />
            </label>
            <label className="block space-y-2">
              <span className={labelClass}>Сервис</span>
              <input
                className={inputClass}
                value={attackForm.service}
                onChange={(e) => setAttackForm((prev) => ({ ...prev, service: e.target.value }))}
              />
            </label>
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            <label className="block space-y-2 md:col-span-1">
              <span className={labelClass}>Порт</span>
              <input
                type="number"
                className={inputClass}
                value={attackForm.port}
                onChange={(e) => setAttackForm((prev) => ({ ...prev, port: Number(e.target.value) }))}
              />
            </label>
            <label className="block space-y-2 md:col-span-1">
              <span className={labelClass}>Вектор</span>
              <select
                className={inputClass}
                value={attackForm.attackType}
                onChange={(e) => setAttackForm((prev) => ({ ...prev, attackType: e.target.value }))}
              >
                <option value="bruteforce">Hydra Bruteforce</option>
                <option value="sqli">SQLMap</option>
                <option value="metasploit">Metasploit</option>
                <option value="legacy_audit">Legacy Audit</option>
              </select>
            </label>
            <label className="block space-y-2 md:col-span-1">
              <span className={labelClass}>Профиль</span>
              <select
                className={inputClass}
                value={attackForm.profile}
                onChange={(e) =>
                  setAttackForm((prev) => ({ ...prev, profile: e.target.value as AttackFormState["profile"] }))
                }
              >
                <option value="black_box">Black box</option>
                <option value="grey_box">Grey box</option>
                <option value="white_box">White box</option>
              </select>
            </label>
          </div>

          <label className="flex items-start gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300">
            <input
              type="checkbox"
              className={checkboxClass}
              checked={attackForm.dry_run}
              onChange={(e) => setAttackForm((prev) => ({ ...prev, dry_run: e.target.checked }))}
            />
            <span>
              Dry-run режим — прогоняем плейбуки без фактического вреда. Полезно для проверки сценариев и интеграций.
            </span>
          </label>

          {isBruteforce && (
            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <BookOpen className="h-4 w-4 text-primary" />
                Словари и потоки
              </div>
              <label className="block space-y-2">
                <span className={labelClass}>Путь к словарю</span>
                <input
                  className={inputClass}
                  value={attackForm.dictionary}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, dictionary: e.target.value }))}
                />
              </label>
              <label className="block space-y-2">
                <span className={labelClass}>Список логинов (comma / newline)</span>
                <textarea
                  className={textareaClass}
                  rows={3}
                  value={attackForm.usernames}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, usernames: e.target.value }))}
                />
              </label>
              <label className="block space-y-2 sm:max-w-xs">
                <span className={labelClass}>Потоков</span>
                <input
                  type="number"
                  className={inputClass}
                  min={1}
                  max={32}
                  value={attackForm.concurrency}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, concurrency: Number(e.target.value) }))}
                />
              </label>
              <p className="text-xs text-slate-500">
                Hydra использует словарь и список логинов. Конкурентность регулирует нагрузку на сервис.
              </p>
            </div>
          )}

          {isMetasploit && (
            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <SlidersHorizontal className="h-4 w-4 text-rose-300" />
                Metasploit параметры
              </div>
              <label className="block space-y-2">
                <span className={labelClass}>Модуль</span>
                <input
                  className={inputClass}
                  value={attackForm.metasploitModule}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, metasploitModule: e.target.value }))}
                />
              </label>
              <label className="block space-y-2">
                <span className={labelClass}>Payload</span>
                <input
                  className={inputClass}
                  value={attackForm.metasploitPayload}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, metasploitPayload: e.target.value }))}
                />
              </label>
              <label className="block space-y-2">
                <span className={labelClass}>Опции (формат KEY=VALUE;KEY=VALUE)</span>
                <textarea
                  className={textareaClass}
                  rows={3}
                  value={attackForm.metasploitOptions}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, metasploitOptions: e.target.value }))}
                />
              </label>
              <p className="text-xs text-slate-500">
                Значения будут проброшены в `set` перед запуском консоли msf. Указывайте RHOST,RPORT,LHOST,LPORT и другие
                ключи.
              </p>
            </div>
          )}

          {isSQLi && (
            <div className="space-y-3 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <SlidersHorizontal className="h-4 w-4 text-sky-300" />
                SQLMap флаги
              </div>
              <textarea
                className={textareaClass}
                rows={3}
                placeholder="--risk=3 --level=5 --batch --tamper=space2comment"
                value={attackForm.sqlmapFlags}
                onChange={(e) => setAttackForm((prev) => ({ ...prev, sqlmapFlags: e.target.value }))}
              />
              <p className="text-xs text-slate-500">
                Флаги будут переданы в sqlmap как есть. Используйте их для кастомизации времени запроса, тамперов и т.д.
              </p>
            </div>
          )}

          <label className="block space-y-2">
            <span className={labelClass}>Название задачи (опционально)</span>
            <input
              className={inputClass}
              value={attackForm.label}
              onChange={(e) => setAttackForm((prev) => ({ ...prev, label: e.target.value }))}
              placeholder="Например, «Hydra по SSH 146.103.121»"
            />
          </label>

          <button onClick={onAttack} disabled={pendingAction === "attack"} className={actionButtonClass}>
            {pendingAction === "attack" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Инициируем атаку...
              </>
            ) : (
              <>
                <Terminal className="h-4 w-4" />
                Запустить атаку
              </>
            )}
          </button>
        </Tabs.Content>

        <Tabs.Content value="llm" className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2">
            <label className="block space-y-2">
              <span className={labelClass}>Домен / цель OSINT</span>
              <input
                className={inputClass}
                value={llmForm.target}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, target: e.target.value }))}
                placeholder="example.com"
              />
            </label>
            <label className="block space-y-2">
              <span className={labelClass}>URL для анализа</span>
              <input
                className={inputClass}
                value={llmForm.url}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, url: e.target.value }))}
              />
            </label>
          </div>

          <label className="block space-y-2">
            <span className={labelClass}>Задача аудита</span>
            <textarea
              className={textareaClass}
              rows={3}
              value={llmForm.goal}
              onChange={(e) => setLlmForm((prev) => ({ ...prev, goal: e.target.value }))}
            />
          </label>

          <div className="flex flex-wrap gap-4 text-sm text-slate-300">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                className={checkboxClass}
                checked={llmForm.run_osint}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, run_osint: e.target.checked }))}
              />
              OSINT перед LLM
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                className={checkboxClass}
                checked={llmForm.comprehensive}
                disabled={!llmForm.run_osint}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, comprehensive: e.target.checked }))}
              />
              Полная разведка
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                className={checkboxClass}
                checked={llmForm.use_browser}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, use_browser: e.target.checked }))}
              />
              Playwright
            </label>
          </div>

          <label className="block space-y-2">
            <span className={labelClass}>Название (опционально)</span>
            <input
              className={inputClass}
              value={llmForm.label}
              onChange={(e) => setLlmForm((prev) => ({ ...prev, label: e.target.value }))}
            />
          </label>

          <button onClick={onLLM} disabled={pendingAction === "llm"} className={actionButtonClass}>
            {pendingAction === "llm" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {llmForm.run_osint ? "Разведка и анализ..." : "Анализ..."}
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4" />
                {llmForm.run_osint ? "Разведка + LLM-аудит" : "Только LLM-аудит"}
              </>
            )}
          </button>
        </Tabs.Content>

        <Tabs.Content value="auto" className="space-y-5">
          <div className="space-y-2">
            <p className="text-sm font-semibold text-slate-200">Auto Pentester</p>
            <p className="text-slate-400 text-sm">
              LLM самостоятельно построит стратегию разведки и атак, выполнит шаги и подготовит отчёт. Укажите цель,
              режим доступа и деловой контекст.
            </p>
          </div>
          <div className="grid gap-5 md:grid-cols-2">
            <label className="block space-y-2">
              <span className={labelClass}>Цель</span>
              <input
                className={inputClass}
                value={autopentestForm.target}
                onChange={(e) => setAutopentestForm((prev) => ({ ...prev, target: e.target.value }))}
              />
            </label>
            <label className="block space-y-2">
              <span className={labelClass}>Профиль</span>
              <select
                className={inputClass}
                value={autopentestForm.profile}
                onChange={(e) =>
                  setAutopentestForm((prev) => ({ ...prev, profile: e.target.value as AutoPentestForm["profile"] }))
                }
              >
                <option value="black_box">Black box</option>
                <option value="grey_box">Grey box</option>
                <option value="white_box">White box</option>
              </select>
            </label>
          </div>
          <label className="block space-y-2">
            <span className={labelClass}>Цель проверки</span>
            <textarea
              className={textareaClass}
              rows={3}
              value={autopentestForm.goal}
              onChange={(e) => setAutopentestForm((prev) => ({ ...prev, goal: e.target.value }))}
              placeholder="Например: поиск уязвимостей OWASP Top 10 на внешнем портале"
            />
          </label>
          <label className="block space-y-2">
            <span className={labelClass}>Scope / ограничения</span>
            <textarea
              className={textareaClass}
              rows={3}
              value={autopentestForm.scope}
              onChange={(e) => setAutopentestForm((prev) => ({ ...prev, scope: e.target.value }))}
              placeholder="Сегмент сети, поддомены, политики dry-run и т. д."
            />
          </label>
          <label className="block space-y-2">
            <span className={labelClass}>Комментарии / пожелания</span>
            <textarea
              className={textareaClass}
              rows={3}
              value={autopentestForm.notes}
              onChange={(e) => setAutopentestForm((prev) => ({ ...prev, notes: e.target.value }))}
              placeholder="Что важно учесть: интересующие сервисы, ограничения, целевые данные..."
            />
          </label>

          <label className="block space-y-2">
            <span className={labelClass}>Название задачи (опционально)</span>
            <input
              className={inputClass}
              value={autopentestForm.label}
              onChange={(e) => setAutopentestForm((prev) => ({ ...prev, label: e.target.value }))}
              placeholder="Например, «Auto Pentest интернет-банка»"
            />
          </label>

          <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-4 text-sm text-slate-400">
            «Auto Pentest» создаёт пошаговый план (разведка → атаки → отчёт) и запускает встроенные инструменты. История
            и прогресс появятся в ленте событий.
          </div>

          <button
            onClick={onAutoPentest}
            disabled={pendingAction === "autopentest"}
            className={actionButtonClass}
          >
            {pendingAction === "autopentest" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Запускаем…
              </>
            ) : (
              <>
                <Workflow className="h-4 w-4" />
                Стартовать Auto Pentest
              </>
            )}
          </button>
        </Tabs.Content>
      </Tabs.Root>
    </section>
  );
}


