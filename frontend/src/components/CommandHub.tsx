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
  const isXssExploit = attackForm.attackType === "xss_exploit";
  const isCommandInjection = attackForm.attackType === "command_injection";
  const isPathTraversal = attackForm.attackType === "path_traversal";
  const isSsrf = attackForm.attackType === "ssrf";
  const isSsti = attackForm.attackType === "ssti";
  const isXxe = attackForm.attackType === "xxe";
  const isOpenRedirect = attackForm.attackType === "open_redirect";
  const isCorsMisconfig = attackForm.attackType === "cors_misconfig";
  const isInjectionVector =
    isXssExploit || isCommandInjection || isPathTraversal || isSsti || isXxe || isSsrf;
  const scannerOptions = [
    { key: "nmap", label: "Nmap", description: "Активное сканирование", icon: Radar },
    { key: "shodan", label: "Shodan", description: "Поиск по сети", icon: Shuffle },
    { key: "virustotal", label: "VirusTotal", description: "IOC / файлы", icon: Database },
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

          <div className="grid gap-5 md:grid-cols-2">
            <label className="block space-y-2">
              <span className={labelClass}>Режим</span>
              <div className="relative">
                <Radar className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <select
                  className={clsx(inputClass, "appearance-none pl-11")}
                  value={reconForm.comprehensive ? "full" : "quick"}
                  onChange={(e) => setReconForm((prev) => ({ ...prev, comprehensive: e.target.value === "full" }))}
                >
                  <option value="quick">Быстрый скан</option>
                  <option value="full">Комплексный отчёт</option>
                </select>
              </div>
            </label>
            <div className="rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-slate-400">
              Маршруты Nmap, Shodan и VirusTotal будут связаны с отчётом, статусы появятся в истории и JSON.
            </div>
          </div>

          <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
              <Radar className="h-4 w-4 text-primary" />
              Сканеры и параметры
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
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
                      "flex flex-col gap-1 rounded-2xl border px-4 py-3 text-left transition",
                      enabled
                        ? "border-primary/50 bg-primary/10 text-white"
                        : "border-white/10 bg-white/5 text-slate-400 hover:border-white/30",
                    )}
                  >
                    <Icon className={clsx("h-4 w-4", enabled ? "text-primary" : "text-slate-500")} />
                    <span className="text-sm font-semibold">{scanner.label}</span>
                    <span className="text-[11px] uppercase tracking-[0.3em]">{scanner.description}</span>
                  </button>
                );
              })}
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              <label className="block space-y-2">
                <span className={labelClass}>Nmap аргументы</span>
                <textarea
                  className={textareaClass}
                  rows={3}
                  value={reconForm.nmapArgs}
                  onChange={(e) => setReconForm((prev) => ({ ...prev, nmapArgs: e.target.value }))}
                  placeholder="-sC -sV -Pn --top-ports=100"
                />
              </label>
              <label className="block space-y-2">
                <span className={labelClass}>Shodan dork</span>
                <textarea
                  className={textareaClass}
                  rows={3}
                  value={reconForm.shodanQuery}
                  onChange={(e) => setReconForm((prev) => ({ ...prev, shodanQuery: e.target.value }))}
                  placeholder='ssl:true http.title:"vpn" city:"moscow"'
                />
              </label>
              <label className="block space-y-2">
                <span className={labelClass}>VirusTotal фильтры</span>
                <textarea
                  className={textareaClass}
                  rows={3}
                  value={reconForm.virustotalFlags}
                  onChange={(e) => setReconForm((prev) => ({ ...prev, virustotalFlags: e.target.value }))}
                  placeholder="--include-malware --historical"
                />
              </label>
            </div>
            <p className="text-xs text-slate-500">
              Можно отключить лишние источники и тонко настроить запросы – параметры попадут в backend вместе с задачей.
            </p>
          </div>

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
                <option value="xss_exploit">XSS Exploit</option>
                <option value="command_injection">Command Injection</option>
                <option value="path_traversal">Path Traversal / LFI</option>
                <option value="ssrf">SSRF</option>
                <option value="ssti">SSTI</option>
                <option value="xxe">XXE</option>
                <option value="open_redirect">Open Redirect</option>
                <option value="cors_misconfig">CORS Misconfig</option>
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

          {isInjectionVector && (
            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <SlidersHorizontal className="h-4 w-4 text-rose-300" />
                Параметры инъекции
              </div>
              {!isXxe && (
                <label className="block space-y-2">
                  <span className={labelClass}>Параметр для инъекции</span>
                  <input
                    className={inputClass}
                    value={attackForm.injectionParam}
                    onChange={(e) => setAttackForm((prev) => ({ ...prev, injectionParam: e.target.value }))}
                    placeholder="q"
                  />
                </label>
              )}
              {(isXssExploit || isCommandInjection || isSsti) && (
                <label className="block space-y-2">
                  <span className={labelClass}>Свои payload'ы (comma / newline, опционально)</span>
                  <textarea
                    className={textareaClass}
                    rows={3}
                    value={attackForm.injectionPayloads}
                    onChange={(e) => setAttackForm((prev) => ({ ...prev, injectionPayloads: e.target.value }))}
                    placeholder={
                      isXssExploit
                        ? "<script>alert(document.domain)</script>"
                        : isSsti
                          ? "{{7*7}}\n${7*7}"
                          : ";id\n|whoami"
                    }
                  />
                </label>
              )}
              {(isPathTraversal || isXxe) && (
                <label className="block space-y-2">
                  <span className={labelClass}>Целевой файл</span>
                  <input
                    className={inputClass}
                    value={attackForm.traversalFile}
                    onChange={(e) => setAttackForm((prev) => ({ ...prev, traversalFile: e.target.value }))}
                    placeholder="etc/passwd"
                  />
                </label>
              )}
              {isSsrf && (
                <label className="block space-y-2">
                  <span className={labelClass}>Целевые SSRF-адреса (comma / newline, опционально)</span>
                  <textarea
                    className={textareaClass}
                    rows={3}
                    value={attackForm.ssrfTargets}
                    onChange={(e) => setAttackForm((prev) => ({ ...prev, ssrfTargets: e.target.value }))}
                    placeholder="http://127.0.0.1\nhttp://169.254.169.254/latest/meta-data/"
                  />
                </label>
              )}
              <p className="text-xs text-slate-500">
                {isXssExploit && "Набор payload'ов будет подставлен в указанный параметр URL, проверяется отражение без экранирования."}
                {isCommandInjection && "Проверяются output- и time-based payload'ы для обнаружения OS command injection."}
                {isPathTraversal && "Перебираются варианты traversal-путей для чтения указанного файла через параметр."}
                {isSsrf && "Указанные адреса (или внутренние/служебные по умолчанию) подставляются в параметр и проверяются на SSRF."}
                {isSsti && "Пробы вычисления выражений ({{7*7}} и аналоги) подставляются в параметр для обнаружения SSTI."}
                {isXxe && "В тело запроса отправляется XML с внешней сущностью, ссылающейся на указанный файл."}
              </p>
            </div>
          )}

          {isOpenRedirect && (
            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <SlidersHorizontal className="h-4 w-4 text-rose-300" />
                Open Redirect
              </div>
              <label className="block space-y-2">
                <span className={labelClass}>Целевой адрес редиректа</span>
                <input
                  className={inputClass}
                  value={attackForm.redirectPayload}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, redirectPayload: e.target.value }))}
                  placeholder="https://evil.example.com"
                />
              </label>
              <p className="text-xs text-slate-500">
                Перебираются типовые редирект-параметры (redirect, url, next, return и т.д.), проверяется
                Location-заголовок на совпадение с указанным адресом.
              </p>
            </div>
          )}

          {isCorsMisconfig && (
            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.35em] text-slate-400">
                <SlidersHorizontal className="h-4 w-4 text-rose-300" />
                CORS Misconfig
              </div>
              <label className="block space-y-2">
                <span className={labelClass}>Заголовок Origin</span>
                <input
                  className={inputClass}
                  value={attackForm.corsOrigin}
                  onChange={(e) => setAttackForm((prev) => ({ ...prev, corsOrigin: e.target.value }))}
                  placeholder="https://evil-attacker.example"
                />
              </label>
              <p className="text-xs text-slate-500">
                Запрос отправляется с указанным Origin; проверяется отражение в Access-Control-Allow-Origin
                совместно с Access-Control-Allow-Credentials: true.
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
          <div className="grid gap-5 md:grid-cols-2">
            <label className="block space-y-2 md:col-span-2">
              <span className={labelClass}>URL</span>
              <input
                className={inputClass}
                value={llmForm.url}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, url: e.target.value }))}
              />
            </label>
            <label className="block space-y-2 md:col-span-2">
              <span className={labelClass}>Задача аудита</span>
              <textarea
                className={textareaClass}
                value={llmForm.goal}
                onChange={(e) => setLlmForm((prev) => ({ ...prev, goal: e.target.value }))}
              />
            </label>
          </div>

          <label className="flex items-start gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300">
            <input
              type="checkbox"
              className={checkboxClass}
              checked={llmForm.use_browser}
              onChange={(e) => setLlmForm((prev) => ({ ...prev, use_browser: e.target.checked }))}
            />
            <span>
              Использовать Playwright (Chromium) для загрузки SPA, обработки cookie и рендеринга контента перед LLM-анализом.
            </span>
          </label>

          <label className="block space-y-2">
            <span className={labelClass}>Название задачи (опционально)</span>
            <input
              className={inputClass}
              value={llmForm.label}
              onChange={(e) => setLlmForm((prev) => ({ ...prev, label: e.target.value }))}
              placeholder="Например, «LLM аудит портала demo»"
            />
          </label>

          <button onClick={onLLM} disabled={pendingAction === "llm"} className={actionButtonClass}>
            {pendingAction === "llm" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Согласуем промпт...
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4" />
                Запустить LLM-скан
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
            «Auto Pentest» создаёт пошаговый план (разведка → атаки → отчёт) и запускает встроенные инструменты:
            Nmap (включая vuln-скрипты), Shodan, VirusTotal, XSS-разведку, Dirfuzz (gobuster), Nikto, а также атаки
            Hydra, SQLMap, Metasploit, XSS Exploit, Command Injection, Path Traversal/LFI, SSRF, SSTI, XXE, Open
            Redirect и CORS Misconfig. Параметры/URL для атак автоматически дополняются находками разведки
            (уязвимые параметры из XSS-скана, пути из Dirfuzz). История и прогресс появятся в ленте событий.
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


