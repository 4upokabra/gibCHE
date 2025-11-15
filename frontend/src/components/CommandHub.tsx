import { Dispatch, SetStateAction } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import clsx from "clsx";
import {
  Loader2,
  MapPin,
  Radar,
  Radio,
  Shield,
  Sparkles,
  Target,
  Terminal,
  Zap,
} from "lucide-react";
import {
  AttackFormState,
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
  pendingAction: PendingAction;
  onRecon: () => void;
  onAttack: () => void;
  onLLM: () => void;
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
  pendingAction,
  onRecon,
  onAttack,
  onLLM,
}: CommandHubProps) {
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
        <Tabs.List className="grid gap-2 sm:grid-cols-3">
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
      </Tabs.Root>
    </section>
  );
}


