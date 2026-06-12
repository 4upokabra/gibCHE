import { RefreshCw, Activity, Workflow, Target, Radar } from "lucide-react";
import { HealthResponse, HistoryStats } from "../types";

type SystemPulseProps = {
  health: HealthResponse | null;
  onRefresh: () => void;
  historyStats: HistoryStats;
  lastUpdated?: string;
  formatDate: (value?: string) => string;
};

export function SystemPulse({ health, onRefresh, historyStats, lastUpdated, formatDate }: SystemPulseProps) {
  const statCards = [
    { label: "Успешно", value: historyStats.completed, icon: Activity, accent: "text-emerald-300 bg-emerald-500/10" },
    { label: "В процессе", value: historyStats.running, icon: Workflow, accent: "text-amber-300 bg-amber-500/10" },
    { label: "Ошибки", value: historyStats.failed, icon: Target, accent: "text-rose-300 bg-rose-500/10" },
    {
      label: "Успешность",
      value: `${historyStats.successRate}%`,
      icon: Radar,
      accent: "text-sky-300 bg-sky-500/10",
    },
  ];

  return (
    <section className="shimmer-border surface space-y-6 p-6 lg:p-7">
      <header className="flex items-start justify-between gap-4">
        <div>
          <p className="chip inline-flex items-center gap-2 bg-white/5 text-slate-300">Live telemetry</p>
          <h2 className="mt-3 text-2xl font-semibold text-white">Пульс инфраструктуры</h2>
          <p className="text-sm text-slate-400">Слежение за компонентами API, брокерами и автоматикой в реальном времени.</p>
        </div>
        <button
          onClick={onRefresh}
          className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold uppercase tracking-[0.3em] text-slate-200 transition hover:border-white/30"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Обновить
        </button>
      </header>

      <div className="grid gap-4 md:grid-cols-2">
        {statCards.map((card) => (
          <article key={card.label} className="rounded-3xl border border-white/10 bg-white/5 px-5 py-4">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-[0.3em] text-slate-500">{card.label}</span>
              <span className={`rounded-full px-2 py-1 text-xs ${card.accent}`}>
                <card.icon className="h-3.5 w-3.5" />
              </span>
            </div>
            <p className="mt-3 text-3xl font-semibold text-white">{card.value}</p>
          </article>
        ))}
      </div>

      <div className="space-y-4 rounded-3xl border border-white/10 bg-white/5 p-5">
        <div className="flex items-center justify-between text-sm text-slate-400">
          <span>Состояние сервисов</span>
          <span>{health ? `Обновлено ${formatDate(health.timestamp)}` : "нет связи"}</span>
        </div>
        {health ? (
          <dl className="grid gap-3">
            {Object.entries(health.components).map(([key, value]) => (
              <div key={key} className="flex items-center justify-between rounded-2xl border border-white/10 bg-slate-950/40 px-4 py-3">
                <span className="text-xs uppercase tracking-[0.3em] text-slate-500">{key}</span>
                <span className="text-sm font-semibold text-slate-100">{value}</span>
              </div>
            ))}
          </dl>
        ) : (
          <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
            Компоненты не ответили. Проверьте подключение или перезапустите backend.
          </div>
        )}
      </div>

      <div className="rounded-3xl border border-white/10 bg-gradient-to-r from-primary/10 via-white/5 to-transparent p-5 text-sm text-slate-400">
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Сводка</p>
        <p className="mt-2 text-base text-white">
          {historyStats.total > 0 ? (
            <>
              За последние 24 часа выполнено <strong>{historyStats.total}</strong> задач. Последнее обновление{" "}
              <strong>{formatDate(lastUpdated)}</strong>.
            </>
          ) : (
            "Пока нет задач — запустите разведку, атаку или LLM-аудит."
          )}
        </p>
      </div>
    </section>
  );
}


