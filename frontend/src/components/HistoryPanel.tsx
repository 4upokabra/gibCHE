import { Dispatch, SetStateAction } from "react";
import { ArrowUpRight, FileDown, Pause, Play, RefreshCw, Search, Square } from "lucide-react";
import clsx from "clsx";
import { FilterState, HistoryItem, TaskControlState } from "../types";
import { STATUS_COLORS } from "../constants";

type HistoryPanelProps = {
  filteredHistory: HistoryItem[];
  filters: FilterState;
  setFilters: Dispatch<SetStateAction<FilterState>>;
  loadingHistory: boolean;
  onRefresh: () => void;
  onSelectItem: (item: HistoryItem) => void;
  formatDate: (value?: string) => string;
  apiDocsUrl: string;
  taskControls: Record<string, TaskControlState>;
  onTaskAction: (taskId: string, action: "pause" | "resume" | "cancel") => void;
};

const statusOptions = [
  { value: "all", label: "Все" },
  { value: "completed", label: "Completed" },
  { value: "started", label: "Started" },
  { value: "processing", label: "Processing" },
  { value: "running", label: "Running" },
  { value: "scheduled", label: "Scheduled" },
  { value: "paused", label: "Paused" },
  { value: "cancelled", label: "Cancelled" },
  { value: "failed", label: "Failed" },
  { value: "error", label: "Error" },
];

export function HistoryPanel({
  filteredHistory,
  filters,
  setFilters,
  loadingHistory,
  onRefresh,
  onSelectItem,
  formatDate,
  apiDocsUrl,
  taskControls,
  onTaskAction,
}: HistoryPanelProps) {
  return (
    <section className="shimmer-border surface space-y-6 p-6 lg:p-7">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="chip inline-flex items-center gap-2 bg-white/5 text-slate-300">Ops timeline</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">История задач</h2>
          <p className="text-sm text-slate-400">
            Фильтруйте результаты по целям, статусу или ID и открывайте JSON с подробностями прямо в интерфейсе.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onRefresh}
            className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/30"
          >
            <RefreshCw className="h-4 w-4" />
            Обновить
          </button>
          <a
            href={apiDocsUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-white/30"
          >
            <ArrowUpRight className="h-4 w-4" />
            Swagger
          </a>
        </div>
      </header>

      <div className="grid gap-3 md:grid-cols-[1.2fr_auto]">
        <div className="relative">
          <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            className="w-full rounded-2xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-sm text-white placeholder:text-slate-500 focus:border-white/40 focus:outline-none focus:ring-2 focus:ring-white/20"
            placeholder="Поиск по цели, event_id или типу"
            value={filters.search}
            onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
          />
        </div>
        <div className="flex flex-wrap gap-2">
          {statusOptions.map((option) => (
            <button
              key={option.value}
              onClick={() => setFilters((prev) => ({ ...prev, status: option.value }))}
              className={clsx(
                "rounded-2xl border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.3em] transition",
                filters.status === option.value
                  ? "border-white/40 bg-white/10 text-white"
                  : "border-white/10 text-slate-400 hover:border-white/30 hover:text-white",
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3 rounded-3xl border border-white/10 bg-slate-950/40 p-2">
        {loadingHistory ? (
          <div className="flex items-center justify-center rounded-2xl border border-dashed border-white/10 px-4 py-16 text-slate-400">
            <RefreshCw className="mr-3 h-4 w-4 animate-spin" />
            Загружаем активность...
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-white/10 px-4 py-16 text-center text-slate-400">
            Нет элементов под выбранные фильтры. Запустите новую задачу или измените условия.
          </div>
        ) : (
          filteredHistory.map((item, index) => (
            <article
              key={item.event_id ?? item.scan_id ?? item.report_id ?? item.timestamp ?? `${item.target}-${index}`}
              className="group flex flex-col gap-3 rounded-2xl border border-white/5 bg-white/5 px-4 py-3 transition hover:border-white/30 hover:bg-white/10"
            >
              {(() => {
                const taskId = item.task_id ?? item.event_id ?? item.scan_id ?? item.report_id;
                const taskControl = taskId ? taskControls[taskId] : undefined;
                const status = taskControl?.status ?? item.status ?? "completed";
                const isFinal = ["completed", "failed", "cancelled", "error"].includes(status);
                const showPause = taskControl && ["running", "processing", "started", "scheduled"].includes(status);
                const showResume = taskControl && status === "paused";
                const showStop = taskControl && !isFinal;

                const customLabel = typeof item.label === "string" ? item.label.trim() : "";
                const targetLabel = customLabel || item.target || item.event_id || item.scan_id || "Без названия";
                const dateLabel = formatDate(item.timestamp ?? item.updated_at);
                return (
                  <>
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>{formatDate(item.timestamp ?? item.updated_at)}</span>
                      <span
                        className={clsx(
                          "rounded-full px-2 py-0.5 text-[11px] font-semibold capitalize",
                          STATUS_COLORS[status] ?? "bg-white/10 text-slate-200",
                        )}
                      >
                        {status}
                      </span>
                    </div>
                    <div className="flex flex-col items-center gap-2 text-center">
                      <div>
                        <p className="text-base font-semibold text-white">
                          {targetLabel}
                        </p>
                        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{dateLabel}</p>
                      </div>
                      {(showPause || showResume || showStop) && taskControl && (
                        <div className="flex flex-wrap justify-center gap-2">
                          {showPause && (
                            <button
                              onClick={() => onTaskAction(taskControl.task_id, "pause")}
                              className="inline-flex items-center gap-1 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-slate-200 transition hover:border-white/30"
                            >
                              <Pause className="h-3.5 w-3.5" />
                              Пауза
                            </button>
                          )}
                          {showResume && (
                            <button
                              onClick={() => onTaskAction(taskControl.task_id, "resume")}
                              className="inline-flex items-center gap-1 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-slate-200 transition hover:border-white/30"
                            >
                              <Play className="h-3.5 w-3.5" />
                              Продолжить
                            </button>
                          )}
                          {showStop && (
                            <button
                              onClick={() => onTaskAction(taskControl.task_id, "cancel")}
                              className="inline-flex items-center gap-1 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-rose-200 transition hover:border-rose-400/60"
                            >
                              <Square className="h-3.5 w-3.5" />
                              Стоп
                            </button>
                          )}
                        </div>
                      )}
                      <div className="flex justify-center">
                        <button
                          onClick={() => onSelectItem(item)}
                          className="inline-flex items-center gap-1 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-slate-200 transition hover:border-white/30"
                        >
                          <FileDown className="h-3.5 w-3.5" />
                          JSON
                        </button>
                      </div>
                    </div>
                  </>
                );
              })()}
              {item.details && (
                <p className="text-sm text-slate-400">
                  {item.details.slice(0, 220)}
                  {item.details.length > 220 ? "…" : ""}
                </p>
              )}
            </article>
          ))
        )}
      </div>
    </section>
  );
}


