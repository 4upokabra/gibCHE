import { FileDown, ShieldCheck, Swords, X } from "lucide-react";
import { HistoryItem } from "../types";

type SummaryInfo = {
  summary?: string;
  changes?: string;
  defensive: string[];
  offensive: string[];
};

type DetailDrawerProps = {
  item: HistoryItem | null;
  content: string;
  summaryInfo?: SummaryInfo | null;
  onClose: () => void;
  onDownload: (item: HistoryItem) => void;
};

export function DetailDrawer({ item, content, summaryInfo, onClose, onDownload }: DetailDrawerProps) {
  if (!item) return null;

  const hasSummary =
    !!summaryInfo &&
    Boolean(summaryInfo.summary || summaryInfo.changes || summaryInfo.defensive.length || summaryInfo.offensive.length);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-end bg-black/70 px-4 py-8 backdrop-blur">
      <div className="shimmer-border surface relative h-full w-full max-w-2xl overflow-hidden">
        <header className="flex items-center justify-between border-b border-white/10 px-6 py-4">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Подробности задачи</p>
            <p className="text-lg font-semibold text-white">
              {item.target || item.event_id || item.scan_id || "Без названия"}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-slate-200 transition hover:border-white/30"
              onClick={() => onDownload(item)}
            >
              <FileDown className="h-4 w-4" />
              Скачать JSON
            </button>
            <button
              className="rounded-full border border-white/10 p-2 text-slate-300 transition hover:border-white/40"
              onClick={onClose}
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>
        <div className="h-full max-h-[80vh] space-y-4 overflow-y-auto px-6 py-5">
          {hasSummary && summaryInfo && (
            <section className="space-y-4 rounded-2xl border border-primary/30 bg-primary/10 p-5 text-sm text-slate-100">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-[0.3em] text-primary/70">LLM Summary</p>
                {summaryInfo.summary && <p className="text-slate-100/90">{summaryInfo.summary}</p>}
                {summaryInfo.changes && (
                  <div className="rounded-xl border border-primary/30 bg-primary/20 p-3 text-slate-200">
                    <p className="text-xs uppercase tracking-[0.25em] text-primary/80">Изменения</p>
                    <p className="mt-2 text-slate-100">{summaryInfo.changes}</p>
                  </div>
                )}
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                {summaryInfo.defensive.length > 0 && (
                  <article className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-4 text-slate-100">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-emerald-200">
                      <ShieldCheck className="h-4 w-4" />
                      Защитные меры
                    </div>
                    <ul className="mt-3 space-y-2 text-sm leading-relaxed text-slate-100">
                      {summaryInfo.defensive.map((item, index) => (
                        <li key={`def-${index}`} className="rounded-lg bg-white/5 px-3 py-2">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </article>
                )}
                {summaryInfo.offensive.length > 0 && (
                  <article className="rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-slate-100">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-red-200">
                      <Swords className="h-4 w-4" />
                      Шаги атаки
                    </div>
                    <ul className="mt-3 space-y-2 text-sm leading-relaxed text-slate-100">
                      {summaryInfo.offensive.map((item, index) => (
                        <li key={`off-${index}`} className="rounded-lg bg-white/5 px-3 py-2">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </article>
                )}
              </div>
            </section>
          )}
          <pre className="overflow-x-auto rounded-2xl bg-slate-950/70 p-4 text-xs text-slate-100">{content}</pre>
        </div>
      </div>
    </div>
  );
}


