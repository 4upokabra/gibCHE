import { FileDown, ListChecks, ShieldCheck, Swords, X } from "lucide-react";
import clsx from "clsx";
import { HistoryItem, ScanFinding } from "../types";

const severityClass: Record<string, string> = {
  critical: "border-rose-400/50 bg-rose-500/15 text-rose-100",
  high: "border-orange-400/50 bg-orange-500/15 text-orange-100",
  medium: "border-amber-400/50 bg-amber-500/15 text-amber-100",
  low: "border-sky-400/50 bg-sky-500/15 text-sky-100",
  info: "border-slate-400/50 bg-slate-500/15 text-slate-200",
};

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
  findings?: ScanFinding[];
  taxonomy?: { cwe?: string[]; bdu?: string[]; threats?: string[] };
  onClose: () => void;
  onDownload: (item: HistoryItem) => void;
};

function TaxonomyBadge({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-white/15 bg-white/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-200">
      {label}: {value}
    </span>
  );
}

export function DetailDrawer({ item, content, summaryInfo, findings = [], taxonomy, onClose, onDownload }: DetailDrawerProps) {
  if (!item) return null;

  const hasSummary =
    !!summaryInfo &&
    Boolean(summaryInfo.summary || summaryInfo.changes || summaryInfo.defensive.length || summaryInfo.offensive.length);
  const formatDate = (value?: string) => {
    if (!value) return "";
    const date = new Date(value);
    return Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "medium" }).format(date);
  };
  const baseLabel =
    (typeof item.label === "string" && item.label.trim().length > 0
      ? item.label.trim()
      : item.target || item.event_id || item.scan_id) || "Без названия";
  const dateLabel = formatDate(item.timestamp ?? item.updated_at);
  const headerLabel = dateLabel ? `${baseLabel} • ${dateLabel}` : baseLabel;
  const dataModule =
    item.data && typeof item.data === "object" && !Array.isArray(item.data)
      ? (item.data as { module?: string }).module
      : undefined;
  const isPureRecon = Boolean(
    item.type === "comprehensive_recon" ||
      dataModule === "recon" ||
      (item.type?.startsWith("recon.") && item.type !== "recon.llm_audit"),
  );
  const nextStepsLabel = isPureRecon ? "Следующие шаги разведки" : "Шаги атаки";
  const NextStepsIcon = isPureRecon ? ListChecks : Swords;

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-end bg-black/70 px-4 py-8 backdrop-blur">
      <div className="shimmer-border surface relative h-full w-full max-w-2xl overflow-hidden">
        <header className="relative flex flex-wrap items-center gap-3 border-b border-white/10 px-6 py-4 pr-16">
          <div className="min-w-0 flex-1">
            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Подробности задачи</p>
            <p className="truncate text-lg font-semibold text-white" title={headerLabel}>
              {headerLabel}
            </p>
          </div>
          <div className="flex flex-shrink-0 gap-2">
            <button
              className="inline-flex items-center gap-2 rounded-2xl border border-white/10 px-3 py-1.5 text-xs text-slate-200 transition hover:border-white/30"
              onClick={() => onDownload(item)}
            >
              <FileDown className="h-4 w-4" />
              Скачать JSON
            </button>
          </div>
          <button
            className="absolute right-4 top-4 rounded-full border border-white/10 p-2 text-slate-300 transition hover:border-white/40"
            onClick={onClose}
            aria-label="Закрыть"
          >
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="h-full max-h-[80vh] space-y-4 overflow-y-auto px-6 py-5">
          {hasSummary && summaryInfo && (
            <section className="space-y-4 rounded-2xl border border-primary/30 bg-primary/10 p-5 text-sm text-slate-100">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-[0.3em] text-primary/70">LLM Summary</p>
                {summaryInfo.summary && <p className="text-slate-100/90">{summaryInfo.summary}</p>}
                {item.recon_summary && (
                  <p className="text-xs text-slate-400">OSINT: {item.recon_summary}</p>
                )}
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
                  <article
                    className={clsx(
                      "rounded-xl border p-4 text-slate-100",
                      isPureRecon
                        ? "border-sky-400/30 bg-sky-500/10"
                        : "border-red-400/30 bg-red-500/10",
                    )}
                  >
                    <div
                      className={clsx(
                        "flex items-center gap-2 text-xs uppercase tracking-[0.3em]",
                        isPureRecon ? "text-sky-200" : "text-red-200",
                      )}
                    >
                      <NextStepsIcon className="h-4 w-4" />
                      {nextStepsLabel}
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

          {findings.length > 0 && (
            <section className="space-y-3">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Уязвимости и классификаторы</p>
              {(taxonomy?.cwe?.length || taxonomy?.bdu?.length || taxonomy?.threats?.length) ? (
                <div className="flex flex-wrap gap-2 rounded-xl border border-white/10 bg-white/5 p-3">
                  {taxonomy.cwe?.map((id) => (
                    <TaxonomyBadge key={`cwe-${id}`} label="CWE" value={id} />
                  ))}
                  {taxonomy.bdu?.map((id) => (
                    <TaxonomyBadge key={`bdu-${id}`} label="БДУ ФСТЭК" value={id} />
                  ))}
                  {taxonomy.threats?.map((id) => (
                    <TaxonomyBadge key={`ubi-${id}`} label="УБИ" value={id} />
                  ))}
                </div>
              ) : null}
              <div className="space-y-3">
                {findings.map((finding, index) => {
                  const severity = (finding.severity || "info").toLowerCase();
                  return (
                    <article
                      key={`${finding.title}-${index}`}
                      className="space-y-2 rounded-2xl border border-white/10 bg-slate-950/50 p-4"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className="text-sm font-semibold text-white">{finding.title || "Находка"}</h4>
                        <span
                          className={clsx(
                            "rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide",
                            severityClass[severity] || severityClass.info,
                          )}
                        >
                          {severity}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {finding.cwe_ids?.map((id) => (
                          <TaxonomyBadge key={`f-cwe-${id}`} label="CWE" value={id} />
                        ))}
                        {finding.bdu_ids?.map((id) => (
                          <TaxonomyBadge key={`f-bdu-${id}`} label="БДУ ФСТЭК" value={id} />
                        ))}
                        {finding.threat_ids?.map((id) => (
                          <TaxonomyBadge key={`f-ubi-${id}`} label="УБИ" value={id} />
                        ))}
                        {finding.cve_ids?.map((id) => (
                          <TaxonomyBadge key={`f-cve-${id}`} label="CVE" value={id} />
                        ))}
                      </div>
                      {finding.description && <p className="text-sm text-slate-300">{finding.description}</p>}
                    </article>
                  );
                })}
              </div>
            </section>
          )}

          <pre className="overflow-x-auto rounded-2xl bg-slate-950/70 p-4 text-xs text-slate-100">{content}</pre>
        </div>
      </div>
    </div>
  );
}


