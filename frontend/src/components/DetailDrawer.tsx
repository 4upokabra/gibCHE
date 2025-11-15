import { FileDown, X } from "lucide-react";
import { HistoryItem } from "../types";

type DetailDrawerProps = {
  item: HistoryItem | null;
  content: string;
  onClose: () => void;
  onDownload: (item: HistoryItem) => void;
};

export function DetailDrawer({ item, content, onClose, onDownload }: DetailDrawerProps) {
  if (!item) return null;

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
        <div className="h-full max-h-[80vh] overflow-y-auto px-6 py-5">
          <pre className="overflow-x-auto rounded-2xl bg-slate-950/70 p-4 text-xs text-slate-100">{content}</pre>
        </div>
      </div>
    </div>
  );
}


