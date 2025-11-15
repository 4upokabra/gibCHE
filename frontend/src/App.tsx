import { useEffect, useMemo, useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@radix-ui/react-tabs";
import { Download, Loader2, RefreshCw, ShieldCheck, Zap } from "lucide-react";
import clsx from "clsx";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

type HistoryItem = {
  event_id?: string;
  scan_id?: string;
  type?: string;
  status?: string;
  timestamp?: string;
  updated_at?: string;
  data?: unknown;
  target?: string;
};

type Toast = {
  id: string;
  title: string;
  description: string;
  tone: "success" | "error";
};

const formCard = "glass rounded-2xl p-6 flex flex-col gap-4";
const labelCls = "text-sm font-medium text-slate-200";
const inputCls =
  "mt-1 w-full rounded-lg bg-slate-900/60 border border-slate-700/70 px-3 py-2 text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-primary";
const buttonCls =
  "inline-flex items-center justify-center rounded-xl px-4 py-2 font-semibold transition-all focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-50";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return await response.json();
}

const heroGradient =
  "relative overflow-hidden rounded-3xl glass p-8 border border-slate-700/60 shadow-[0_25px_80px_rgba(124,58,237,0.25)]";

function Hero() {
  return (
    <section className={heroGradient}>
      <div className="absolute -right-10 -top-10 h-40 w-40 rounded-full bg-primary/30 blur-3xl" />
      <div className="absolute -left-6 bottom-0 h-32 w-32 rounded-full bg-accent/20 blur-3xl" />
      <div className="relative flex flex-col gap-4 text-slate-100">
        <p className="text-sm uppercase tracking-[0.3em] text-slate-400">ReconScope</p>
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-3xl font-semibold leading-tight md:text-4xl">
              Совмещённые разведка, атаки и LLM-аналитика в одном дашборде
            </h1>
            <p className="mt-3 max-w-2xl text-slate-300">
              Управляйте брутфорсом, SQLi, Metasploit, пассивной разведкой и LLM-аудитом
              через единый интерфейс. Мониторьте результаты и скачивайте их для отчётности.
            </p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-slate-600/70 px-4 py-2 text-sm text-slate-200">
            <ShieldCheck className="h-4 w-4 text-accent" /> Black • Grey • White Box
          </span>
        </div>
      </div>
    </section>
  );
}

function ResultCard({ item, onDownload }: { item: HistoryItem; onDownload: (item: HistoryItem) => void }) {
  const title = item.type ?? "event";
  const subtitle = item.target ?? item.event_id ?? item.scan_id ?? "";
  const status = item.status ?? "unknown";
  const timestamp = item.timestamp ?? item.updated_at ?? "";

  return (
    <div className="glass rounded-2xl p-4 border border-slate-700/60 flex flex-col gap-2">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-slate-400">{title}</p>
          <p className="text-lg font-semibold text-slate-100">{subtitle}</p>
        </div>
        <span
          className={clsx(
            "px-3 py-1 text-xs font-semibold rounded-full",
            status === "completed"
              ? "bg-emerald-400/20 text-emerald-300"
              : status === "failed" || status === "error"
                ? "bg-rose-400/20 text-rose-300"
                : "bg-slate-400/20 text-slate-300",
          )}
        >
          {status}
        </span>
      </div>
      <p className="text-xs text-slate-400">{timestamp}</p>
      <div className="flex justify-end">
        <button
          className={clsx(buttonCls, "bg-slate-800 hover:bg-slate-700 text-slate-100 gap-2 text-sm")}
          onClick={() => onDownload(item)}
        >
          <Download className="h-4 w-4" /> Скачать JSON
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [toastList, setToastList] = useState<Toast[]>([]);

  const [reconForm, setReconForm] = useState({
    target: "scanme.nmap.org",
    targetType: "ip",
    comprehensive: false,
  });

  const [attackForm, setAttackForm] = useState({
    target: "10.10.10.10",
    attackType: "bruteforce",
    profile: "black_box",
    dry_run: true,
    service: "ssh",
    port: 22,
  });

  const [llmForm, setLlmForm] = useState({
    url: "http://testphp.vulnweb.com",
    goal: "Найди OWASP Top 10 и критичные конфигурационные ошибки.",
    use_browser: true,
  });

  const [activeTab, setActiveTab] = useState("recon");
  const [pending, setPending] = useState(false);

  const notify = (toast: Omit<Toast, "id">) => {
    setToastList((prev) => [...prev, { ...toast, id: crypto.randomUUID() }]);
    setTimeout(() => setToastList((prev) => prev.slice(1)), 4000);
  };

  const fetchHistory = async () => {
    try {
      setLoadingHistory(true);
      const response = await apiFetch<{ items: HistoryItem[] }>("/history");
      setHistory(response.items.reverse());
    } catch (error) {
      notify({ tone: "error", title: "Ошибка истории", description: String(error) });
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleRecon = async () => {
    setPending(true);
    try {
      const payload = {
        target: reconForm.target,
        target_type: reconForm.targetType,
        comprehensive: reconForm.comprehensive,
      };
      if (reconForm.comprehensive) {
        await apiFetch("/intelligence/comprehensive", {
          method: "POST",
          body: JSON.stringify(payload),
        });
      } else {
        await apiFetch("/intelligence/basic", {
          method: "POST",
          body: JSON.stringify(payload),
        });
      }
      notify({ tone: "success", title: "Запущено", description: "Сбор разведки стартовал" });
      fetchHistory();
    } catch (error) {
      notify({ tone: "error", title: "Сбой разведки", description: String(error) });
    } finally {
      setPending(false);
    }
  };

  const handleAttack = async () => {
    setPending(true);
    try {
      await apiFetch("/attack/execute", {
        method: "POST",
        body: JSON.stringify({
          target: attackForm.target,
          attack_type: attackForm.attackType,
          profile: attackForm.profile,
          dry_run: attackForm.dry_run,
          parameters: {
            service: attackForm.service,
            port: Number(attackForm.port),
          },
        }),
      });
      notify({ tone: "success", title: "Атака запущена", description: "Результат появится в истории" });
      fetchHistory();
    } catch (error) {
      notify({ tone: "error", title: "Сбой атаки", description: String(error) });
    } finally {
      setPending(false);
    }
  };

  const handleLLMScan = async () => {
    setPending(true);
    try {
      await apiFetch("/llm/scan", {
        method: "POST",
        body: JSON.stringify({
          url: llmForm.url,
          goal: llmForm.goal,
          use_browser: llmForm.use_browser,
        }),
      });
      notify({ tone: "success", title: "LLM-скан запущен", description: "Отчёт появится после обработки" });
      fetchHistory();
    } catch (error) {
      notify({ tone: "error", title: "Сбой LLM", description: String(error) });
    } finally {
      setPending(false);
    }
  };

  const downloadResult = (item: HistoryItem) => {
    const filename = `${item.event_id || item.scan_id || "result"}.json`;
    const blob = new Blob([JSON.stringify(item, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const actionButtons = useMemo(
    () => (
      <div className="flex flex-wrap gap-3">
        <button
          onClick={fetchHistory}
          className={clsx(buttonCls, "bg-slate-800 hover:bg-slate-700 text-slate-100 gap-2 text-sm")}
        >
          <RefreshCw className="h-4 w-4" /> Обновить историю
        </button>
        <a
          href={`${API_BASE}/docs`}
          target="_blank"
          rel="noreferrer"
          className={clsx(buttonCls, "border border-slate-700 text-slate-200 text-sm")}
        >
          Открыть Swagger
        </a>
      </div>
    ),
    [],
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-6xl px-4 py-8 md:py-12 flex flex-col gap-8">
        <Hero />

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="glass grid grid-cols-2 md:grid-cols-4 gap-2 p-2 rounded-2xl">
            {[
              { id: "recon", label: "Разведка" },
              { id: "attack", label: "Атаки" },
              { id: "llm", label: "LLM" },
              { id: "history", label: "История" },
            ].map((tab) => (
              <TabsTrigger
                key={tab.id}
                value={tab.id}
                className="rounded-xl px-4 py-2 text-sm font-medium data-[state=active]:bg-primary/30 data-[state=active]:text-white"
              >
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="recon" className="mt-6">
            <div className={formCard}>
              <div>
                <p className="text-xl font-semibold">Пассивная разведка</p>
                <p className="text-sm text-slate-400">Подключены Nmap, Shodan, VirusTotal</p>
              </div>
              <div className="grid gap-4 md:grid-cols-3">
                <label className={labelCls}>
                  Цель
                  <input
                    className={inputCls}
                    value={reconForm.target}
                    onChange={(e) => setReconForm({ ...reconForm, target: e.target.value })}
                  />
                </label>
                <label className={labelCls}>
                  Тип цели
                  <select
                    className={inputCls}
                    value={reconForm.targetType}
                    onChange={(e) => setReconForm({ ...reconForm, targetType: e.target.value })}
                  >
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="network">Network</option>
                  </select>
                </label>
                <label className="flex items-center gap-3 text-sm text-slate-200">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-slate-600 bg-slate-800 text-primary focus:ring-primary"
                    checked={reconForm.comprehensive}
                    onChange={(e) => setReconForm({ ...reconForm, comprehensive: e.target.checked })}
                  />
                  Комплексный режим
                </label>
              </div>
              <button
                onClick={handleRecon}
                disabled={pending}
                className={clsx(buttonCls, "bg-primary/90 hover:bg-primary text-white gap-2 mt-2 self-start")}
              >
                {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                Запустить разведку
              </button>
            </div>
          </TabsContent>

          <TabsContent value="attack" className="mt-6">
            <div className={formCard}>
              <div>
                <p className="text-xl font-semibold">Модуль атак Dev B</p>
                <p className="text-sm text-slate-400">
                  Доступны брутфорс (Hydra), SQLi (sqlmap), Metasploit и аудит версий.
                </p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <label className={labelCls}>
                  Цель
                  <input
                    className={inputCls}
                    value={attackForm.target}
                    onChange={(e) => setAttackForm({ ...attackForm, target: e.target.value })}
                  />
                </label>
                <label className={labelCls}>
                  Тип атаки
                  <select
                    className={inputCls}
                    value={attackForm.attackType}
                    onChange={(e) => setAttackForm({ ...attackForm, attackType: e.target.value })}
                  >
                    <option value="bruteforce">Bruteforce</option>
                    <option value="sqli">SQLi</option>
                    <option value="metasploit">Metasploit</option>
                    <option value="legacy_audit">Legacy Audit</option>
                  </select>
                </label>
                <label className={labelCls}>
                  Профиль теста
                  <select
                    className={inputCls}
                    value={attackForm.profile}
                    onChange={(e) => setAttackForm({ ...attackForm, profile: e.target.value })}
                  >
                    <option value="black_box">Black Box</option>
                    <option value="grey_box">Grey Box</option>
                    <option value="white_box">White Box</option>
                  </select>
                </label>
                <label className="flex items-center gap-3 text-sm text-slate-200">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-slate-600 bg-slate-800 text-primary focus:ring-primary"
                    checked={attackForm.dry_run}
                    onChange={(e) => setAttackForm({ ...attackForm, dry_run: e.target.checked })}
                  />
                  Dry-run
                </label>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <label className={labelCls}>
                  Сервис
                  <input
                    className={inputCls}
                    value={attackForm.service}
                    onChange={(e) => setAttackForm({ ...attackForm, service: e.target.value })}
                  />
                </label>
                <label className={labelCls}>
                  Порт
                  <input
                    className={inputCls}
                    type="number"
                    value={attackForm.port}
                    onChange={(e) => setAttackForm({ ...attackForm, port: Number(e.target.value) })}
                  />
                </label>
              </div>
              <button
                onClick={handleAttack}
                disabled={pending}
                className={clsx(
                  buttonCls,
                  "bg-gradient-to-r from-primary to-accent text-slate-900 gap-2 mt-2 self-start",
                )}
              >
                {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                Запустить атаку
              </button>
            </div>
          </TabsContent>
          <TabsContent value="llm" className="mt-6">
            <div className={formCard}>
              <div>
                <p className="text-xl font-semibold">LLM-сканер</p>
                <p className="text-sm text-slate-400">
                  Парсинг контента, нормализация и генерация отчёта на базе OpenRouter.
                </p>
              </div>
              <label className={labelCls}>
                URL
                <input
                  className={inputCls}
                  value={llmForm.url}
                  onChange={(e) => setLlmForm({ ...llmForm, url: e.target.value })}
                />
              </label>
              <label className={labelCls}>
                Цель аудита
                <textarea
                  className={clsx(inputCls, "min-h-[96px]")}
                  value={llmForm.goal}
                  onChange={(e) => setLlmForm({ ...llmForm, goal: e.target.value })}
                />
              </label>
              <label className="flex items-center gap-3 text-sm text-slate-200">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-slate-600 bg-slate-800 text-primary focus:ring-primary"
                  checked={llmForm.use_browser}
                  onChange={(e) => setLlmForm({ ...llmForm, use_browser: e.target.checked })}
                />
                Использовать браузер (Playwright)
              </label>
              <button
                onClick={handleLLMScan}
                disabled={pending}
                className={clsx(buttonCls, "bg-slate-100 text-slate-900 gap-2 mt-2 self-start")}
              >
                {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                Запустить LLM-скан
              </button>
            </div>
          </TabsContent>

          <TabsContent value="history" className="mt-6 flex flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xl font-semibold">История операций</p>
                <p className="text-sm text-slate-400">Все атаки, разведка и сканы в одном списке</p>
              </div>
              {actionButtons}
            </div>
            {loadingHistory ? (
              <div className="flex items-center justify-center rounded-2xl border border-dashed border-slate-700 py-12 text-slate-400">
                <Loader2 className="mr-3 h-5 w-5 animate-spin" />
                Загружаем историю...
              </div>
            ) : history.length === 0 ? (
              <div className="glass rounded-2xl border border-slate-700/60 p-8 text-center text-slate-400">
                Пока нет записей. Запустите разведку, атаку или LLM-скан.
              </div>
            ) : (
              <div className="grid gap-4 md:grid-cols-2">
                {history.map((item) => (
                  <ResultCard key={item.event_id ?? item.scan_id} item={item} onDownload={downloadResult} />
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>

        <div className="flex justify-center">
          <p className="text-center text-sm text-slate-500">
            Backend: FastAPI · Attack Engine Dev B · Реализация UI: React + Tailwind + Radix UI
          </p>
        </div>
      </div>

      <div className="fixed bottom-4 right-4 flex flex-col gap-2">
        {toastList.map((toast) => (
          <div
            key={toast.id}
            className={clsx(
              "rounded-2xl px-4 py-3 shadow-2xl glass border",
              toast.tone === "success" ? "border-emerald-400/40" : "border-rose-400/40",
            )}
          >
            <p className="text-sm font-semibold">{toast.title}</p>
            <p className="text-xs text-slate-400">{toast.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

