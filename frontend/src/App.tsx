import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Globe, Shield, Sparkles, Zap } from "lucide-react";
import { CommandHub } from "./components/CommandHub";
import { SystemPulse } from "./components/SystemPulse";
import { HistoryPanel } from "./components/HistoryPanel";
import { DetailDrawer } from "./components/DetailDrawer";
import { AuthOverlay } from "./components/AuthOverlay";
import { ToastStack } from "./components/ToastStack";
import type { ActionSummary, LlmReport } from "./types";
import {
  AttackFormState,
  FilterState,
  HealthResponse,
  HistoryItem,
  HistoryStats,
  LlmFormState,
  PendingAction,
  ReconFormState,
  TaskControlState,
  Toast,
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";
const ACCESS_PASS = (import.meta.env.VITE_ACCESS_PASS ?? "").trim();

const createId = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : Math.random().toString(36).slice(2, 10);

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

const formatDate = (value?: string) => {
  if (!value) return "—";
  const date = new Date(value);
  return Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "medium" }).format(date);
};

const stringify = (value: unknown) =>
  JSON.stringify(
    value,
    (_, current) => (typeof current === "bigint" ? Number(current) : current),
    2,
  );

const safeItems = (items?: HistoryItem[]) => (Array.isArray(items) ? items : []);
const mapTasks = (items?: TaskControlState[]) =>
  (Array.isArray(items) ? items : []).reduce<Record<string, TaskControlState>>((acc, task) => {
    acc[task.task_id] = task;
    return acc;
  }, {});

export default function App() {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [detailItem, setDetailItem] = useState<HistoryItem | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [tasks, setTasks] = useState<Record<string, TaskControlState>>({});
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [filters, setFilters] = useState<FilterState>({ search: "", status: "all" });
  const [toastList, setToastList] = useState<Toast[]>([]);
  const [reconForm, setReconForm] = useState<ReconFormState>({
    target: "scanme.nmap.org",
    targetType: "ip",
    comprehensive: true,
    scanners: {
      nmap: true,
      shodan: true,
      virustotal: true,
    },
    nmapArgs: "-sC -sV",
    shodanQuery: "ssl:true org:\"Example Corp\"",
    virustotalFlags: "--include-malware --historical",
    label: "",
  });
  const [attackForm, setAttackForm] = useState<AttackFormState>({
    target: "10.10.10.10",
    attackType: "bruteforce",
    profile: "black_box",
    dry_run: true,
    service: "ssh",
    port: 22,
    dictionary: "/opt/wordlists/rockyou.txt",
    usernames: "root,admin,ubuntu",
    concurrency: 4,
    metasploitModule: "auxiliary/scanner/ssh/ssh_login",
    metasploitPayload: "linux/x64/shell_reverse_tcp",
    metasploitOptions: "LHOST=10.10.14.2;LPORT=4444",
    sqlmapFlags: "--risk=3 --level=5 --batch",
    injectionParam: "q",
    injectionPayloads: "",
    traversalFile: "etc/passwd",
    ssrfTargets: "",
    redirectPayload: "https://evil.example.com",
    corsOrigin: "https://evil-attacker.example",
    label: "",
  });
  const [llmForm, setLlmForm] = useState<LlmFormState>({
    url: "http://testphp.vulnweb.com",
    goal: "Найди OWASP Top 10, утечки данных и уязвимые компоненты.",
    use_browser: true,
    label: "",
  });
  const [autopentestForm, setAutopentestForm] = useState<AutoPentestForm>({
    target: "scanme.nmap.org",
    profile: "black_box",
    goal: "Построить цепочку атак и подготовить отчёт.",
    scope: "",
    notes: "",
    label: "",
  });
  const [isAuthorized, setIsAuthorized] = useState(() => ACCESS_PASS.length === 0);
  const [passwordInput, setPasswordInput] = useState("");
  const [authError, setAuthError] = useState("");

  const notify = (toast: Omit<Toast, "id">) => {
    setToastList((prev) => [...prev, { ...toast, id: createId() }]);
    setTimeout(() => setToastList((prev) => prev.slice(1)), 4200);
  };

  const fetchHistory = async () => {
    try {
      setLoadingHistory(true);
      const [historyResponse, tasksResponse] = await Promise.all([
        apiFetch<{ items?: HistoryItem[] }>("/history"),
        apiFetch<{ items?: TaskControlState[] }>("/tasks"),
      ]);
      setHistory(safeItems(historyResponse.items).slice().reverse());
      setTasks(mapTasks(tasksResponse.items));
    } catch (error) {
      notify({ tone: "error", title: "История недоступна", description: String(error) });
    } finally {
      setLoadingHistory(false);
    }
  };

  const fetchHealth = async () => {
    try {
      const response = await apiFetch<HealthResponse>("/health");
      setHealth(response);
    } catch {
      setHealth(null);
    }
  };

  useEffect(() => {
    fetchHistory();
    fetchHealth();
    const savedPass = localStorage.getItem("reconscope:access");
    if (ACCESS_PASS && savedPass === ACCESS_PASS) {
      setIsAuthorized(true);
    }
    const historyTimer = setInterval(fetchHistory, 15000);
    const healthTimer = setInterval(fetchHealth, 30000);
    return () => {
      clearInterval(historyTimer);
      clearInterval(healthTimer);
    };
  }, []);

  const runAction = async (action: Exclude<PendingAction, null>, request: () => Promise<void>) => {
    setPendingAction(action);
    try {
      await request();
      notify({ tone: "success", title: "Задача запущена", description: "Проверьте историю через несколько секунд" });
      fetchHistory();
    } catch (error) {
      notify({ tone: "error", title: "Ошибка запуска", description: String(error) });
    } finally {
      setPendingAction(null);
    }
  };

  const handleRecon = () =>
    runAction("recon", async () => {
      const label = reconForm.label.trim();
      const payload = {
        target: reconForm.target,
        target_type: reconForm.targetType,
        comprehensive: reconForm.comprehensive,
        scanners: reconForm.scanners,
        overrides: {
          nmap_args: reconForm.nmapArgs,
          shodan_query: reconForm.shodanQuery,
          virustotal_flags: reconForm.virustotalFlags,
        },
        label: label || undefined,
      };
      await apiFetch(
        reconForm.comprehensive ? "/intelligence/comprehensive" : "/intelligence/basic",
        { method: "POST", body: JSON.stringify(payload) },
      );
    });

  const handleAttack = () =>
    runAction("attack", async () => {
      const label = attackForm.label.trim();
      const customPayloads = attackForm.injectionPayloads
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean);
      const ssrfTargets = attackForm.ssrfTargets
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean);
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
            dictionary: attackForm.dictionary,
            usernames: attackForm.usernames,
            concurrency: Number(attackForm.concurrency),
            metasploit_module: attackForm.metasploitModule,
            metasploit_payload: attackForm.metasploitPayload,
            metasploit_options: attackForm.metasploitOptions,
            sqlmap_flags: attackForm.sqlmapFlags,
            param: attackForm.injectionParam,
            ...(customPayloads.length > 0 ? { payloads: customPayloads } : {}),
            file: attackForm.traversalFile,
            ...(ssrfTargets.length > 0 ? { targets: ssrfTargets } : {}),
            payload: attackForm.redirectPayload,
            origin: attackForm.corsOrigin,
          },
          label: label || undefined,
        }),
      });
    });

  const handleLLMScan = () =>
    runAction("llm", async () => {
      const label = llmForm.label.trim();
      await apiFetch("/llm/scan", {
        method: "POST",
        body: JSON.stringify({
          url: llmForm.url,
          goal: llmForm.goal,
          use_browser: llmForm.use_browser,
          label: label || undefined,
        }),
      });
    });

  const handleAutoPentest = () =>
    runAction("autopentest", async () => {
      const label = autopentestForm.label.trim();
      await apiFetch("/autopentest/start", {
        method: "POST",
        body: JSON.stringify({
          target: autopentestForm.target,
          profile: autopentestForm.profile,
          goal: autopentestForm.goal,
          scope: autopentestForm.scope,
          notes: autopentestForm.notes,
          label: label || undefined,
        }),
      });
    });

  const historyStats = useMemo<HistoryStats>(() => {
    const effectiveStatuses = history.map((item) => {
      const taskId = item.task_id ?? item.event_id ?? item.scan_id ?? item.report_id;
      return tasks[taskId ?? ""]?.status ?? item.status ?? "completed";
    });
    const completed = effectiveStatuses.filter((status) => status === "completed").length;
    const failed = effectiveStatuses.filter((status) => status.includes("fail") || status === "error").length;
    const running = effectiveStatuses.filter((status) => ["started", "processing", "running"].includes(status)).length;
    const total = history.length;
    const successRate = total === 0 ? 0 : Math.round((completed / total) * 100);
    return { completed, failed, running, total, successRate };
  }, [history, tasks]);

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesSearch =
        filters.search.trim().length === 0 ||
        [item.label, item.target, item.event_id, item.scan_id, item.type]
          .join(" ")
          .toLowerCase()
          .includes(filters.search.toLowerCase());
      const taskId = item.task_id ?? item.event_id ?? item.scan_id ?? item.report_id;
      const taskStatus = taskId ? tasks[taskId]?.status : undefined;
      const effectiveStatus = taskStatus ?? item.status;
      const matchesStatus = filters.status === "all" || effectiveStatus === filters.status;
      return matchesSearch && matchesStatus;
    });
  }, [filters, history, tasks]);

  const downloadResult = (item: HistoryItem) => {
    const filename = `${item.event_id || item.scan_id || item.report_id || "result"}.json`;
    const blob = new Blob([stringify(item)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const handleTaskAction = async (taskId: string, action: "pause" | "resume" | "cancel") => {
    try {
      await apiFetch(`/tasks/${taskId}/${action}`, {
        method: "POST",
        body: action === "cancel" ? JSON.stringify({ reason: "Остановлено через интерфейс" }) : undefined,
      });
      notify({
        tone: "success",
        title: "Статус обновлён",
        description:
          action === "pause"
            ? "Задача поставлена на паузу"
            : action === "resume"
              ? "Задача продолжена"
              : "Задача отменена",
      });
      fetchHistory();
    } catch (error) {
      notify({ tone: "error", title: "Не удалось обновить задачу", description: String(error) });
    }
  };

  const detailValue = detailItem && (detailItem.data ?? detailItem);
  const latestTimestamp = history[0]?.timestamp ?? history[0]?.updated_at;
  const apiDocsUrl = `${API_BASE}/docs`;

  const summaryInfo = useMemo(() => {
    if (!detailItem) return null;

    const rawData = detailItem.data;
    const dataObject =
      rawData && typeof rawData === "object" && !Array.isArray(rawData) ? (rawData as Record<string, unknown>) : undefined;

    const dataReport =
      dataObject && "report" in dataObject
        ? ((dataObject as { report?: unknown }).report as LlmReport | undefined)
        : undefined;
    const nestedActionSummary =
      dataObject && "action_summary" in dataObject
        ? ((dataObject as { action_summary?: unknown }).action_summary as ActionSummary | undefined)
        : undefined;

    const report = detailItem.report ?? dataReport;
    const actionSummary =
      detailItem.action_summary ?? nestedActionSummary ?? report?.action_summary ?? null;

    const summaryTextCandidate =
      (typeof detailItem.summary === "string" ? detailItem.summary : undefined) ??
      (dataObject && "summary" in dataObject && typeof (dataObject as { summary?: unknown }).summary === "string"
        ? ((dataObject as { summary?: string }).summary as string)
        : undefined) ??
      (report && typeof report.summary === "string" ? report.summary : undefined);

    if (!actionSummary && !summaryTextCandidate) {
      return null;
    }

    const defensive =
      actionSummary?.defensive_actions?.map((item) => item?.trim()).filter((item): item is string => Boolean(item)) ?? [];
    const offensive =
      actionSummary?.offensive_actions?.map((item) => item?.trim()).filter((item): item is string => Boolean(item)) ?? [];
    const changes = actionSummary?.changes?.trim();

    return {
      summary: summaryTextCandidate,
      changes: changes && changes.length > 0 ? changes : undefined,
      defensive,
      offensive,
    };
  }, [detailItem]);

  const handleAuthorize = () => {
    if (!ACCESS_PASS) {
      setIsAuthorized(true);
      return;
    }
    if (passwordInput === ACCESS_PASS) {
      localStorage.setItem("reconscope:access", ACCESS_PASS);
      setIsAuthorized(true);
      setAuthError("");
      return;
    }
    setAuthError("Неверный пароль");
  };

  const scrollToHub = () => {
    if (typeof document === "undefined") return;
    document.getElementById("command-hub")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const heroHighlights = [
    { title: "Recon orchestration", subtitle: "Nmap · Shodan · VirusTotal", icon: Globe },
    { title: "LLM pipeline", subtitle: "Playwright + OpenRouter", icon: Sparkles },
    { title: "Secure playground", subtitle: "Dry-run · Audit trail", icon: Shield },
  ];

  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-950 text-slate-50">
      <div className="pointer-events-none absolute inset-0 grid-overlay" />
      <div className="blur-blob absolute -top-32 left-0 h-72 w-72 bg-primary/30" />
      <div className="blur-blob absolute bottom-0 right-0 h-96 w-96 bg-accent/20" />

      <div className="relative z-10 mx-auto max-w-6xl space-y-10 px-4 py-10 lg:px-8 lg:py-14">
        <header className="shimmer-border surface relative overflow-hidden px-6 py-8 lg:px-10">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-start">
            <div className="space-y-6 lg:max-w-3xl">
              <span className="chip inline-flex items-center gap-2 bg-white/5 text-slate-300">
                <Sparkles className="h-4 w-4 text-primary" />
                ReconScope · Command 0.2
              </span>
              <div className="space-y-4">
                <h1 className="text-4xl font-semibold leading-tight text-white lg:text-5xl">
                  Операционный центр для разведки, атак и LLM-аудитов
                </h1>
                <p className="text-sm text-slate-400">
                  Запускайте сценарии Black/Grey/White box, отслеживайте телеметрию инфраструктуры и анализируйте результаты
                  в одном стекле. Каждый запуск сохраняется в истории с полным JSON.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={scrollToHub}
                  className="inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-primary to-accent px-6 py-3 text-sm font-semibold text-slate-950 shadow-primary/40 transition hover:brightness-110"
                >
                  <Zap className="h-4 w-4" />
                  Открыть командный центр
                </button>
                <a
                  href={apiDocsUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-2xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-100 transition hover:border-white/30"
                >
                  <ArrowUpRight className="h-4 w-4" />
                  API Docs
                </a>
              </div>
              <div className="flex flex-wrap gap-4 text-xs uppercase tracking-[0.35em] text-slate-400">
                <span className="chip bg-white/5 text-slate-200">FastAPI Core</span>
                <span className="chip bg-white/5 text-slate-200">Event history</span>
                <span className="chip bg-white/5 text-slate-200">JSON export</span>
              </div>
            </div>
            <div className="flex-1 space-y-4 rounded-3xl border border-white/10 bg-slate-950/50 p-5">
              <div className="grid gap-3 sm:grid-cols-2">
                {[
                  { label: "Всего задач", value: historyStats.total },
                  { label: "Успешность", value: `${historyStats.successRate}%` },
                  {
                    label: "Компоненты",
                    value: Object.keys(health?.components ?? {}).length || "—",
                  },
                ].map((stat) => (
                  <article key={stat.label} className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                    <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500">{stat.label}</p>
                    <p className="mt-2 text-2xl font-semibold text-white">{stat.value}</p>
                  </article>
                ))}
              </div>
              <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-gradient-to-r from-primary/10 to-accent/10 px-4 py-3 text-sm text-slate-300">
                <div>
                  <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Последнее событие</p>
                  <p className="text-base text-white">{formatDate(latestTimestamp)}</p>
                </div>
                <span className="rounded-full bg-white/10 px-3 py-1 text-xs uppercase tracking-[0.3em] text-slate-400">
                  Live feed
                </span>
              </div>
            </div>
          </div>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {heroHighlights.map((item) => (
              <article
                key={item.title}
                className="rounded-3xl border border-white/10 bg-white/5 px-4 py-5 text-sm text-slate-300"
              >
                <item.icon className="mb-3 h-5 w-5 text-primary" />
                <p className="text-base font-semibold text-white">{item.title}</p>
                <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{item.subtitle}</p>
              </article>
            ))}
          </div>
        </header>

        <section id="command-hub" className="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
          <CommandHub
            reconForm={reconForm}
            setReconForm={setReconForm}
            attackForm={attackForm}
            setAttackForm={setAttackForm}
            llmForm={llmForm}
            setLlmForm={setLlmForm}
            autopentestForm={autopentestForm}
            setAutopentestForm={setAutopentestForm}
            pendingAction={pendingAction}
            onRecon={handleRecon}
            onAttack={handleAttack}
            onLLM={handleLLMScan}
            onAutoPentest={handleAutoPentest}
          />
          <SystemPulse
            health={health}
            onRefresh={fetchHealth}
            historyStats={historyStats}
            lastUpdated={latestTimestamp}
            formatDate={formatDate}
          />
        </section>

        <HistoryPanel
          filteredHistory={filteredHistory}
          filters={filters}
          setFilters={setFilters}
          loadingHistory={loadingHistory}
          onRefresh={fetchHistory}
          onSelectItem={setDetailItem}
          formatDate={formatDate}
          apiDocsUrl={apiDocsUrl}
          taskControls={tasks}
          onTaskAction={handleTaskAction}
        />
      </div>

      <AuthOverlay
        isAuthorized={isAuthorized}
        passwordInput={passwordInput}
        onChangePassword={setPasswordInput}
        onSubmit={handleAuthorize}
        authError={authError}
        pendingAction={pendingAction}
      />

      <DetailDrawer
        item={detailItem}
        content={detailItem && detailValue ? stringify(detailValue) : ""}
        summaryInfo={summaryInfo}
        onClose={() => setDetailItem(null)}
        onDownload={downloadResult}
      />

      <ToastStack toastList={toastList} />
    </div>
  );
}


