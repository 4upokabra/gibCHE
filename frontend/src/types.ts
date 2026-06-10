export type PendingAction = "recon" | "attack" | "llm" | "autopentest" | null;

export type ReconFormState = {
  target: string;
  targetType: "ip" | "domain" | "network";
  comprehensive: boolean;
  scanners: {
    nmap: boolean;
    shodan: boolean;
    virustotal: boolean;
  };
  nmapArgs: string;
  shodanQuery: string;
  virustotalFlags: string;
  label: string;
};

export type AttackFormState = {
  target: string;
  attackType: string;
  profile: "black_box" | "grey_box" | "white_box";
  dry_run: boolean;
  service: string;
  port: number;
  dictionary: string;
  usernames: string;
  concurrency: number;
  metasploitModule: string;
  metasploitPayload: string;
  metasploitOptions: string;
  sqlmapFlags: string;
  injectionParam: string;
  injectionPayloads: string;
  traversalFile: string;
  label: string;
};

export type LlmFormState = {
  url: string;
  goal: string;
  use_browser: boolean;
  label: string;
};

export type ActionSummary = {
  changes?: string;
  defensive_actions?: string[];
  offensive_actions?: string[];
};

export type LlmReport = {
  summary?: string;
  action_summary?: ActionSummary;
  [key: string]: unknown;
};

export type HistoryItem = {
  event_id?: string;
  scan_id?: string;
  report_id?: string;
  task_id?: string;
  type?: string;
  status?: string;
  timestamp?: string;
  updated_at?: string;
  data?: unknown;
  target?: string;
  details?: string;
  message?: string;
  error?: string;
  summary?: string;
  metadata?: Record<string, unknown>;
  action_summary?: ActionSummary;
  report?: LlmReport;
  label?: string;
};

export type HistoryStats = {
  completed: number;
  failed: number;
  running: number;
  total: number;
  successRate: number;
};

export type FilterState = {
  search: string;
  status: string;
};

export type TaskControlState = {
  task_id: string;
  kind: string;
  status: string;
  metadata?: Record<string, unknown>;
  error?: string;
  created_at: string;
  updated_at: string;
};

export type HealthResponse = {
  status: string;
  timestamp: string;
  components: Record<string, string>;
};

export type Toast = {
  id: string;
  title: string;
  description: string;
  tone: "success" | "error";
};

export type AutoPentestForm = {
  target: string;
  profile: "black_box" | "grey_box" | "white_box";
  goal: string;
  scope: string;
  notes: string;
  label: string;
};

