export type PendingAction = "recon" | "attack" | "llm" | null;

export type ReconFormState = {
  target: string;
  targetType: "ip" | "domain" | "network";
  comprehensive: boolean;
  scanners: {
    nmap: boolean;
    shodan: boolean;
    virustotal: boolean;
    subdomains: boolean;
    technologies: boolean;
    files: boolean;
    github: boolean;
    seo: boolean;
    dorks: boolean;
  };
  nmapArgs: string;
  shodanQuery: string;
  googleDork: string;
  virustotalFlags: string;
  useCache: boolean;
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
};

export type LlmFormState = {
  url: string;
  goal: string;
  use_browser: boolean;
  reconEventId: string;
  runReconFirst: boolean;
  useCombinedAudit: boolean;
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

