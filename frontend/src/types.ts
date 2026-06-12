export type PendingAction = "recon" | "attack" | "llm" | "autopentest" | null;

export type OsintScanners = {
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

export type ReconFormState = {
  target: string;
  targetType: "ip" | "domain" | "network";
  comprehensive: boolean;
  useCache: boolean;
  scanners: OsintScanners;
  nmapArgs: string;
  shodanQuery: string;
  googleDork: string;
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
  ssrfTargets: string;
  redirectPayload: string;
  corsOrigin: string;
  nmapScanType: "quick" | "full" | "vuln" | "custom";
  nmapArguments: string;
  label: string;
};

export type LlmFormState = {
  url: string;
  target: string;
  goal: string;
  use_browser: boolean;
  run_osint: boolean;
  comprehensive: boolean;
  label: string;
};

export type ActionSummary = {
  changes?: string;
  defensive_actions?: string[];
  offensive_actions?: string[];
};

export type ScanFinding = {
  title?: string;
  severity?: string;
  description?: string;
  evidence?: string[];
  recommendations?: string[];
  cwe_ids?: string[];
  cve_ids?: string[];
  bdu_ids?: string[];
  threat_ids?: string[];
};

export type LlmReport = {
  summary?: string;
  findings?: ScanFinding[];
  metadata?: {
    taxonomy?: { cwe?: string[]; bdu?: string[]; threats?: string[] };
    enrichment?: Record<string, unknown>;
    [key: string]: unknown;
  };
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
  recon_summary?: string;
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
