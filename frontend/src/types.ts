export type PendingAction = "recon" | "attack" | "llm" | null;

export type ReconFormState = {
  target: string;
  targetType: "ip" | "domain" | "network";
  comprehensive: boolean;
};

export type AttackFormState = {
  target: string;
  attackType: string;
  profile: "black_box" | "grey_box" | "white_box";
  dry_run: boolean;
  service: string;
  port: number;
};

export type LlmFormState = {
  url: string;
  goal: string;
  use_browser: boolean;
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

