// 这里的类型定义尽量与后端 JSON 字段保持一致（snake_case），
// 这样页面代码可以“直连 API”而不需要额外的字段映射层。

export type MetaResponse = {
  ok: boolean;
  time: number;
  app: {
    version: string;
    commit: string;
    build_time: string;
  };
  db: {
    schema_version: string;
    schema_name: string;
    path: string;
  };
  rules: {
    wallet: {
      path: string;
      version: string;
      total: number;
      enabled: number;
      sha256: string;
    };
    exchange: {
      path: string;
      version: string;
      total: number;
      enabled: number;
      sha256: string;
    };
  };
};

export type CaseSummary = {
  case_id: string;
  case_no?: string;
  title?: string;
  status: string;
  created_by?: string;
  note?: string;
  created_at: number;
  updated_at: number;
};

export type CaseOverview = {
  case_id: string;
  case_no?: string;
  title?: string;
  status: string;
  created_by?: string;
  note?: string;
  created_at: number;
  updated_at: number;
  device_count: number;
  artifact_count: number;
  hit_count: number;
  report_count: number;
};

export type CaseDevice = {
  device_id: string;
  case_id: string;
  os_type: string;
  device_name?: string;
  identifier?: string;
  connection_type: string;
  authorized: boolean;
  auth_note?: string;
  first_seen_at: number;
  last_seen_at: number;
};

export type HitDetail = {
  hit_id: string;
  case_id: string;
  device_id: string;
  hit_type: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  matched_value: string;
  first_seen_at: number;
  last_seen_at: number;
  confidence: number; // 0~1
  verdict: string;
  detail_json?: string;
  artifact_ids?: string[];
};

export type ArtifactInfo = {
  artifact_id: string;
  case_id: string;
  device_id: string;
  artifact_type: string;
  source_ref?: string;
  snapshot_path: string;
  sha256: string;
  size_bytes: number;
  collected_at: number;
  collector_name?: string;
  collector_version?: string;
  acquisition_method?: string;
};

export type ArtifactResponse = {
  artifact: ArtifactInfo;
  content?: string;
  content_length?: number;
};

export type PrecheckResult = {
  check_id?: string;
  case_id: string;
  device_id?: string;
  scan_scope: string;
  check_code: string;
  check_name: string;
  required: boolean;
  status: "passed" | "failed" | "skipped";
  message?: string;
  detail_json?: any;
  checked_at: number;
  record_hash?: string;
};

export type AuditLog = {
  event_id: string;
  case_id: string;
  device_id?: string;
  event_type: string;
  action: string;
  status: string;
  actor?: string;
  source?: string;
  detail_json?: any;
  occurred_at: number;
  chain_prev_hash?: string;
  chain_hash: string;
};

export type ReportInfo = {
  report_id: string;
  case_id: string;
  report_type: string;
  file_path: string;
  sha256: string;
  generated_at: number;
  generator_version: string;
  status: string;
};

export type ReportContentResponse = {
  report: ReportInfo | null;
  content?: string;
  content_length?: number;
  // 后端对 ZIP/PDF 这类二进制报告不会内联 content（只允许 download）。
  content_available?: boolean;
  content_omitted_reason?: string;
};

export type ScanAllJob = {
  job_id: string;
  kind: string;
  status: "running" | "success" | "failed";
  created_at: number;
  started_at: number;
  finished_at: number;
  stage?: string;
  progress?: number;
  logs?: { time: number; message: string }[];
  case_id?: string;
  host?: {
    case_id: string;
    device_id: string;
    device_name: string;
    device_os: string;
    artifact_count: number;
    hit_count: number;
    wallet_hits: number;
    exchange_hits: number;
    warnings?: string[];
    report_id?: string;
    report_path?: string;
    started_at: number;
    finished_at: number;
  };
  host_error?: string;
  mobile?: {
    case_id: string;
    device_count: number;
    android_count: number;
    ios_count: number;
    artifact_count: number;
    hit_count: number;
    wallet_hits: number;
    warnings?: string[];
    report_id?: string;
    report_path?: string;
    started_at: number;
    finished_at: number;
  };
  mobile_error?: string;
  error?: string;
};

// 链上余额查询（当前仅 EVM 原生币余额）
export type ChainEVMBalancesResponse = {
  ok: boolean;
  chain: "evm";
  rpc_url: string;
  symbol: string;
  balances: Record<string, Record<string, string>>; // address -> { WEI, ETH, ... }
  warnings?: string[];
  addr_count: number;
};
