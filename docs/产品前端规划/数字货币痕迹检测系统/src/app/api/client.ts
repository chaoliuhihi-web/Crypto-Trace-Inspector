import type {
  ArtifactResponse,
  CaseDevice,
  CaseOverview,
  CaseSummary,
  ChainEVMBalancesResponse,
  MetaResponse,
  PrecheckResult,
  HitDetail,
  AuditLog,
  ArtifactInfo,
  ReportContentResponse,
  ReportInfo,
  ScanAllJob,
} from "./types";

type ApiErrorBody = { error?: string };

async function requestJSON<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  // 约定：后端出错时返回 {error:"..."}，成功返回业务 JSON。
  const text = await res.text();
  const data = text ? (JSON.parse(text) as any) : ({} as any);
  if (!res.ok) {
    const msg =
      (data as ApiErrorBody)?.error ||
      `HTTP ${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data as T;
}

export const api = {
  getMeta: () => requestJSON<MetaResponse>("/api/meta"),

  listCases: (limit = 50, offset = 0) =>
    requestJSON<{ cases: CaseSummary[] }>(
      `/api/cases?limit=${limit}&offset=${offset}`
    ),

  createOrUpdateCase: (payload: {
    case_id?: string;
    case_no?: string;
    title?: string;
    operator?: string;
    note?: string;
  }) =>
    requestJSON<{ case_id: string; overview: CaseOverview | null }>(
      "/api/cases",
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),

  getCaseOverview: (caseId: string) =>
    requestJSON<CaseOverview>(`/api/cases/${caseId}/overview`),

  listCaseDevices: (caseId: string) =>
    requestJSON<{ devices: CaseDevice[] }>(`/api/cases/${caseId}/devices`),

  listCaseHits: (caseId: string, hitType?: string) => {
    const q = hitType ? `?hit_type=${encodeURIComponent(hitType)}` : "";
    return requestJSON<{ hits: HitDetail[] }>(`/api/cases/${caseId}/hits${q}`);
  },

  listCaseArtifacts: (caseId: string) =>
    requestJSON<{ artifacts: ArtifactInfo[] }>(`/api/cases/${caseId}/artifacts`),

  getArtifact: (artifactId: string, includeContent = false) => {
    const q = includeContent ? "?content=true" : "";
    return requestJSON<ArtifactResponse>(`/api/artifacts/${artifactId}${q}`);
  },

  listCasePrechecks: (caseId: string) =>
    requestJSON<{ prechecks: PrecheckResult[] }>(
      `/api/cases/${caseId}/prechecks`
    ),

  listCaseAudits: (caseId: string, limit = 500) =>
    requestJSON<{ audits: AuditLog[] }>(
      `/api/cases/${caseId}/audits?limit=${limit}`
    ),

  listCaseReports: (caseId: string) =>
    requestJSON<{ reports: ReportInfo[] }>(`/api/cases/${caseId}/reports`),

  getCaseReportContent: (caseId: string, reportId?: string) => {
    const q = reportId
      ? `?report_id=${encodeURIComponent(reportId)}&content=true`
      : "?content=true";
    return requestJSON<ReportContentResponse>(`/api/cases/${caseId}/report${q}`);
  },

  // 司法导出包（ZIP + manifest + hashes.sha256）
  generateForensicZip: (
    caseId: string,
    payload?: { operator?: string; note?: string }
  ) =>
    requestJSON<{
      ok: boolean;
      case_id: string;
      report_id: string;
      zip_path: string;
      zip_sha256: string;
      warnings?: string[];
      report: ReportInfo | null;
    }>(`/api/cases/${caseId}/exports/forensic-zip`, {
      method: "POST",
      body: JSON.stringify(payload ?? {}),
    }),

  // 取证 PDF 报告（forensic_pdf）
  generateForensicPdf: (
    caseId: string,
    payload?: { operator?: string; note?: string }
  ) =>
    requestJSON<{
      ok: boolean;
      case_id: string;
      report_id: string;
      pdf_path: string;
      pdf_sha256: string;
      warnings?: string[];
      report: ReportInfo | null;
    }>(`/api/cases/${caseId}/exports/forensic-pdf`, {
      method: "POST",
      body: JSON.stringify(payload ?? {}),
    }),

  // 链上余额查询（EVM 原生币余额，eth_getBalance）
  queryEVMBalances: (payload: {
    rpc_url?: string;
    symbol?: string;
    addresses: string[];
  }) =>
    requestJSON<ChainEVMBalancesResponse>("/api/chain/evm/balances", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  startScanAll: (payload: {
    operator?: string;
    note?: string;
    profile?: "internal" | "external";
    case_id?: string;
    auth_order?: string;
    auth_basis?: string;
    privacy_mode?: "off" | "masked";
    ios_full_backup?: boolean;
    enable_host?: boolean;
    enable_mobile?: boolean;
    enable_android?: boolean;
    enable_ios?: boolean;
  }) =>
    requestJSON<ScanAllJob>("/api/jobs/scan-all", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getJob: (jobId: string) => requestJSON<ScanAllJob>(`/api/jobs/${jobId}`),
};
