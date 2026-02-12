import type {
  ArtifactResponse,
  CaseDevice,
  CaseOverview,
  CaseSummary,
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

