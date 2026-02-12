import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { CaseOverview, CaseSummary, MetaResponse, ScanAllJob } from "../api/types";

type AppContextValue = {
  meta: MetaResponse | null;
  cases: CaseSummary[];
  selectedCaseId: string;
  selectedCaseOverview: CaseOverview | null;
  operator: string;

  currentJob: ScanAllJob | null;
  error: string | null;

  refreshMeta: () => Promise<void>;
  refreshCases: () => Promise<void>;
  selectCase: (caseId: string) => void;
  setOperator: (operator: string) => void;

  createCase: (payload: {
    case_no?: string;
    title?: string;
    note?: string;
  }) => Promise<string>;
  updateCase: (payload: {
    case_id: string;
    case_no?: string;
    title?: string;
    note?: string;
  }) => Promise<void>;

  startScanAll: (payload: {
    note?: string;
    profile?: "internal" | "external";
    auth_order?: string;
    auth_basis?: string;
    ios_full_backup?: boolean;
    enable_host?: boolean;
    enable_android?: boolean;
    enable_ios?: boolean;
  }) => Promise<void>;
};

const AppContext = createContext<AppContextValue | null>(null);

const LS_OPERATOR = "crypto_inspector.operator";
const LS_SELECTED_CASE = "crypto_inspector.selected_case_id";

export function AppProvider(props: { children: React.ReactNode }) {
  const [meta, setMeta] = useState<MetaResponse | null>(null);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(
    localStorage.getItem(LS_SELECTED_CASE) || ""
  );
  const [selectedCaseOverview, setSelectedCaseOverview] =
    useState<CaseOverview | null>(null);
  const [operator, _setOperator] = useState<string>(
    localStorage.getItem(LS_OPERATOR) || "system"
  );

  const [currentJob, setCurrentJob] = useState<ScanAllJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollTimerRef = useRef<number | null>(null);

  const refreshMeta = async () => {
    try {
      const m = await api.getMeta();
      setMeta(m);
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  };

  const refreshCases = async () => {
    try {
      const res = await api.listCases(200, 0);
      setCases(res.cases || []);
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  };

  const selectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    localStorage.setItem(LS_SELECTED_CASE, caseId);
  };

  const setOperator = (v: string) => {
    const next = (v || "").trim() || "system";
    _setOperator(next);
    localStorage.setItem(LS_OPERATOR, next);
  };

  const createCase = async (payload: {
    case_no?: string;
    title?: string;
    note?: string;
  }) => {
    setError(null);
    const res = await api.createOrUpdateCase({
      case_no: payload.case_no,
      title: payload.title,
      operator,
      note: payload.note,
    });
    await refreshCases();
    selectCase(res.case_id);
    return res.case_id;
  };

  const updateCase = async (payload: {
    case_id: string;
    case_no?: string;
    title?: string;
    note?: string;
  }) => {
    setError(null);
    await api.createOrUpdateCase({
      case_id: payload.case_id,
      case_no: payload.case_no,
      title: payload.title,
      operator,
      note: payload.note,
    });
    await refreshCases();
  };

  const stopPolling = () => {
    if (pollTimerRef.current != null) {
      window.clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const startPollingJob = (jobId: string) => {
    stopPolling();
    pollTimerRef.current = window.setInterval(async () => {
      try {
        const j = await api.getJob(jobId);
        setCurrentJob(j);
        if (j.status !== "running") {
          stopPolling();
          // job 结束后刷新 case 列表与 overview，保证页面数据是新的
          await refreshCases();
          if (j.case_id) {
            selectCase(j.case_id);
          }
        }
      } catch (e: any) {
        setError(e?.message || String(e));
      }
    }, 800);
  };

  const startScanAll = async (payload: {
    note?: string;
    profile?: "internal" | "external";
    auth_order?: string;
    auth_basis?: string;
    ios_full_backup?: boolean;
    enable_host?: boolean;
    enable_android?: boolean;
    enable_ios?: boolean;
  }) => {
    setError(null);

    // enable_mobile 由 Android/iOS 勾选推导：两者都关就认为不跑 mobile
    const enable_android = payload.enable_android ?? true;
    const enable_ios = payload.enable_ios ?? true;
    const enable_mobile = enable_android || enable_ios;

    const job = await api.startScanAll({
      operator,
      note: payload.note,
      profile: payload.profile || "internal",
      case_id: selectedCaseId || undefined,
      auth_order: payload.auth_order,
      auth_basis: payload.auth_basis,
      ios_full_backup: payload.ios_full_backup ?? true,
      enable_host: payload.enable_host ?? true,
      enable_mobile,
      enable_android,
      enable_ios,
      privacy_mode: "off",
    });

    setCurrentJob(job);
    if (job.job_id) {
      startPollingJob(job.job_id);
    }
  };

  // 初始化：拉取 meta + cases
  useEffect(() => {
    refreshMeta();
    refreshCases();
    return () => stopPolling();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 当 case 切换时，拉取 overview
  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setSelectedCaseOverview(null);
        return;
      }
      try {
        const ov = await api.getCaseOverview(selectedCaseId);
        setSelectedCaseOverview(ov);
      } catch (e: any) {
        setError(e?.message || String(e));
      }
    })();
  }, [selectedCaseId]);

  // cases 列表更新后，若当前没有选中 case，则默认选第一个
  useEffect(() => {
    if (selectedCaseId) return;
    if (cases.length > 0) {
      selectCase(cases[0].case_id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cases]);

  const value: AppContextValue = useMemo(
    () => ({
      meta,
      cases,
      selectedCaseId,
      selectedCaseOverview,
      operator,
      currentJob,
      error,
      refreshMeta,
      refreshCases,
      selectCase,
      setOperator,
      createCase,
      updateCase,
      startScanAll,
    }),
    [meta, cases, selectedCaseId, selectedCaseOverview, operator, currentJob, error]
  );

  return <AppContext.Provider value={value}>{props.children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) {
    throw new Error("useApp must be used within AppProvider");
  }
  return ctx;
}

