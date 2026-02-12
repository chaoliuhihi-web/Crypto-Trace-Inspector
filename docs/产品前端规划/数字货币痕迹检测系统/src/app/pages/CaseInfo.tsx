import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { AuditLog } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

export default function CaseInfo() {
  const {
    selectedCaseId,
    selectedCaseOverview,
    operator,
    createCase,
    updateCase,
  } = useApp();

  const [caseNo, setCaseNo] = useState("");
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");
  const [audits, setAudits] = useState<AuditLog[]>([]);
  const [saving, setSaving] = useState(false);

  const statusLabel = useMemo(() => {
    const s = selectedCaseOverview?.status || "";
    if (!s) return "未知";
    if (s === "open") return "进行中";
    return s;
  }, [selectedCaseOverview?.status]);

  useEffect(() => {
    setCaseNo(selectedCaseOverview?.case_no || "");
    setTitle(selectedCaseOverview?.title || "");
    setNote(selectedCaseOverview?.note || "");
  }, [selectedCaseOverview?.case_id]);

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setAudits([]);
        return;
      }
      try {
        const res = await api.listCaseAudits(selectedCaseId, 50);
        setAudits(res.audits || []);
      } catch {
        // ignore：不阻断页面
      }
    })();
  }, [selectedCaseId]);

  const onCreateNew = async () => {
    setSaving(true);
    try {
      await createCase({
        case_no: caseNo,
        title,
        note,
      });
    } finally {
      setSaving(false);
    }
  };

  const onSave = async () => {
    if (!selectedCaseId) return;
    setSaving(true);
    try {
      await updateCase({
        case_id: selectedCaseId,
        case_no: caseNo,
        title,
        note,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        01 案件信息
      </h2>

      <div className="grid grid-cols-2 gap-6">
        {/* 左侧：案件基本信息 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            案件基本信息
          </h3>

          <div className="space-y-3">
            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">案件编号：</label>
              <input
                type="text"
                value={caseNo}
                onChange={(e) => setCaseNo(e.target.value)}
                placeholder="如：2026-01-001（可选）"
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7]"
              />
            </div>

            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">案件标题：</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="如：涉币资金流向排查"
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7]"
              />
            </div>

            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">创建时间：</label>
              <input
                type="text"
                value={formatTime(selectedCaseOverview?.created_at || 0)}
                disabled
                className="flex-1 bg-[#1a1d23] border border-[#3a3f4a] px-2 py-1 text-xs text-[#7a7f8a] rounded"
              />
            </div>

            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">操作员：</label>
              <input
                type="text"
                value={operator}
                disabled
                className="flex-1 bg-[#1a1d23] border border-[#3a3f4a] px-2 py-1 text-xs text-[#7a7f8a] rounded"
              />
            </div>

            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">案件状态：</label>
              <span className="text-[#ffa726] text-xs">{statusLabel}</span>
            </div>

            <div className="flex items-start">
              <label className="w-24 text-[#b8bcc4] text-xs pt-1">备注：</label>
              <textarea
                rows={4}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="请输入案件备注信息..."
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7] resize-none"
              />
            </div>
          </div>

          <div className="flex gap-2 mt-6 pt-4 border-t border-[#3a3f4a]">
            <button
              disabled={saving}
              onClick={onSave}
              className="bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-4 py-1.5 text-xs rounded transition-colors"
            >
              [保存当前案件]
            </button>
            <button
              disabled={saving}
              onClick={onCreateNew}
              className="bg-[#1e2127] hover:bg-[#252931] disabled:opacity-50 border border-[#5a5f6a] text-[#b8bcc4] px-4 py-1.5 text-xs rounded transition-colors"
            >
              [新建案件]
            </button>
          </div>
        </div>

        {/* 右侧：案件操作记录 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            案件操作记录（审计日志）
          </h3>

          <div className="space-y-2 max-h-[360px] overflow-y-auto pr-2">
            {audits.length === 0 ? (
              <div className="text-xs text-[#7a7f8a]">暂无记录</div>
            ) : (
              audits
                .slice()
                .reverse()
                .map((a) => (
                  <div key={a.event_id} className="flex items-center gap-3 text-xs">
                    <span className="text-[#ffa726] font-mono">
                      {new Date(a.occurred_at * 1000).toLocaleTimeString("zh-CN", {
                        hour12: false,
                      })}
                    </span>
                    <span className="text-[#b8bcc4]">
                      {a.event_type}/{a.action} ({a.status})
                    </span>
                  </div>
                ))
            )}
          </div>

          <div className="mt-4 pt-4 border-t border-[#3a3f4a] text-xs text-[#7a7f8a]">
            * 审计记录不可删除（链式 hash 留痕）
          </div>
        </div>
      </div>
    </div>
  );
}
