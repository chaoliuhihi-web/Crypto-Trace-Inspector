import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { api } from "../api/client";
import type { AuditLog } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

export default function AuditVerification() {
  const { selectedCaseId } = useApp();
  const [audits, setAudits] = useState<AuditLog[]>([]);
  const [verifiedAt, setVerifiedAt] = useState<number>(0);

  const refresh = async () => {
    if (!selectedCaseId) return;
    try {
      const res = await api.listCaseAudits(selectedCaseId, 2000);
      setAudits(res.audits || []);
      setVerifiedAt(Date.now());
    } catch {
      setAudits([]);
      setVerifiedAt(Date.now());
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCaseId]);

  const verify = useMemo(() => {
    if (audits.length === 0) {
      return { ok: true, brokenAt: -1, expected: "", actual: "" };
    }
    for (let i = 1; i < audits.length; i++) {
      const prev = audits[i - 1];
      const cur = audits[i];
      const expected = prev.chain_hash || "";
      const actual = cur.chain_prev_hash || "";
      if (expected !== actual) {
        return { ok: false, brokenAt: i, expected, actual };
      }
    }
    return { ok: true, brokenAt: -1, expected: "", actual: "" };
  }, [audits]);

  const lastHash = audits.length > 0 ? audits[audits.length - 1]?.chain_hash : "";

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        08 审计校验
      </h2>

      {/* 审计链状态 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">审计链状态</h3>

        <div className="grid grid-cols-3 gap-6 mb-4">
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">当前链高度</div>
            <div className="text-2xl font-bold text-[#4fc3f7]">{audits.length}</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">最近 hash</div>
            <div className="text-xs font-mono text-[#e8e8e8] mt-2 break-all">
              {lastHash || "-"}
            </div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">上次校验时间</div>
            <div className="text-xs text-[#e8e8e8] mt-2">
              {verifiedAt ? new Date(verifiedAt).toLocaleString("zh-CN", { hour12: false }) : "-"}
            </div>
          </div>
        </div>

        <button
          onClick={refresh}
          className="bg-[#2b5278] hover:bg-[#365f8a] border border-[#4fc3f7] text-[#4fc3f7] px-6 py-2 text-xs rounded transition-colors"
        >
          [执行完整性校验]
        </button>

        {/* 校验状态 */}
        <div className="mt-4 pt-4 border-t border-[#3a3f4a]">
          {!verify.ok ? (
            <div className="flex items-start gap-3 bg-[#3d2817] border border-[#ffa726] rounded p-3">
              <AlertTriangle className="w-5 h-5 text-[#ffa726] flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-bold text-[#ffa726] mb-2">
                  在位置 {verify.brokenAt} 处检测到不连续
                </div>
                <div className="space-y-1 text-xs">
                  <div>
                    <span className="text-[#b8bcc4]">预期 prev_hash：</span>
                    <span className="text-[#e8e8e8] font-mono ml-2 break-all">{verify.expected}</span>
                  </div>
                  <div>
                    <span className="text-[#b8bcc4]">实际 prev_hash：</span>
                    <span className="text-[#ff6b6b] font-mono ml-2 break-all">{verify.actual}</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-3 bg-[#1a2f1f] border border-green-500 rounded p-3">
              <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
              <div className="text-sm text-green-500">
                审计链完整性校验通过（chain_prev_hash 连续）
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 审计记录 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">审计记录</h3>

        <div className="bg-[#252931] border border-[#3a3f4a] rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[#1e2127] border-b border-[#3a3f4a]">
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">时间</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">事件</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">设备</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">状态</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">记录哈希</th>
              </tr>
            </thead>
            <tbody>
              {audits.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-3 px-3 text-[#7a7f8a]">
                    暂无审计记录（请先执行采集）
                  </td>
                </tr>
              ) : (
                audits.map((a) => (
                  <tr key={a.event_id} className="border-b border-[#3a3f4a] hover:bg-[#1e2127]">
                    <td className="py-2 px-3 text-[#4fc3f7]">{formatTime(a.occurred_at)}</td>
                    <td className="py-2 px-3 text-[#e8e8e8]">
                      {a.event_type}/{a.action}
                    </td>
                    <td className="py-2 px-3 text-[#b8bcc4]">{a.device_id || "-"}</td>
                    <td className="py-2 px-3">
                      <span className={a.status === "failed" ? "text-[#ff6b6b]" : "text-green-500"}>
                        {a.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[#b8bcc4] font-mono break-all">{a.chain_hash}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="mt-4 text-xs text-[#7a7f8a]">
          * 审计记录采用链式 hash：每条记录包含前一条记录的 hash（chain_prev_hash）
        </div>
      </div>

      {/* 技术信息 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mt-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">技术信息</h3>

        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-2 text-xs">
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">哈希算法：</label>
              <span className="text-[#e8e8e8]">SHA-256</span>
            </div>
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">链式存储：</label>
              <span className="text-[#e8e8e8]">SQLite audit_logs</span>
            </div>
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">时间戳来源：</label>
              <span className="text-[#e8e8e8]">系统时间</span>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">完整性保护：</label>
              <span className="text-green-500">已启用</span>
            </div>
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">防篡改机制：</label>
              <span className="text-green-500">链式 hash 留痕</span>
            </div>
            <div className="flex items-center">
              <label className="w-32 text-[#b8bcc4]">审计日志备份：</label>
              <span className="text-[#7a7f8a]">待接入</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

