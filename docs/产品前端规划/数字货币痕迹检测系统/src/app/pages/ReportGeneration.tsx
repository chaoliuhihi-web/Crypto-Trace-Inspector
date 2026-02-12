import { useEffect, useMemo, useState } from "react";
import { Download, FileText } from "lucide-react";
import { api } from "../api/client";
import type { ReportInfo } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

export default function ReportGeneration() {
  const { selectedCaseId } = useApp();
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string>("");
  const [content, setContent] = useState<string>("");

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setReports([]);
        setSelectedReportId("");
        setContent("");
        return;
      }
      try {
        const res = await api.listCaseReports(selectedCaseId);
        const rows = res.reports || [];
        setReports(rows);
        if (rows.length > 0) {
          setSelectedReportId(rows[0].report_id);
        } else {
          setSelectedReportId("");
          setContent("");
        }
      } catch {
        setReports([]);
        setSelectedReportId("");
        setContent("");
      }
    })();
  }, [selectedCaseId]);

  const selectedReport = useMemo(() => {
    return reports.find((r) => r.report_id === selectedReportId) || null;
  }, [reports, selectedReportId]);

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) return;
      if (!selectedReportId) {
        setContent("");
        return;
      }
      try {
        const res = await api.getCaseReportContent(selectedCaseId, selectedReportId);
        const raw = res.content || "";
        // 报告目前是 internal_json，尽量格式化展示
        try {
          const parsed = JSON.parse(raw);
          setContent(JSON.stringify(parsed, null, 2));
        } catch {
          setContent(raw);
        }
      } catch (e: any) {
        setContent(`ERROR: ${e?.message || String(e)}`);
      }
    })();
  }, [selectedCaseId, selectedReportId]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        07 报告生成
      </h2>

      {/* 报告生成 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">报告生成</h3>

        <div className="text-xs text-[#7a7f8a]">
          当前版本报告在采集任务结束时自动生成（internal_json）。如需重生成，请回到“数据采集”重新执行。
        </div>
      </div>

      {/* 历史报告 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">历史报告</h3>

        <div className="bg-[#252931] border border-[#3a3f4a] rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[#1e2127] border-b border-[#3a3f4a]">
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">报告ID</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">生成时间</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">SHA256</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">类型</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">操作</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-3 px-3 text-[#7a7f8a]">
                    暂无报告（请先执行采集）
                  </td>
                </tr>
              ) : (
                reports.map((report) => (
                  <tr
                    key={report.report_id}
                    className={`border-b border-[#3a3f4a] cursor-pointer ${
                      selectedReportId === report.report_id ? "bg-[#2b5278]" : "hover:bg-[#1e2127]"
                    }`}
                    onClick={() => setSelectedReportId(report.report_id)}
                  >
                    <td className="py-2 px-3">
                      <span className="text-[#4fc3f7] font-mono">{report.report_id}</span>
                    </td>
                    <td className="py-2 px-3 text-[#e8e8e8]">{formatTime(report.generated_at)}</td>
                    <td className="py-2 px-3 text-[#b8bcc4] font-mono break-all">{report.sha256}</td>
                    <td className="py-2 px-3 text-[#b8bcc4]">{report.report_type}</td>
                    <td className="py-2 px-3">
                      <a
                        className="flex items-center gap-1 text-[#4fc3f7] hover:text-[#6dd5ff]"
                        href={`/api/reports/${report.report_id}/download`}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>下载</span>
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 报告预览 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
        <div className="flex items-center justify-between mb-4 border-b border-[#3a3f4a] pb-2">
          <h3 className="text-sm font-bold text-[#4fc3f7]">报告预览（只读）</h3>
          <div className="flex items-center gap-2 text-xs text-[#b8bcc4]">
            <FileText className="w-4 h-4" />
            <span>{selectedReport?.report_id || "-"}</span>
          </div>
        </div>

        <div className="bg-[#0d0f12] border border-[#3a3f4a] rounded p-3 overflow-x-auto max-h-96">
          <pre className="text-[10px] text-[#e8e8e8] font-mono leading-relaxed">
            {content || "(empty)"}
          </pre>
        </div>
      </div>
    </div>
  );
}

