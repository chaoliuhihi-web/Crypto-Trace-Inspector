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
  const { selectedCaseId, operator } = useApp();
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string>("");
  const [content, setContent] = useState<string>("");
  const [contentType, setContentType] = useState<"text" | "html">("text");
  const [exportingZip, setExportingZip] = useState(false);
  const [exportZipMsg, setExportZipMsg] = useState<string>("");
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportPdfMsg, setExportPdfMsg] = useState<string>("");

  const loadReports = async (caseId: string) => {
    const res = await api.listCaseReports(caseId);
    const rows = res.reports || [];
    setReports(rows);
    if (rows.length > 0) {
      setSelectedReportId(rows[0].report_id);
    } else {
      setSelectedReportId("");
      setContent("");
    }
  };

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setReports([]);
        setSelectedReportId("");
        setContent("");
        return;
      }
      try {
        await loadReports(selectedCaseId);
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
        const reportType = res?.report?.report_type || "";
        const raw = res.content || "";
        if (!raw) {
          if (res.content_available === false) {
            setContentType("text");
            setContent(
              `(该报告为二进制产物：${reportType || "-"}，不支持内联预览。请点击“下载”获取文件。)`
            );
          } else {
            setContentType("text");
            setContent("");
          }
          return;
        }
        if (reportType === "internal_html") {
          setContentType("html");
          setContent(raw);
          return;
        }
        setContentType("text");
        // internal_json：尽量格式化展示（其他文本类型则原样输出）
        try {
          const parsed = JSON.parse(raw);
          setContent(JSON.stringify(parsed, null, 2));
        } catch {
          setContent(raw);
        }
      } catch (e: any) {
        setContentType("text");
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
          当前版本报告在采集任务结束时自动生成（internal_json + internal_html）。如需重生成，请回到“数据采集”重新执行。
        </div>
      </div>

      {/* 司法导出包 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">司法导出包（ZIP）</h3>

        <div className="text-xs text-[#7a7f8a] mb-3">
          生成内容：manifest.json + hashes.sha256 + evidence/（证据快照）+ reports/（报告产物）+ rules/（规则文件）。
        </div>

        <div className="flex items-center gap-3">
          <button
            disabled={!selectedCaseId || exportingZip}
            onClick={async () => {
              if (!selectedCaseId) return;
              setExportZipMsg("");
              setExportingZip(true);
              try {
                await api.generateForensicZip(selectedCaseId, {
                  operator,
                  note: "ui_generate_forensic_zip",
                });
                await loadReports(selectedCaseId);
                setExportZipMsg("已生成（请在“历史报告”列表中下载 forensic_zip）");
              } catch (e: any) {
                setExportZipMsg(`ERROR: ${e?.message || String(e)}`);
              } finally {
                setExportingZip(false);
              }
            }}
            className="bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-6 py-2 text-xs rounded transition-colors"
          >
            [{exportingZip ? "生成中..." : "生成司法导出包（ZIP）"}]
          </button>
          {exportZipMsg ? (
            <div className="text-xs text-[#b8bcc4]">
              {exportZipMsg.startsWith("ERROR") ? (
                <span className="text-[#ff6b6b]">{exportZipMsg}</span>
              ) : (
                <span className="text-green-500">{exportZipMsg}</span>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* 取证 PDF */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">取证 PDF 报告</h3>

        <div className="text-xs text-[#7a7f8a] mb-3">
          生成内容：案件摘要 + 设备清单 + 前置条件检查 + 命中列表 + 证据列表（Top N）。PDF 为二进制产物，生成后请在“历史报告”里下载。
        </div>

        <div className="flex items-center gap-3">
          <button
            disabled={!selectedCaseId || exportingPdf}
            onClick={async () => {
              if (!selectedCaseId) return;
              setExportPdfMsg("");
              setExportingPdf(true);
              try {
                await api.generateForensicPdf(selectedCaseId, {
                  operator,
                  note: "ui_generate_forensic_pdf",
                });
                await loadReports(selectedCaseId);
                setExportPdfMsg("已生成（请在“历史报告”列表中下载 forensic_pdf）");
              } catch (e: any) {
                setExportPdfMsg(`ERROR: ${e?.message || String(e)}`);
              } finally {
                setExportingPdf(false);
              }
            }}
            className="bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-6 py-2 text-xs rounded transition-colors"
          >
            [{exportingPdf ? "生成中..." : "生成取证 PDF"}]
          </button>
          {exportPdfMsg ? (
            <div className="text-xs text-[#b8bcc4]">
              {exportPdfMsg.startsWith("ERROR") ? (
                <span className="text-[#ff6b6b]">{exportPdfMsg}</span>
              ) : (
                <span className="text-green-500">{exportPdfMsg}</span>
              )}
            </div>
          ) : null}
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

        {contentType === "html" ? (
          <div className="bg-[#0d0f12] border border-[#3a3f4a] rounded overflow-hidden">
            <iframe
              title="internal_html_preview"
              className="w-full h-96 bg-white"
              // sandbox 为空表示使用最严格限制：禁用脚本/表单/同源等
              sandbox=""
              srcDoc={content || ""}
            />
          </div>
        ) : (
          <div className="bg-[#0d0f12] border border-[#3a3f4a] rounded p-3 overflow-x-auto max-h-96">
            <pre className="text-[10px] text-[#e8e8e8] font-mono leading-relaxed">
              {content || "(empty)"}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
