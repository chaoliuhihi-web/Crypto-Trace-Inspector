import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, File } from "lucide-react";
import { api } from "../api/client";
import type { ArtifactInfo, CaseDevice } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

function formatBytes(bytes: number) {
  const b = bytes || 0;
  if (b < 1024) return `${b} B`;
  const kb = b / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  const gb = mb / 1024;
  return `${gb.toFixed(1)} GB`;
}

export default function EvidenceManagement() {
  const { selectedCaseId } = useApp();
  const [devices, setDevices] = useState<CaseDevice[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactInfo[]>([]);
  const [expandedDevices, setExpandedDevices] = useState<string[]>([]);
  const [selectedArtifactId, setSelectedArtifactId] = useState<string>("");
  const [viewMode, setViewMode] = useState<"json" | "table">("json");
  const [content, setContent] = useState<string>("");
  const [contentLoading, setContentLoading] = useState(false);

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setDevices([]);
        setArtifacts([]);
        setExpandedDevices([]);
        setSelectedArtifactId("");
        setContent("");
        return;
      }
      try {
        const [d, a] = await Promise.all([
          api.listCaseDevices(selectedCaseId),
          api.listCaseArtifacts(selectedCaseId),
        ]);
        const devs = d.devices || [];
        const arts = a.artifacts || [];
        setDevices(devs);
        setArtifacts(arts);
        setExpandedDevices(devs.map((x) => x.device_id));
        if (arts.length > 0) {
          setSelectedArtifactId(arts[0].artifact_id);
        } else {
          setSelectedArtifactId("");
        }
      } catch {
        setDevices([]);
        setArtifacts([]);
        setExpandedDevices([]);
        setSelectedArtifactId("");
        setContent("");
      }
    })();
  }, [selectedCaseId]);

  const artifactsByDevice = useMemo(() => {
    const m = new Map<string, ArtifactInfo[]>();
    for (const a of artifacts) {
      const list = m.get(a.device_id) || [];
      list.push(a);
      m.set(a.device_id, list);
    }
    // 保持时间倒序（后端已按 collected_at DESC 排了）
    return m;
  }, [artifacts]);

  const selectedArtifact = useMemo(() => {
    return artifacts.find((a) => a.artifact_id === selectedArtifactId) || null;
  }, [artifacts, selectedArtifactId]);

  const deviceNameByID = useMemo(() => {
    const m = new Map<string, string>();
    for (const d of devices) {
      m.set(d.device_id, d.device_name || d.identifier || d.os_type);
    }
    return m;
  }, [devices]);

  const toggleDevice = (deviceId: string) => {
    setExpandedDevices((prev) =>
      prev.includes(deviceId) ? prev.filter((x) => x !== deviceId) : [...prev, deviceId]
    );
  };

  const loadContent = async (artifactId: string) => {
    setContentLoading(true);
    try {
      const res = await api.getArtifact(artifactId, true);
      setContent(res.content || "");
    } catch (e: any) {
      setContent(`ERROR: ${e?.message || String(e)}`);
    } finally {
      setContentLoading(false);
    }
  };

  useEffect(() => {
    if (!selectedArtifactId) {
      setContent("");
      return;
    }
    // 选中项变化时自动加载内容（JSON 通常不大；若后续大文件再改成“点击加载”）
    loadContent(selectedArtifactId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedArtifactId]);

  const parsed = useMemo(() => {
    try {
      return content ? JSON.parse(content) : null;
    } catch {
      return null;
    }
  }, [content]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        06 证据管理
      </h2>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* 左侧：证据分类树（按设备） */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            证据分类树
          </h3>

          <div className="space-y-1">
            {devices.length === 0 ? (
              <div className="text-xs text-[#7a7f8a]">暂无设备（请先采集）</div>
            ) : (
              devices.map((d) => {
                const expanded = expandedDevices.includes(d.device_id);
                const items = artifactsByDevice.get(d.device_id) || [];
                return (
                  <div key={d.device_id}>
                    <div
                      onClick={() => toggleDevice(d.device_id)}
                      className="flex items-center gap-1 py-1.5 px-2 hover:bg-[#252931] cursor-pointer rounded"
                    >
                      {expanded ? (
                        <ChevronDown className="w-3.5 h-3.5 text-[#b8bcc4]" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5 text-[#b8bcc4]" />
                      )}
                      <span className="text-xs font-bold text-[#e8e8e8]">
                        {d.device_name || d.os_type}
                      </span>
                      <span className="text-[10px] text-[#7a7f8a] ml-auto">
                        {items.length} 项
                      </span>
                    </div>

                    {expanded ? (
                      <div className="ml-5 space-y-0.5">
                        {items.length === 0 ? (
                          <div className="text-[10px] text-[#7a7f8a] px-2 py-1">无证据</div>
                        ) : (
                          items.map((a) => (
                            <div
                              key={a.artifact_id}
                              onClick={() => setSelectedArtifactId(a.artifact_id)}
                              className={`flex items-center gap-2 py-1.5 px-2 cursor-pointer rounded ${
                                selectedArtifactId === a.artifact_id
                                  ? "bg-[#2b5278] text-[#4fc3f7]"
                                  : "hover:bg-[#252931] text-[#b8bcc4]"
                              }`}
                            >
                              <File className="w-3.5 h-3.5 flex-shrink-0" />
                              <span className="text-xs">
                                {a.artifact_type}
                                {a.source_ref ? ` (${a.source_ref})` : ""}
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    ) : null}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* 右侧：证据元信息 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            证据列表
          </h3>

          {!selectedArtifact ? (
            <div className="text-xs text-[#7a7f8a]">请选择一条证据</div>
          ) : (
            <>
              <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 space-y-2 mb-4">
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">设备：</label>
                  <span className="text-[#e8e8e8] text-xs">
                    {deviceNameByID.get(selectedArtifact.device_id) || selectedArtifact.device_id}
                  </span>
                </div>
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">类型：</label>
                  <span className="text-[#e8e8e8] text-xs">{selectedArtifact.artifact_type}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">来源：</label>
                  <span className="text-[#e8e8e8] text-xs">{selectedArtifact.source_ref || "-"}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">SHA256：</label>
                  <span className="text-[#4fc3f7] text-xs font-mono break-all">{selectedArtifact.sha256}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">大小：</label>
                  <span className="text-[#e8e8e8] text-xs">{formatBytes(selectedArtifact.size_bytes)}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-24 text-[#b8bcc4] text-xs">采集时间：</label>
                  <span className="text-[#4fc3f7] text-xs">{formatTime(selectedArtifact.collected_at)}</span>
                </div>
              </div>

              <div className="flex gap-2">
                <a
                  className="flex-1 text-center bg-[#2b5278] hover:bg-[#365f8a] border border-[#4fc3f7] text-[#4fc3f7] px-4 py-2 text-xs rounded transition-colors"
                  href={`/api/artifacts/${selectedArtifact.artifact_id}/download`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <span className="inline-flex items-center gap-1">
                    <Download className="w-4 h-4" />
                    下载快照
                  </span>
                </a>
                <button
                  onClick={() => loadContent(selectedArtifact.artifact_id)}
                  className="flex-1 bg-[#1e2127] hover:bg-[#252931] border border-[#5a5f6a] text-[#b8bcc4] px-4 py-2 text-xs rounded transition-colors"
                >
                  {contentLoading ? "加载中..." : "刷新内容"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* 证据详情 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
        <div className="flex items-center justify-between mb-4 border-b border-[#3a3f4a] pb-2">
          <h3 className="text-sm font-bold text-[#4fc3f7]">证据详情（JSON 预览）</h3>
          <div className="flex gap-2">
            <button
              onClick={() => setViewMode("json")}
              className={`px-3 py-1 text-xs rounded transition-colors ${
                viewMode === "json"
                  ? "bg-[#2b5278] border border-[#4fc3f7] text-[#4fc3f7]"
                  : "bg-[#252931] border border-[#5a5f6a] text-[#b8bcc4]"
              }`}
            >
              JSON
            </button>
            <button
              onClick={() => setViewMode("table")}
              className={`px-3 py-1 text-xs rounded transition-colors ${
                viewMode === "table"
                  ? "bg-[#2b5278] border border-[#4fc3f7] text-[#4fc3f7]"
                  : "bg-[#252931] border border-[#5a5f6a] text-[#b8bcc4]"
              }`}
            >
              表格
            </button>
          </div>
        </div>

        <div className="bg-[#0d0f12] border border-[#3a3f4a] rounded p-3 overflow-x-auto">
          {viewMode === "json" ? (
            <pre className="text-[10px] text-[#e8e8e8] font-mono leading-relaxed">
              {content || "(empty)"}
            </pre>
          ) : (
            <div className="text-xs text-[#b8bcc4]">
              {parsed ? (
                <pre className="text-[10px] text-[#e8e8e8] font-mono leading-relaxed">
                  {JSON.stringify(parsed, null, 2)}
                </pre>
              ) : (
                <div>无法解析为 JSON（可能是非 JSON 内容或为空）</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

