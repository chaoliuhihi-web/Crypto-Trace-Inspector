import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { CaseDevice, HitDetail } from "../api/types";
import { useApp } from "../state/AppContext";

function toPercent(conf: number) {
  const v = Math.round((conf || 0) * 100);
  return Number.isFinite(v) ? v : 0;
}

function confidenceLabel(conf: number) {
  const p = toPercent(conf);
  if (p >= 85) return `高(${p}%)`;
  if (p >= 60) return `中(${p}%)`;
  return `低(${p}%)`;
}

function typeLabel(hitType: string) {
  switch (hitType) {
    case "wallet_installed":
      return "钱包";
    case "exchange_visited":
      return "交易所";
    default:
      return hitType || "-";
  }
}

function riskLevel(h: HitDetail): "high" | "medium" | "low" {
  const p = toPercent(h.confidence);
  if (h.hit_type === "wallet_installed" && p >= 70) return "high";
  if (h.hit_type === "exchange_visited" && p >= 70) return "medium";
  if (p >= 70) return "medium";
  return "low";
}

function parseDetail(detail?: string): any {
  if (!detail) return null;
  try {
    return JSON.parse(detail);
  } catch {
    return null;
  }
}

export default function HitAnalysis() {
  const { selectedCaseId } = useApp();
  const [hits, setHits] = useState<HitDetail[]>([]);
  const [devices, setDevices] = useState<CaseDevice[]>([]);
  const [selectedHitId, setSelectedHitId] = useState<string>("");

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setHits([]);
        setDevices([]);
        setSelectedHitId("");
        return;
      }
      try {
        const [h, d] = await Promise.all([
          api.listCaseHits(selectedCaseId),
          api.listCaseDevices(selectedCaseId),
        ]);
        const rows = h.hits || [];
        setHits(rows);
        setDevices(d.devices || []);
        if (rows.length > 0) {
          setSelectedHitId(rows[0].hit_id);
        } else {
          setSelectedHitId("");
        }
      } catch {
        setHits([]);
        setDevices([]);
        setSelectedHitId("");
      }
    })();
  }, [selectedCaseId]);

  const deviceNameByID = useMemo(() => {
    const m = new Map<string, string>();
    for (const d of devices) {
      m.set(d.device_id, d.device_name || d.identifier || d.os_type);
    }
    return m;
  }, [devices]);

  const selectedHit = useMemo(() => {
    return hits.find((h) => h.hit_id === selectedHitId) || null;
  }, [hits, selectedHitId]);

  const counts = useMemo(() => {
    const walletCount = hits.filter((h) => h.hit_type === "wallet_installed").length;
    const exchangeCount = hits.filter((h) => h.hit_type === "exchange_visited").length;
    const highRisk = hits.filter((h) => riskLevel(h) === "high").length;
    const mediumRisk = hits.filter((h) => riskLevel(h) === "medium").length;
    return { walletCount, exchangeCount, highRisk, mediumRisk };
  }, [hits]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        05 命中分析
      </h2>

      {/* 命中汇总 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">命中汇总</h3>

        <div className="grid grid-cols-4 gap-4">
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ffa726]">{counts.walletCount}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">钱包安装/扩展</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ffa726]">{counts.exchangeCount}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">交易所访问</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ff6b6b]">{counts.highRisk}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">高风险</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ffa726]">{counts.mediumRisk}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">中风险</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* 左侧：命中列表 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            命中列表（高密度表格）
          </h3>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-[#1e2127] border-b border-[#3a3f4a]">
                  <th className="text-left py-2 px-2 text-[#b8bcc4] font-bold">类型</th>
                  <th className="text-left py-2 px-2 text-[#b8bcc4] font-bold">名称</th>
                  <th className="text-left py-2 px-2 text-[#b8bcc4] font-bold">置信度</th>
                  <th className="text-left py-2 px-2 text-[#b8bcc4] font-bold">设备</th>
                </tr>
              </thead>
              <tbody>
                {hits.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-3 px-2 text-[#7a7f8a]">
                      暂无命中（请先执行采集）
                    </td>
                  </tr>
                ) : (
                  hits.map((hit) => {
                    const active = selectedHitId === hit.hit_id;
                    const confText = confidenceLabel(hit.confidence);
                    return (
                      <tr
                        key={hit.hit_id}
                        onClick={() => setSelectedHitId(hit.hit_id)}
                        className={`border-b border-[#3a3f4a] cursor-pointer ${
                          active ? "bg-[#2b5278] text-[#4fc3f7]" : "hover:bg-[#1e2127]"
                        }`}
                      >
                        <td className="py-2 px-2">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-[10px] ${
                              hit.hit_type === "wallet_installed"
                                ? "bg-[#4fc3f7] text-[#1a1d23]"
                                : "bg-[#ffa726] text-[#1a1d23]"
                            }`}
                          >
                            {typeLabel(hit.hit_type)}
                          </span>
                        </td>
                        <td className={`py-2 px-2 ${active ? "text-[#4fc3f7]" : "text-[#e8e8e8]"}`}>
                          {hit.rule_name || hit.rule_id}
                        </td>
                        <td className="py-2 px-2">
                          <span
                            className={
                              confText.includes("高")
                                ? "text-[#ff6b6b]"
                                : confText.includes("中")
                                  ? "text-[#ffa726]"
                                  : "text-[#b8bcc4]"
                            }
                          >
                            {confText}
                          </span>
                        </td>
                        <td className={`py-2 px-2 ${active ? "text-[#4fc3f7]" : "text-[#b8bcc4]"}`}>
                          {deviceNameByID.get(hit.device_id) || hit.device_id}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-3 text-xs text-[#7a7f8a]">
            * 点击行查看详细信息
          </div>
        </div>

        {/* 右侧：命中详情 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            命中详情
          </h3>

          {!selectedHit ? (
            <div className="text-xs text-[#7a7f8a]">请选择一条命中记录</div>
          ) : (
            <div className="space-y-4">
              <div>
                <div className="text-xs text-[#b8bcc4] mb-2">基本信息</div>
                <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 space-y-2">
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">名称：</label>
                    <span className="text-[#e8e8e8] text-xs font-bold">
                      {selectedHit.rule_name || selectedHit.rule_id}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">类型：</label>
                    <span className="text-[#e8e8e8] text-xs">
                      {typeLabel(selectedHit.hit_type)}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">置信度：</label>
                    <span className="text-xs text-[#ffa726]">
                      {confidenceLabel(selectedHit.confidence)}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">设备：</label>
                    <span className="text-[#e8e8e8] text-xs">
                      {deviceNameByID.get(selectedHit.device_id) || selectedHit.device_id}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">首次发现：</label>
                    <span className="text-[#4fc3f7] text-xs">
                      {selectedHit.first_seen_at
                        ? new Date(selectedHit.first_seen_at * 1000).toLocaleString("zh-CN", {
                            hour12: false,
                          })
                        : "-"}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">最后发现：</label>
                    <span className="text-[#4fc3f7] text-xs">
                      {selectedHit.last_seen_at
                        ? new Date(selectedHit.last_seen_at * 1000).toLocaleString("zh-CN", {
                            hour12: false,
                          })
                        : "-"}
                    </span>
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs text-[#b8bcc4] mb-2">匹配信息</div>
                <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 space-y-2">
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">规则ID：</label>
                    <span className="text-[#4fc3f7] text-xs font-mono">
                      {selectedHit.rule_id}
                    </span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-24 text-[#b8bcc4] text-xs">版本：</label>
                    <span className="text-[#e8e8e8] text-xs">{selectedHit.rule_version || "-"}</span>
                  </div>
                  <div className="flex items-start">
                    <label className="w-24 text-[#b8bcc4] text-xs pt-0.5">匹配值：</label>
                    <span className="text-[#e8e8e8] text-xs font-mono break-all">
                      {selectedHit.matched_value}
                    </span>
                  </div>
                  <div className="flex items-start">
                    <label className="w-24 text-[#b8bcc4] text-xs pt-0.5">细节：</label>
                    <span className="text-[#b8bcc4] text-xs font-mono break-all">
                      {(() => {
                        const d = parseDetail(selectedHit.detail_json);
                        if (!d) return "-";
                        const mf = d.match_field || d.matchField;
                        const os = d.os || d.device_os;
                        return [mf ? `match_field=${mf}` : "", os ? `os=${os}` : ""]
                          .filter(Boolean)
                          .join(" ");
                      })()}
                    </span>
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs text-[#b8bcc4] mb-2">关联证据</div>
                <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 space-y-1">
                  {(selectedHit.artifact_ids || []).length === 0 ? (
                    <div className="text-xs text-[#7a7f8a]">无关联证据</div>
                  ) : (
                    (selectedHit.artifact_ids || []).map((id) => (
                      <div key={id} className="flex items-center gap-2">
                        <span className="text-[#4fc3f7] text-xs">•</span>
                        <a
                          className="text-[#e8e8e8] text-xs font-mono hover:text-[#4fc3f7]"
                          href={`/api/artifacts/${id}/download`}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {id}
                        </a>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

