import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { HitDetail } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

export default function RuleMatching() {
  const { meta, selectedCaseId } = useApp();
  const [hits, setHits] = useState<HitDetail[]>([]);

  useEffect(() => {
    (async () => {
      if (!selectedCaseId) {
        setHits([]);
        return;
      }
      try {
        const res = await api.listCaseHits(selectedCaseId);
        setHits(res.hits || []);
      } catch {
        setHits([]);
      }
    })();
  }, [selectedCaseId]);

  const walletHits = hits.filter((h) => h.hit_type === "wallet_installed");
  const exchangeHits = hits.filter((h) => h.hit_type === "exchange_visited");

  const ruleAgg = useMemo(() => {
    // 聚合到“规则维度”，便于表格快速扫视
    const m = new Map<
      string,
      { rule_id: string; hit_type: string; rule_name: string; rule_version: string; count: number }
    >();
    for (const h of hits) {
      const key = `${h.hit_type}::${h.rule_id}`;
      const v = m.get(key) || {
        rule_id: h.rule_id,
        hit_type: h.hit_type,
        rule_name: h.rule_name,
        rule_version: h.rule_version,
        count: 0,
      };
      v.count += 1;
      m.set(key, v);
    }
    return Array.from(m.values()).sort((a, b) => b.count - a.count);
  }, [hits]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        04 规则匹配
      </h2>

      {/* 规则库信息 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">规则库信息</h3>

        <div className="grid grid-cols-3 gap-6">
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">钱包规则</div>
            <div className="text-base font-bold text-[#4fc3f7]">
              {meta?.rules?.wallet?.version || "-"}
            </div>
            <div className="text-xs text-[#7a7f8a] mt-1">
              共 {meta?.rules?.wallet?.total ?? 0} 条，启用 {meta?.rules?.wallet?.enabled ?? 0} 条
            </div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">交易所规则</div>
            <div className="text-base font-bold text-[#4fc3f7]">
              {meta?.rules?.exchange?.version || "-"}
            </div>
            <div className="text-xs text-[#7a7f8a] mt-1">
              共 {meta?.rules?.exchange?.total ?? 0} 条，启用 {meta?.rules?.exchange?.enabled ?? 0} 条
            </div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-1">元信息</div>
            <div className="text-xs text-[#e8e8e8] mt-2">
              meta 时间：{meta?.time ? formatTime(meta.time) : "-"}
            </div>
            <div className="text-[10px] text-[#7a7f8a] mt-2 break-all">
              wallet sha256: {meta?.rules?.wallet?.sha256 || "-"}
            </div>
          </div>
        </div>

        <div className="flex gap-2 mt-4">
          <button
            disabled
            className="bg-[#2b5278] opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-4 py-1.5 text-xs rounded"
          >
            [执行规则匹配]
          </button>
          <div className="text-xs text-[#7a7f8a] flex items-center">
            规则匹配已在采集时自动完成；如需重跑请回到“数据采集”重新执行。
          </div>
        </div>
      </div>

      {/* 规则匹配摘要 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">规则匹配摘要</h3>

        <div className="grid grid-cols-4 gap-4">
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ffa726]">{walletHits.length}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">钱包命中</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#ffa726]">{exchangeHits.length}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">交易所命中</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#7a7f8a]">-</div>
            <div className="text-xs text-[#b8bcc4] mt-1">未命中数据</div>
          </div>

          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 text-center">
            <div className="text-2xl font-bold text-[#4fc3f7]">{hits.length}</div>
            <div className="text-xs text-[#b8bcc4] mt-1">总命中数</div>
          </div>
        </div>
      </div>

      {/* 详细匹配结果 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">详细匹配结果（按规则聚合）</h3>

        <div className="bg-[#252931] border border-[#3a3f4a] rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-[#1e2127] border-b border-[#3a3f4a]">
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">规则ID</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">规则类型</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">规则名称</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">命中数量</th>
                <th className="text-left py-2 px-3 text-[#b8bcc4] font-bold">版本</th>
              </tr>
            </thead>
            <tbody>
              {ruleAgg.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-3 px-3 text-[#7a7f8a]">
                    暂无命中（请先执行采集）
                  </td>
                </tr>
              ) : (
                ruleAgg.map((r) => (
                  <tr key={`${r.hit_type}-${r.rule_id}`} className="border-b border-[#3a3f4a] hover:bg-[#1e2127]">
                    <td className="py-2 px-3 text-[#4fc3f7] font-mono">{r.rule_id}</td>
                    <td className="py-2 px-3 text-[#e8e8e8]">
                      {r.hit_type === "wallet_installed" ? "钱包" : "交易所"}
                    </td>
                    <td className="py-2 px-3 text-[#e8e8e8]">{r.rule_name || "-"}</td>
                    <td className="py-2 px-3 text-[#ffa726] font-bold">{r.count}</td>
                    <td className="py-2 px-3 text-green-500">{r.rule_version || "-"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="mt-4 text-xs text-[#7a7f8a]">
          * 该页为“采集后匹配结果展示”。匹配逻辑在采集任务内执行，确保结果与证据链一致。
        </div>
      </div>
    </div>
  );
}

