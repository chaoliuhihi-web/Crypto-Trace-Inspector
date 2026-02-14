import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { HitDetail, RuleFileInfo, RulesListResponse } from "../api/types";
import { useApp } from "../state/AppContext";

function formatTime(ts: number) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

export default function RuleMatching() {
  const { meta, selectedCaseId, refreshMeta } = useApp();
  const [hits, setHits] = useState<HitDetail[]>([]);

  const [rules, setRules] = useState<RulesListResponse | null>(null);
  const [rulesLoading, setRulesLoading] = useState<boolean>(false);
  const [rulesErr, setRulesErr] = useState<string>("");
  const [rulesMsg, setRulesMsg] = useState<string>("");
  const [walletPath, setWalletPath] = useState<string>("");
  const [exchangePath, setExchangePath] = useState<string>("");
  const [walletUpload, setWalletUpload] = useState<File | null>(null);
  const [exchangeUpload, setExchangeUpload] = useState<File | null>(null);

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

  const loadRules = async () => {
    setRulesErr("");
    setRulesMsg("");
    setRulesLoading(true);
    try {
      const res = await api.listRules();
      setRules(res);
      setWalletPath(res.active.wallet_path || "");
      setExchangePath(res.active.exchange_path || "");
    } catch (e: any) {
      setRules(null);
      setRulesErr(e?.message || String(e));
    } finally {
      setRulesLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const ruleLabel = (r: RuleFileInfo) => {
    const v = (r.version || "").trim();
    return `${r.filename}${v ? ` (v${v})` : ""}`;
  };

  const doActivate = async (kind: "wallet" | "exchange") => {
    setRulesErr("");
    setRulesMsg("");
    setRulesLoading(true);
    try {
      if (kind === "wallet") {
        await api.activateRules({ wallet_path: walletPath });
      } else {
        await api.activateRules({ exchange_path: exchangePath });
      }
      await refreshMeta();
      await loadRules();
      setRulesMsg("已启用（下一次扫描会使用新规则）。");
    } catch (e: any) {
      setRulesErr(e?.message || String(e));
    } finally {
      setRulesLoading(false);
    }
  };

  const doImport = async (kind: "wallet" | "exchange") => {
    setRulesErr("");
    setRulesMsg("");
    const f = kind === "wallet" ? walletUpload : exchangeUpload;
    if (!f) {
      setRulesErr("请选择要上传的规则 YAML 文件。");
      return;
    }
    setRulesLoading(true);
    try {
      const content = await f.text();
      await api.importRules({ kind, filename: f.name, content });
      await refreshMeta();
      await loadRules();
      setRulesMsg("上传并启用成功（下一次扫描会使用新规则）。");
    } catch (e: any) {
      setRulesErr(e?.message || String(e));
    } finally {
      setRulesLoading(false);
    }
  };

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

      {/* 规则管理（导入/切换） */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">规则管理（导入/切换）</h3>

        <div className="text-xs text-[#7a7f8a] mb-3">
          说明：规则文件保存在本机 <span className="text-[#4fc3f7] font-mono">{rules?.rules_dir || "-"}</span>。
          <br />
          切换规则不会影响已生成的历史命中与证据链；只会影响“下一次采集/匹配”。
        </div>

        {rulesErr ? (
          <div className="text-xs text-[#ff6b6b] mb-2">ERROR: {rulesErr}</div>
        ) : null}
        {rulesMsg ? (
          <div className="text-xs text-green-500 mb-2">{rulesMsg}</div>
        ) : null}

        <div className="grid grid-cols-2 gap-6">
          {/* Wallet rules */}
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-2">钱包规则（wallet_signatures）</div>

            <div className="flex items-center gap-2 mb-2">
              <select
                value={walletPath}
                onChange={(e) => setWalletPath(e.target.value)}
                className="flex-1 bg-[#1e2127] border border-[#3a3f4a] rounded px-2 py-1 text-xs text-[#e8e8e8] focus:outline-none focus:border-[#4fc3f7]"
              >
                {(rules?.wallet || []).map((r) => (
                  <option key={r.path} value={r.path}>
                    {r.active ? `* ${ruleLabel(r)}` : ruleLabel(r)}
                  </option>
                ))}
              </select>
              <button
                disabled={rulesLoading || !walletPath}
                onClick={() => doActivate("wallet")}
                className="bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-3 py-1 text-xs rounded transition-colors"
              >
                [启用]
              </button>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="file"
                accept=".yaml,.yml"
                onChange={(e) => setWalletUpload(e.target.files?.[0] || null)}
                className="flex-1 text-xs text-[#b8bcc4]"
              />
              <button
                disabled={rulesLoading}
                onClick={() => doImport("wallet")}
                className="bg-[#1e2127] hover:bg-[#252931] disabled:opacity-50 border border-[#5a5f6a] text-[#b8bcc4] px-3 py-1 text-xs rounded transition-colors"
              >
                [上传并启用]
              </button>
            </div>
          </div>

          {/* Exchange rules */}
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <div className="text-xs text-[#b8bcc4] mb-2">交易所规则（exchange_domains）</div>

            <div className="flex items-center gap-2 mb-2">
              <select
                value={exchangePath}
                onChange={(e) => setExchangePath(e.target.value)}
                className="flex-1 bg-[#1e2127] border border-[#3a3f4a] rounded px-2 py-1 text-xs text-[#e8e8e8] focus:outline-none focus:border-[#4fc3f7]"
              >
                {(rules?.exchange || []).map((r) => (
                  <option key={r.path} value={r.path}>
                    {r.active ? `* ${ruleLabel(r)}` : ruleLabel(r)}
                  </option>
                ))}
              </select>
              <button
                disabled={rulesLoading || !exchangePath}
                onClick={() => doActivate("exchange")}
                className="bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-3 py-1 text-xs rounded transition-colors"
              >
                [启用]
              </button>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="file"
                accept=".yaml,.yml"
                onChange={(e) => setExchangeUpload(e.target.files?.[0] || null)}
                className="flex-1 text-xs text-[#b8bcc4]"
              />
              <button
                disabled={rulesLoading}
                onClick={() => doImport("exchange")}
                className="bg-[#1e2127] hover:bg-[#252931] disabled:opacity-50 border border-[#5a5f6a] text-[#b8bcc4] px-3 py-1 text-xs rounded transition-colors"
              >
                [上传并启用]
              </button>
            </div>
          </div>
        </div>

        <div className="mt-3 text-[10px] text-[#7a7f8a] font-mono break-all">
          active wallet: {rules?.active?.wallet_path || "-"}
          <br />
          active exchange: {rules?.active?.exchange_path || "-"}
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
