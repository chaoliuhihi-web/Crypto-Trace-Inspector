import { Link, useLocation, Outlet } from "react-router";
import { CheckCircle2, Circle } from "lucide-react";
import { BlockchainBackground } from "./BlockchainBackground";
import { TechCorners } from "./TechCorners";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "../state/AppContext";

const steps = [
  { id: 1, name: "01 案件信息", path: "/" },
  { id: 2, name: "02 设备连接", path: "/device" },
  { id: 3, name: "03 数据采集", path: "/collection" },
  { id: 4, name: "04 规则匹配", path: "/rules" },
  { id: 5, name: "05 命中分析", path: "/analysis" },
  { id: 6, name: "06 证据管理", path: "/evidence" },
  { id: 7, name: "07 报告生成", path: "/report" },
  { id: 8, name: "08 审计校验", path: "/audit" },
];

export function Layout() {
  const location = useLocation();
  const {
    meta,
    cases,
    selectedCaseId,
    selectCase,
    selectedCaseOverview,
    operator,
    setOperator,
    currentJob,
    error,
  } = useApp();

  // 顶部时间每秒刷新（避免一次渲染后“定格”）
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(t);
  }, []);

  const currentTime = useMemo(
    () =>
      now.toLocaleString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }),
    [now]
  );

  const jobStageLabel = useMemo(() => {
    const s = currentJob?.stage || "";
    switch (s) {
      case "host_scan":
        return "主机采集";
      case "mobile_scan":
        return "移动采集";
      case "finished":
        return "完成";
      default:
        return s || "-";
    }
  }, [currentJob?.stage]);

  const lastLog = useMemo(() => {
    const logs = currentJob?.logs || [];
    if (logs.length === 0) return "";
    return logs[logs.length - 1]?.message || "";
  }, [currentJob?.logs]);

  return (
    <div className="h-screen flex flex-col bg-[#1a1d23] text-[#e8e8e8] font-mono text-sm relative">
      {/* 区块链背景动效 */}
      <BlockchainBackground />
      
      {/* 科技感角落装饰 */}
      <TechCorners />
      
      {/* 顶部状态栏 */}
      <div className="bg-[#252931] border-b border-[#3a3f4a] px-4 py-3 relative z-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-8">
            <h1 className="text-base font-bold text-[#f0f0f0]">
              数字货币痕迹检测系统（内部使用）
            </h1>
            <div className="flex items-center gap-6 text-xs">
              <span className="text-[#b8bcc4]">
                案件：
                <select
                  value={selectedCaseId}
                  onChange={(e) => selectCase(e.target.value)}
                  className="ml-2 bg-[#1e2127] border border-[#3a3f4a] rounded px-2 py-1 text-[#4fc3f7] focus:outline-none focus:border-[#4fc3f7]"
                >
                  {cases.length === 0 ? (
                    <option value="">（暂无案件）</option>
                  ) : (
                    cases.map((c) => (
                      <option key={c.case_id} value={c.case_id}>
                        {(c.case_no && c.case_no.trim()) || c.case_id}{" "}
                        {c.title ? `- ${c.title}` : ""}
                      </option>
                    ))
                  )}
                </select>
              </span>
              <span className="text-[#b8bcc4]">
                操作员：
                <input
                  value={operator}
                  onChange={(e) => setOperator(e.target.value)}
                  className="ml-2 w-[120px] bg-[#1e2127] border border-[#3a3f4a] rounded px-2 py-1 text-[#4fc3f7] focus:outline-none focus:border-[#4fc3f7]"
                />
              </span>
              <span className="text-[#b8bcc4]">
                当前时间：<span className="text-[#4fc3f7]">{currentTime}</span>
              </span>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              <span className="text-[#b8bcc4]">证据链状态：可追溯</span>
            </span>
            <span className="text-[#b8bcc4]">
              数据库：{meta?.db?.schema_version ? `schema v${meta.db.schema_version}` : "未知"}
            </span>
            <span className="text-[#b8bcc4]">
              规则库：wallet v{meta?.rules?.wallet?.version || "-"}
            </span>
          </div>
        </div>
        {error ? (
          <div className="mt-2 text-xs text-[#ff6b6b]">
            ERROR: {error}
          </div>
        ) : null}
      </div>

      <div className="flex flex-1 overflow-hidden relative z-10">
        {/* 左侧导航 */}
        <div className="w-[220px] bg-[#1e2127]/95 backdrop-blur-sm border-r border-[#3a3f4a] overflow-y-auto">
          <nav className="p-3">
            {steps.map((step) => {
              const isActive = location.pathname === step.path;
              const currentStepIndex = steps.findIndex(
                (s) => s.path === location.pathname
              );
              const isCompleted = step.id < steps[currentStepIndex]?.id;

              return (
                <Link
                  key={step.id}
                  to={step.path}
                  className={`flex items-center gap-2 px-3 py-2.5 mb-1 rounded transition-colors ${
                    isActive
                      ? "bg-[#2b5278] text-[#4fc3f7] border border-[#4fc3f7]"
                      : "text-[#b8bcc4] hover:bg-[#252931] hover:text-[#e8e8e8]"
                  }`}
                >
                  {isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  ) : (
                    <Circle
                      className={`w-4 h-4 flex-shrink-0 ${
                        isActive ? "text-[#4fc3f7]" : "text-[#5a5f6a]"
                      }`}
                    />
                  )}
                  <span className="text-xs">{step.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* 主工作区 */}
        <div className="flex-1 overflow-y-auto bg-transparent">
          <Outlet />
        </div>
      </div>

      {/* 底部状态栏 */}
      <div className="bg-[#252931] border-t border-[#3a3f4a] px-4 py-2 flex items-center justify-between text-xs relative z-10">
        <div className="flex items-center gap-6 text-[#b8bcc4]">
          <span>
            任务ID：<span className="text-[#4fc3f7]">{currentJob?.job_id || "-"}</span>
          </span>
          <span>
            当前阶段：<span className="text-[#4fc3f7]">{jobStageLabel}</span>
          </span>
          <span>
            进度：<span className="text-[#4fc3f7]">{(currentJob?.progress ?? 0)}%</span>
          </span>
          <span>
            最近日志：<span className="text-[#ffa726]">{lastLog || "-"}</span>
          </span>
        </div>
        <div className="flex items-center gap-6 text-[#b8bcc4]">
          <span>系统版本：{meta?.app?.version || "-"}</span>
          <span>DB Schema：{meta?.db?.schema_version || "-"}</span>
          <span>命中：{selectedCaseOverview?.hit_count ?? 0}</span>
        </div>
      </div>
    </div>
  );
}
