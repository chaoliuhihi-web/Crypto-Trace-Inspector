import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Circle, Loader2 } from "lucide-react";
import { useApp } from "../state/AppContext";

type NodeStatus = "complete" | "progress" | "waiting" | "failed" | "skipped";

function StatusIcon(props: { status: NodeStatus }) {
  const s = props.status;
  if (s === "complete") {
    return (
      <CheckCircle2 className="w-3.5 h-3.5 text-green-500 flex-shrink-0" />
    );
  }
  if (s === "progress") {
    return (
      <Loader2 className="w-3.5 h-3.5 text-[#4fc3f7] animate-spin flex-shrink-0" />
    );
  }
  if (s === "failed") {
    return (
      <AlertTriangle className="w-3.5 h-3.5 text-[#ff6b6b] flex-shrink-0" />
    );
  }
  return <Circle className="w-3.5 h-3.5 text-[#5a5f6a] flex-shrink-0" />;
}

function statusTextColor(s: NodeStatus) {
  switch (s) {
    case "complete":
      return "text-[#b8bcc4]";
    case "progress":
      return "text-[#4fc3f7]";
    case "failed":
      return "text-[#ff6b6b]";
    case "skipped":
      return "text-[#7a7f8a]";
    default:
      return "text-[#7a7f8a]";
  }
}

export default function DataCollection() {
  const { currentJob, startScanAll } = useApp();

  const [mode, setMode] = useState<"quick" | "full" | "custom">("full");
  const [enableHost, setEnableHost] = useState(true);
  const [enableAndroid, setEnableAndroid] = useState(true);
  const [enableIOS, setEnableIOS] = useState(false);
  const [authOrder, setAuthOrder] = useState("");
  const [authBasis, setAuthBasis] = useState("");
  const [note, setNote] = useState("");

  const running = currentJob?.status === "running";

  const walletHits =
    (currentJob?.host?.wallet_hits || 0) + (currentJob?.mobile?.wallet_hits || 0);
  const exchangeHits = currentJob?.host?.exchange_hits || 0;

  const collectionStages = useMemo(() => {
    const stage = currentJob?.stage || "";
    const status = currentJob?.status || "";

    const hostFailed = !!currentJob?.host_error;
    const mobileFailed = !!currentJob?.mobile_error;

    const hostStatus: NodeStatus = !enableHost
      ? "skipped"
      : hostFailed
        ? "failed"
        : status === "running" && stage === "host_scan"
          ? "progress"
          : currentJob?.host
            ? "complete"
            : status === "success" && stage === "finished"
              ? "complete"
              : "waiting";

    const mobileEnabled = enableAndroid || enableIOS;
    const mobileStatus: NodeStatus = !mobileEnabled
      ? "skipped"
      : mobileFailed
        ? "failed"
        : status === "running" && stage === "mobile_scan"
          ? "progress"
          : currentJob?.mobile
            ? "complete"
            : status === "success" && stage === "finished"
              ? "complete"
              : stage === "host_scan" && status === "running"
                ? "waiting"
                : "waiting";

    return [
      {
        name: "主机采集",
        children: [{ name: "安装应用/扩展/历史（合并展示）", status: hostStatus }],
      },
      {
        name: "Android 设备",
        children: [{ name: "包名采集", status: enableAndroid ? mobileStatus : "skipped" }],
      },
      {
        name: "iOS 设备",
        children: [{ name: "备份接入（骨架）", status: enableIOS ? mobileStatus : "skipped" }],
      },
    ];
  }, [currentJob, enableHost, enableAndroid, enableIOS]);

  const logs = useMemo(() => {
    const rows = currentJob?.logs || [];
    return rows.slice(-120);
  }, [currentJob?.logs]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        03 数据采集
      </h2>

      {/* 扫描配置 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-4">扫描配置</h3>

        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <label className="text-[#b8bcc4] text-xs w-20">模式：</label>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="mode"
                    value="quick"
                    checked={mode === "quick"}
                    onChange={() => setMode("quick")}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">快速</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="mode"
                    value="full"
                    checked={mode === "full"}
                    onChange={() => setMode("full")}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">全量</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="mode"
                    value="custom"
                    checked={mode === "custom"}
                    onChange={() => setMode("custom")}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">自定义</span>
                </label>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <label className="text-[#b8bcc4] text-xs w-20">采集范围：</label>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableHost}
                    onChange={(e) => setEnableHost(e.target.checked)}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">主机</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableAndroid}
                    onChange={(e) => setEnableAndroid(e.target.checked)}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">Android</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableIOS}
                    onChange={(e) => setEnableIOS(e.target.checked)}
                    className="w-3 h-3"
                  />
                  <span className="text-xs text-[#b8bcc4]">iOS</span>
                </label>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">授权令号：</label>
              <input
                type="text"
                value={authOrder}
                onChange={(e) => setAuthOrder(e.target.value)}
                placeholder="内测可不填；对外/审计建议填写"
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7]"
              />
            </div>

            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">授权依据：</label>
              <input
                type="text"
                value={authBasis}
                onChange={(e) => setAuthBasis(e.target.value)}
                placeholder="可选"
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7]"
              />
            </div>

            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">备注：</label>
              <input
                type="text"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="本次采集说明（可选）"
                className="flex-1 bg-[#252931] border border-[#3a3f4a] px-2 py-1 text-xs text-[#e8e8e8] rounded focus:outline-none focus:border-[#4fc3f7]"
              />
            </div>
          </div>
        </div>

        <button
          disabled={running}
          onClick={() =>
            startScanAll({
              note,
              profile: "internal",
              auth_order: authOrder,
              auth_basis: authBasis,
              ios_full_backup: true,
              enable_host: enableHost,
              enable_android: enableAndroid,
              enable_ios: enableIOS,
            })
          }
          className="mt-4 bg-[#2b5278] hover:bg-[#365f8a] disabled:opacity-50 border border-[#4fc3f7] text-[#4fc3f7] px-6 py-2 text-xs rounded transition-colors"
        >
          [{running ? "采集中..." : "开始采集"}]
        </button>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* 左侧：采集阶段树 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            采集阶段树
          </h3>

          <div className="space-y-3">
            {collectionStages.map((stage, idx) => (
              <div key={idx} className="space-y-1">
                <div className="text-xs font-bold text-[#e8e8e8]">
                  {stage.name}
                </div>
                {stage.children.map((child, cidx) => (
                  <div key={cidx} className="flex items-center gap-2 pl-4 py-1">
                    <StatusIcon status={child.status as NodeStatus} />
                    <span
                      className={`text-xs ${statusTextColor(child.status as NodeStatus)}`}
                    >
                      {child.name}
                    </span>
                    {child.status === "progress" ? (
                      <span className="text-[#4fc3f7] text-xs ml-auto">进行中</span>
                    ) : null}
                    {child.status === "waiting" ? (
                      <span className="text-[#7a7f8a] text-xs ml-auto">等待</span>
                    ) : null}
                    {child.status === "skipped" ? (
                      <span className="text-[#7a7f8a] text-xs ml-auto">跳过</span>
                    ) : null}
                    {child.status === "failed" ? (
                      <span className="text-[#ff6b6b] text-xs ml-auto">失败</span>
                    ) : null}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>

        {/* 右侧：运行状态控制台 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            运行状态控制台
          </h3>

          <div className="space-y-3 mb-4">
            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">任务ID：</label>
              <span className="text-[#4fc3f7] text-xs font-mono">
                {currentJob?.job_id || "-"}
              </span>
            </div>

            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">开始时间：</label>
              <span className="text-[#e8e8e8] text-xs">
                {currentJob?.started_at
                  ? new Date(currentJob.started_at * 1000).toLocaleString("zh-CN", {
                      hour12: false,
                    })
                  : "-"}
              </span>
            </div>

            <div className="flex items-center">
              <label className="w-20 text-[#b8bcc4] text-xs">进度：</label>
              <div className="flex-1">
                <div className="bg-[#252931] h-5 rounded overflow-hidden border border-[#3a3f4a]">
                  <div
                    className="bg-[#4fc3f7] h-full flex items-center justify-center text-[10px] text-[#1a1d23] font-bold"
                    style={{ width: `${currentJob?.progress ?? 0}%` }}
                  >
                    {currentJob?.progress ?? 0}%
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 实时命中 */}
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 mb-4">
            <h4 className="text-xs font-bold text-[#b8bcc4] mb-2">实时命中</h4>
            <div className="grid grid-cols-2 gap-2">
              <div className="text-xs">
                <span className="text-[#b8bcc4]">钱包：</span>
                <span className="text-[#ffa726] font-bold">{walletHits}</span>
              </div>
              <div className="text-xs">
                <span className="text-[#b8bcc4]">交易所：</span>
                <span className="text-[#ffa726] font-bold">{exchangeHits}</span>
              </div>
            </div>
          </div>

          {/* 运行日志 */}
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <h4 className="text-xs font-bold text-[#b8bcc4] mb-2">运行日志</h4>
            <div className="space-y-1 font-mono max-h-32 overflow-y-auto">
              {logs.length === 0 ? (
                <div className="text-[10px] text-[#7a7f8a]">暂无日志</div>
              ) : (
                logs.map((log) => (
                  <div key={log.time + log.message} className="text-[10px]">
                    <span className="text-[#ffa726]">
                      {new Date(log.time * 1000).toLocaleTimeString("zh-CN", {
                        hour12: false,
                      })}
                    </span>
                    <span className="text-[#b8bcc4] ml-2">{log.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

