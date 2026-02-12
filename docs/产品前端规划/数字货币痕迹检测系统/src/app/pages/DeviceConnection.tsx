import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, AlertTriangle } from "lucide-react";
import { api } from "../api/client";
import type { CaseDevice, PrecheckResult } from "../api/types";
import { useApp } from "../state/AppContext";

function statusToIcon(status: string) {
  if (status === "passed") {
    return <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />;
  }
  return <AlertTriangle className="w-4 h-4 text-[#ffa726] flex-shrink-0" />;
}

function statusToLabel(status: string) {
  switch (status) {
    case "passed":
      return "通过";
    case "failed":
      return "失败";
    case "skipped":
      return "跳过";
    default:
      return status || "-";
  }
}

export default function DeviceConnection() {
  const { selectedCaseId } = useApp();
  const [devices, setDevices] = useState<CaseDevice[]>([]);
  const [prechecks, setPrechecks] = useState<PrecheckResult[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    if (!selectedCaseId) return;
    setLoading(true);
    try {
      const [d, p] = await Promise.all([
        api.listCaseDevices(selectedCaseId),
        api.listCasePrechecks(selectedCaseId),
      ]);
      setDevices(d.devices || []);
      setPrechecks(p.prechecks || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCaseId]);

  const hostDevice = useMemo(() => {
    return (
      devices.find((d) => d.connection_type === "local") ||
      devices.find((d) => d.os_type === "windows" || d.os_type === "macos") ||
      null
    );
  }, [devices]);

  const androidDevices = useMemo(
    () => devices.filter((d) => d.os_type === "android"),
    [devices]
  );
  const iosDevices = useMemo(
    () => devices.filter((d) => d.os_type === "ios"),
    [devices]
  );

  const checkResults = useMemo(() => {
    // 这里只展示主机/通用的前置检查，移动端授权检查在 devices 列表里也能看到。
    const rows = prechecks.filter(
      (c) => c.scan_scope === "host" || c.scan_scope === "general"
    );
    return rows.slice(-8).reverse();
  }, [prechecks]);

  return (
    <div className="p-6">
      <h2 className="text-lg font-bold mb-6 text-[#f0f0f0] border-b border-[#3a3f4a] pb-2">
        02 设备连接
      </h2>
      
      {/* 设备状态总览 */}
      <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 mb-6 shadow-lg">
        <h3 className="text-sm font-bold text-[#4fc3f7] mb-3">设备状态总览</h3>
        <div className="flex items-center gap-6 text-xs">
          <span className="text-[#b8bcc4]">
            主机：
            <span className={hostDevice ? "text-green-500" : "text-[#7a7f8a]"}>
              {hostDevice ? "已识别" : "未识别"}
            </span>
          </span>
          <span className="text-[#b8bcc4]">
            Android：<span className="text-[#4fc3f7]">{androidDevices.length} 台</span>
          </span>
          <span className="text-[#b8bcc4]">
            iOS：
            <span className={iosDevices.length > 0 ? "text-[#4fc3f7]" : "text-[#7a7f8a]"}>
              {iosDevices.length > 0 ? `${iosDevices.length} 台` : "未连接"}
            </span>
          </span>
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-6">
        {/* 左侧：主机设备信息 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            主机设备信息
          </h3>
          
          <div className="space-y-3 mb-4">
            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">主机名：</label>
              <span className="text-[#e8e8e8] text-xs">
                {hostDevice?.device_name || "-"}
              </span>
            </div>
            
            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">OS：</label>
              <span className="text-[#e8e8e8] text-xs">
                {hostDevice?.os_type || "-"}
              </span>
            </div>
            
            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">唯一指纹：</label>
              <span className="text-[#e8e8e8] text-xs font-mono">
                {hostDevice?.identifier || "-"}
              </span>
            </div>
            
            <div className="flex items-center">
              <label className="w-24 text-[#b8bcc4] text-xs">采集权限：</label>
              <span className="text-green-500 text-xs">
                {hostDevice ? "本机（可采集）" : "-"}
              </span>
            </div>
          </div>
          
          <button
            onClick={refresh}
            className="w-full bg-[#2b5278] hover:bg-[#365f8a] border border-[#4fc3f7] text-[#4fc3f7] px-4 py-2 text-xs rounded transition-colors mb-4"
          >
            [{loading ? "刷新中..." : "刷新前置检查"}]
          </button>
          
          {/* 前置检查结果 */}
          <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3">
            <h4 className="text-xs font-bold text-[#b8bcc4] mb-3">环境检查结果</h4>
            <div className="space-y-2">
              {checkResults.length === 0 ? (
                <div className="text-xs text-[#7a7f8a]">暂无检查结果（请先执行采集）</div>
              ) : (
                checkResults.map((c) => (
                  <div key={c.check_code + c.checked_at} className="flex items-center gap-2 text-xs">
                    {statusToIcon(c.status)}
                    <span className="text-[#b8bcc4]">
                      {c.check_name}：{statusToLabel(c.status)}
                      {c.message ? `（${c.message}）` : ""}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
        
        {/* 右侧：移动设备列表 */}
        <div className="bg-[#1e2127]/80 backdrop-blur-sm border border-[#3a3f4a] rounded p-4 shadow-lg">
          <h3 className="text-sm font-bold text-[#4fc3f7] mb-4 border-b border-[#3a3f4a] pb-2">
            移动设备列表
          </h3>
          
          {/* Android 设备 */}
          {androidDevices.map((d) => (
            <div key={d.device_id} className="bg-[#252931] border border-[#3a3f4a] rounded p-3 mb-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#4fc3f7] text-xs font-bold">
                  {d.device_name || "Android"}
                </span>
                <span className={d.authorized ? "text-green-500 text-xs" : "text-[#ffa726] text-xs"}>
                  {d.authorized ? "已授权" : "未授权"}
                </span>
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center">
                  <label className="w-20 text-[#b8bcc4] text-xs">标识：</label>
                  <span className="text-[#e8e8e8] text-xs font-mono">{d.identifier || "-"}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-20 text-[#b8bcc4] text-xs">连接：</label>
                  <span className="text-[#e8e8e8] text-xs">{d.connection_type}</span>
                </div>
                <div className="flex items-center">
                  <label className="w-20 text-[#b8bcc4] text-xs">授权说明：</label>
                  <span className="text-[#e8e8e8] text-xs">{d.auth_note || "-"}</span>
                </div>
              </div>
            </div>
          ))}
          
          {/* iOS 设备提示 */}
          {iosDevices.length === 0 ? (
            <div className="bg-[#252931] border border-[#3a3f4a] rounded p-3 mb-4">
              <div className="flex items-center justify-between">
                <span className="text-[#7a7f8a] text-xs">iOS 设备</span>
                <span className="text-[#7a7f8a] text-xs">未检测到</span>
              </div>
            </div>
          ) : (
            iosDevices.map((d) => (
              <div key={d.device_id} className="bg-[#252931] border border-[#3a3f4a] rounded p-3 mb-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[#4fc3f7] text-xs font-bold">
                    {d.device_name || "iOS"}
                  </span>
                  <span className={d.authorized ? "text-green-500 text-xs" : "text-[#ffa726] text-xs"}>
                    {d.authorized ? "已授权" : "未授权"}
                  </span>
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center">
                    <label className="w-20 text-[#b8bcc4] text-xs">标识：</label>
                    <span className="text-[#e8e8e8] text-xs font-mono">{d.identifier || "-"}</span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-20 text-[#b8bcc4] text-xs">连接：</label>
                    <span className="text-[#e8e8e8] text-xs">{d.connection_type}</span>
                  </div>
                  <div className="flex items-center">
                    <label className="w-20 text-[#b8bcc4] text-xs">授权说明：</label>
                    <span className="text-[#e8e8e8] text-xs">{d.auth_note || "-"}</span>
                  </div>
                </div>
              </div>
            ))
          )}
          
          <button
            onClick={refresh}
            className="w-full bg-[#1e2127] hover:bg-[#252931] border border-[#5a5f6a] text-[#b8bcc4] px-4 py-2 text-xs rounded transition-colors"
          >
            [{loading ? "刷新中..." : "刷新设备"}]
          </button>
        </div>
      </div>
    </div>
  );
}
