# Windows/macOS 采集清单（MVP）

## 1. 目标

- 用于实现两类检测：
- `wallet_installed`：是否安装过/使用过数字钱包。
- `exchange_visited`：是否访问过主流交易所网站。

说明：
- 本清单优先满足内部排查，字段与 `/Users/xinghe/XingheAI2026/数字币/docs/sql/001_init.sql` 对齐。
- 每次采集都要落地 `artifact`，并保存 `sha256` 与 `record_hash`。

## 2. 采集总策略

1. 优先采集“强证据”
- 应用安装清单
- 浏览器扩展目录与扩展 ID
- 浏览器历史数据库

2. 次级采集“辅助证据”
- 常见安装路径残留
- 登录项/启动项关键词
- DNS 缓存（可选）

3. 证据分级建议
- `A`：直接命中包名/扩展ID/确切域名（高置信）
- `B`：命中可疑关键词（中置信）
- `C`：仅残留痕迹（低置信）

## 3. Windows 采集清单

### 3.1 应用安装信息（artifact_type=`installed_apps`）

数据源：
- 注册表卸载项
- 常见安装目录

重点位置：
- `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*`
- `HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*`
- `HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*`
- `%ProgramFiles%`
- `%ProgramFiles(x86)%`
- `%LOCALAPPDATA%`

建议采集字段：
- `DisplayName`
- `DisplayVersion`
- `Publisher`
- `InstallLocation`
- `InstallDate`
- `UninstallString`

落库建议：
- 原始导出保存为 `csv/json` 快照
- `source_ref` 示例：`registry_uninstall_keys`
- `acquisition_method`：`registry_query`

### 3.2 浏览器扩展（artifact_type=`browser_extension`）

目标浏览器：
- Chrome
- Edge
- Firefox

重点位置：
- `%LOCALAPPDATA%/Google/Chrome/User Data/*/Extensions`
- `%LOCALAPPDATA%/Microsoft/Edge/User Data/*/Extensions`
- `%APPDATA%/Mozilla/Firefox/Profiles/*/extensions`

关键内容：
- 扩展 ID
- manifest 名称与版本
- profile 标识

落库建议：
- 每个浏览器一次采集形成一个 artifact
- `source_ref` 示例：`chrome_extensions_profile_default`
- `acquisition_method`：`file_scan`

### 3.3 浏览历史（artifact_type=`browser_history`）

目标浏览器：
- Chrome
- Edge
- Firefox

重点数据库：
- Chrome: `%LOCALAPPDATA%/Google/Chrome/User Data/*/History`
- Edge: `%LOCALAPPDATA%/Microsoft/Edge/User Data/*/History`
- Firefox: `%APPDATA%/Mozilla/Firefox/Profiles/*/places.sqlite`

建议提取字段：
- `url`
- `title`
- `visit_time`
- `visit_count`
- `typed_count`
- `profile`

注意：
- 正在运行的浏览器数据库可能锁定，先复制再解析。
- 时间格式需统一转换到 UTC epoch 秒。

落库建议：
- 原始 DB 复制件与解析结果都可形成 artifacts
- `source_ref` 示例：`chrome_history_profile_default`
- `acquisition_method`：`file_copy_parse`

### 3.4 可选辅助采集

- DNS 缓存：`ipconfig /displaydns`
- 启动项关键词：`HKCU/HKLM ...\\Run`
- 最近执行记录（谨慎启用）

这些证据默认设为中低置信，不单独作为最终结论。

## 4. macOS 采集清单

### 4.1 应用安装信息（artifact_type=`installed_apps`）

数据源：
- `/Applications`
- `~/Applications`
- LaunchServices 信息（可选）

重点位置：
- `/Applications/*.app`
- `~/Applications/*.app`
- `~/Library/Application Support/*`

建议采集字段：
- 应用名（`CFBundleName`）
- Bundle ID（`CFBundleIdentifier`）
- 版本（`CFBundleShortVersionString`）
- 安装路径

落库建议：
- `source_ref` 示例：`applications_bundle_scan`
- `acquisition_method`：`bundle_scan`

### 4.2 浏览器扩展（artifact_type=`browser_extension`）

目标浏览器：
- Chrome
- Edge
- Firefox
- Safari（扩展可见性受系统策略影响）

重点位置：
- `~/Library/Application Support/Google/Chrome/*/Extensions`
- `~/Library/Application Support/Microsoft Edge/*/Extensions`
- `~/Library/Application Support/Firefox/Profiles/*/extensions`

关键内容：
- 扩展 ID / 扩展包名
- profile
- manifest

落库建议：
- `source_ref` 示例：`edge_extensions_profile_profile1`
- `acquisition_method`：`file_scan`

### 4.3 浏览历史（artifact_type=`browser_history`）

目标浏览器：
- Safari
- Chrome
- Edge
- Firefox

重点数据库：
- Safari: `~/Library/Safari/History.db`
- Chrome: `~/Library/Application Support/Google/Chrome/*/History`
- Edge: `~/Library/Application Support/Microsoft Edge/*/History`
- Firefox: `~/Library/Application Support/Firefox/Profiles/*/places.sqlite`

建议提取字段：
- `url`
- `title`
- `visit_time`
- `visit_count`
- `profile/browser`

注意：
- 数据库拷贝后解析，避免锁冲突。
- Safari 时间基准和 Chromium/Firefox 不同，统一转 epoch 秒。

落库建议：
- `source_ref` 示例：`safari_history_db`
- `acquisition_method`：`file_copy_parse`

### 4.4 可选辅助采集

- `~/Library/Preferences` 中钱包相关偏好文件
- `~/Library/Caches` 中可疑缓存

这些只作为辅助证据，不直接判定“已安装”。

## 5. 采集与规则匹配映射

1. `installed_apps` + `wallet_signatures.desktop.*`
- 命中程序名、bundle id、安装路径、关键词。

2. `browser_extension` + `wallet_signatures.browser_extensions.*`
- 命中扩展 ID（高置信）。

3. `browser_history` + `exchange_domains.domains`
- 命中确切域名或根域名（高置信）。

4. `browser_history` + `exchange_domains.urls_contains`
- 命中 URL 关键词（中置信）。

## 6. artifact 命名建议

- 命名格式：`{caseId}_{deviceId}_{artifactType}_{source}_{ts}.json|db|zip`
- 示例：
- `CASE001_HOSTWIN_browser_history_chrome_default_1739395200.db`
- `CASE001_HOSTMAC_installed_apps_bundle_scan_1739395200.json`

## 7. 失败场景与状态落库

必须记录到 `audit_logs`：
- 浏览器文件锁定
- 权限不足
- 路径不存在
- 解析失败

`rule_hits.verdict` 建议：
- 成功命中：`confirmed`
- 仅关键词：`suspected`
- 因系统限制无法判断：`unsupported`

## 8. MVP 执行顺序（Windows/macOS）

1. 设备识别与前置检查
2. 采集安装应用
3. 采集浏览器扩展
4. 采集浏览器历史
5. 规则匹配（钱包/交易所）
6. 证据入库与链路日志
7. 输出内部报告
