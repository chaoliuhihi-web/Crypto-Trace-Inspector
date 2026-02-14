# TODO List（从当前仓库现状出发）

目标：把当前“可用的内测版”补齐为更完整的功能闭环，并把所有改动做到“可验证、可追溯、可复现”。

说明：
- 本清单以 `/Users/xinghe/XingheAI2026/数字币/功能需求.pdf` + 当前实现差距为准。
- 某些移动端数据在**未 root/未越狱/未授权**情况下天然不可得：此类功能按“best effort + 明确前置条件 + 证据链留痕”的方式实现。

---

## P0（必须完成：形成闭环，能交付内测）

- [x] 01. 移动端“交易所访问”检测（iOS 优先，Android best effort）
  - 实现：
    - iOS：从 iOS 备份中提取 Safari/Chrome 浏览痕迹 -> 生成 `browser_history` artifact -> 匹配交易所域名规则并写入 `exchange_visited` 命中（best effort；不做破解/绕过）。
    - Android：通过 `adb shell content query` 尝试读取可达的浏览 provider（best effort）；不可达时写入 `precheck=skipped` 并记录尝试细节/原因（UI 可见）。
  - 验证：
    - iOS：单元测试覆盖（Manifest.db + History.db 合成备份目录），并在移动端 matcher 中可生成 `exchange_visited` 命中。
    - Android：单元/集成层面验证“不可达 -> precheck=skipped 且 reason 可见”；真机上若 provider 可用则可落 `browser_history` artifact。
  - 当前进度：
    - iOS：Safari/Chrome 备份解析已实现并新增单测
    - Android：浏览历史 best effort 采集已实现（content provider 尝试 + precheck 留痕）

- [x] 02. 链上余额：满足“BTC/USDT/ETH 数量”最小可用
  - 实现：
    - ETH：沿用 EVM `eth_getBalance`
    - USDT（EVM）：新增 ERC20 `balanceOf` 查询（可配置 chain/rpc/contract）
    - BTC：新增可配置 provider（默认公共 API，允许内网自建节点/网关替换）
    - 支持“手动输入地址查询 + 结果留痕（可写入报告/导出）”
  - 验证：
    - 单元测试覆盖：EVM 原生余额、ERC20 余额、BTC provider（使用 httptest）。
    - UI 发起查询成功/失败都能展示明确信息。

- [x] 03. 自动抽取地址（从现有证据中提取 wallet_address 命中）
  - 实现：
    - 从主机/移动端 `browser_history` 的 URL/title 中提取：EVM 地址（0x…）、BTC bech32/base58（基础规则）
    - 命中写入 `rule_hits.hit_type=wallet_address`，并关联触发证据
  - 验证：
    - 构造包含地址的访问 URL/标题，扫描后出现 wallet_address 命中。

- [x] 04. token_balance 命中（把链上余额查询结果固化成命中 + 证据）
  - 实现：
    - 将余额查询结果写入：
      - `artifacts`（快照 JSON）
      - `rule_hits.hit_type=token_balance`（matched_value=address 或 address+token 标识）
    - 在司法导出 ZIP 的 manifest 中可追溯
  - 验证：
    - UI 可看到 token_balance 命中，且能下载对应证据快照。

- [x] 05. 证据文件 SHA256 复核（UI 一键校验 + API/CLI）
  - 实现：
    - API：对指定 artifact 或指定 case 全量复算 `snapshot_path` 哈希并对比数据库 `sha256`
    - 输出校验结果（ok/mismatch/missing/error），并写 audit
  - 验证：
    - 正常文件：ok
    - 人工改动 snapshot 文件：mismatch

- [x] 06. 司法导出包离线校验工具（verify 命令）
  - 实现：
    - CLI：`inspector-cli verify forensic-zip --zip <path>`
    - 读取 `manifest.json` + `hashes.sha256`，对 zip 内文件复算并输出差异
  - 验证：
    - 原始 zip：校验通过
    - 篡改 zip 内文件：校验失败并定位到文件路径

- [x] 07. internal_html 报告（可读性更强，UI 可直接预览）
  - 实现：
    - hostscan/mobilescan 完成后同时生成 `internal_json` + `internal_html`
    - HTML 中包含：案件摘要、设备清单、前置条件、命中汇总、证据列表、审计链状态
  - 验证：
    - UI 报告页能预览 internal_html（内联内容）

- [x] 08. 规则包版本留痕（rule_bundles 入库 + 命中关联 rule_bundle_id）
  - 实现：
    - 规则加载时计算规则文件 sha256，写入 rule_bundles
    - 保存命中时填充 rule_bundle_id
  - 验证：
    - DB 中存在 rule_bundles 记录，命中关联字段非空

---

## P1（重要：提升可用性与可信度）

- [x] 09. 主机采集增强：应用/扩展/历史字段补全 + “原始 DB 证据快照”
  - Windows：InstallDate/UninstallString/DisplayIcon 等（注册表卸载项）
  - macOS：BundleID/版本号等（解析 .app/Contents/Info.plist）
  - 浏览历史：把用于解析的 DB 副本也落盘为 artifact（证据更强）
  - 浏览器扩展：补齐 manifest 名称/版本（Chrome/Edge 解析 manifest.json；Firefox 解析 extensions.json）
  - 规则匹配增强（可选）：让 matcher 利用规则中的 install_paths_windows/macos 做 direct-match（当前未实现）
  - 当前进度：
    - 已完成：`browser_history_db` artifact（zip，包含 db + -wal/-shm）已落盘并进入导出/校验链路
    - 已完成：installed_apps/browser_extension 字段补齐（name/version/bundle_id/install_date/uninstall_string 等）

- [x] 10. 审计链强校验：重算 chain_hash 并输出校验报告（不仅仅 prev_hash 连续）
  - 实现：
    - 后端 API：`POST /api/cases/{case_id}/verify/audits` 返回强校验结果（并写入一条 verify 审计记录）
    - CLI：`inspector-cli verify audits --case-id ...`（DB 内审计链强校验）
    - CLI：`inspector-cli verify forensic-zip --zip ...` 增强：若 zip 内包含 `manifest.json`，会对 manifest.audits 做强校验
  - 验证：
    - 单元测试覆盖：`internal/services/auditverify`
    - `go test ./...` PASS

- [x] 11. 隐私开关 masked 生效（展示层脱敏）
  - 实现范围（当前）：
    - internal_json/internal_html 报告：对 `snapshot_path` 与敏感命中值做展示层脱敏（URL/地址）
    - 不修改 artifacts 原始快照文件（授权人员仍可下载原始证据复核）
  - 说明：
    - masked 主要用于“对外分享/演示材料”；司法导出 ZIP/PDF 仍默认保留原始证据

- [x] 12. 规则管理最小 UI（导入/版本切换）
  - 实现：
    - API：`GET/POST /api/rules`（导入 YAML、切换 active 路径，写入 schema_meta）
    - UI：在“04 规则匹配”页提供上传并启用、下拉切换
  - 说明：
    - 当前不做“单条规则启用/禁用”的在线编辑（可通过导入不同版本 YAML 实现）

---

## P2（增强：产品化与跨平台体验）

- [ ] 13. 真桌面壳（Wails/WebView）替换“打开系统浏览器”

- [ ] 14. 安装器签名与发布链路
  - macOS：签名 + notarization
  - Windows：代码签名（减少 SmartScreen 拦截）

- [ ] 15. E2E 自动化（Playwright）：跑通“建案->采集->命中->导出->校验”的回归测试

---

## 验证项（不一定是代码缺失，但需要外部条件/设备覆盖）

- [ ] V1. Windows 原生安装器（Inno Setup）在 Windows 真机安装/卸载验证
  - 覆盖：开始菜单快捷方式、默认数据目录（`%LOCALAPPDATA%\\Crypto-Trace-Inspector\\`）、升级覆盖

- [ ] V2. Android 真机采集覆盖（不同 ROM/浏览器/权限策略）
  - 覆盖：`adb` 授权、`pm list packages`、浏览历史 provider 可达性差异
  - 预期：不可达时必须落 `precheck=skipped` + 原因/尝试明细（不做绕过）

- [ ] V3. iOS 真机备份解析覆盖（不同 iOS/加密备份差异）
  - 覆盖：`libimobiledevice` 工具链、配对/信任、加密备份处理策略（不做绕过）

- [ ] V4. 主机采集在“浏览器运行中/History DB 被锁”情况下的稳定性验证
  - 覆盖：Chrome/Edge/Firefox/Safari 正在运行时仍可通过“复制 DB + wal/shm”读取到尽量完整的记录
