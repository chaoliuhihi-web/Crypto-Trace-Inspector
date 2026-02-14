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

- [ ] 09. 主机采集增强：应用/扩展/历史字段补全 + “原始 DB 证据快照”
  - Windows：InstallDate/UninstallString 等
  - macOS：BundleID/版本号等
  - 浏览历史：把用于解析的 DB 副本也落盘为 artifact（证据更强）
  - 当前进度：
    - 已完成：`browser_history_db` artifact（zip，包含 db + -wal/-shm）已落盘并进入导出/校验链路
    - 待完成：Windows/macOS 应用字段补全、扩展字段补全

- [x] 10. 审计链强校验：重算 chain_hash 并输出校验报告（不仅仅 prev_hash 连续）
  - 实现：
    - 后端 API：`POST /api/cases/{case_id}/verify/audits` 返回强校验结果（并写入一条 verify 审计记录）
    - CLI：`inspector-cli verify audits --case-id ...`（DB 内审计链强校验）
    - CLI：`inspector-cli verify forensic-zip --zip ...` 增强：若 zip 内包含 `manifest.json`，会对 manifest.audits 做强校验
  - 验证：
    - 单元测试覆盖：`internal/services/auditverify`
    - `go test ./...` PASS

- [ ] 11. 隐私开关 masked 真正生效（仅对 external/profile 生效；内部默认 off）

- [ ] 12. 规则管理（导入/启用禁用/版本切换）最小 UI

---

## P2（增强：产品化与跨平台体验）

- [ ] 13. 真桌面壳（Wails/WebView）替换“打开系统浏览器”

- [ ] 14. 安装器签名与发布链路
  - macOS：签名 + notarization
  - Windows：代码签名（减少 SmartScreen 拦截）

- [ ] 15. E2E 自动化（Playwright）：跑通“建案->采集->命中->导出->校验”的回归测试
