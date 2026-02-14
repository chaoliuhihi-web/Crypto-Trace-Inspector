# macOS 用户验收测试用例（UAT）

目标：从“最终用户（内测调查员）”视角，验证 macOS 端产品是否能完成主闭环：

- 启动客户端（桌面壳/本地 Web UI）
- 建案 -> 采集 -> 命中 -> 证据 -> 审计 -> 报告 -> 导出 -> 离线校验

说明：

- 本项目移动端采集为 best effort，需设备授权/工具链；不做绕过/破解。
- 测试过程中产生的 `data/`、`output/`、导出包/证据快照可能包含敏感信息，禁止提交到 Git。

---

## 0. 测试准备

### 0.1 环境

- macOS 11+（建议 Apple Silicon，体验更完整）
- Go 1.24.x
- Node 20+（构建内嵌前端用）
- Xcode Command Line Tools（`lipo`/`pkgbuild`/`hdiutil`）

### 0.2 约定测试标识

- `operator`：建议统一用 `macos-uat`
- `case_no`：建议用 `UAT-<日期>-<序号>`（例如 `UAT-20260214-01`）

---

## 1. 安装与启动

### MAC-UAT-01（DMG 安装与启动）

步骤：

1. 构建安装器：
   - `VERSION=0.1.0-uat bash scripts/package_macos_installer.sh`
2. 打开 `dist/installers/macos/*.dmg`，将 `CryptoTraceInspector.app` 拖拽到 `/Applications`
3. 启动 App（双击）

预期：

- 出现客户端窗口（Apple Silicon 上为内嵌 WebView；Intel/Rosetta 可能降级为浏览器）
- `GET http://127.0.0.1:8787/api/health` 返回 `ok=true`
- 日志目录存在：`~/Library/Application Support/Crypto-Trace-Inspector/logs/`

### MAC-UAT-02（PKG 安装包结构检查）

步骤：

1. 构建安装器：
   - `VERSION=0.1.0-uat bash scripts/package_macos_installer.sh`
2. 检查 PKG payload：
   - `pkgutil --payload-files dist/installers/macos/*.pkg | rg "CryptoTraceInspector\\.app" | head`

预期：

- payload 中包含 `./Applications/CryptoTraceInspector.app/...`
- 若未配置签名证书，`pkgutil --check-signature` 显示 `no signature`（符合预期，内部试用不强制签名）

### MAC-UAT-03（Bundle 解压即用启动）

步骤：

1. 构建 bundle：
   - `VERSION=0.1.0-uat bash scripts/package_bundle.sh`
2. 进入 `dist/crypto-inspector-darwin-arm64/`
3. 执行：
   - `./start.sh`

预期：

- 能启动 UI（webview 或浏览器，取决于参数）
- 数据目录写入正常（bundle 的 `data/` 内）

---

## 2. UI 基础流程

### MAC-UAT-10（建案）

步骤：

1. 打开 UI 首页：`01 案件信息`
2. 输入 `案件编号/标题/备注`
3. 点击 `[新建案件]`

预期：

- `创建时间` 从 `-` 变为具体时间
- 左上角案件下拉框出现新案件并选中
- 页面刷新后仍能正确恢复已选案件（localStorage）

### MAC-UAT-11（只采集主机）

步骤：

1. 进入 `03 数据采集`
2. 勾选：主机；取消：Android、iOS
3. 点击 `[开始采集]`，等待完成

预期：

- 底部状态显示 `当前阶段：完成`
- `06 证据管理` 中出现 artifacts（数量 > 0）
- `05 命中分析` 中至少可看到命中汇总（命中数允许为 0，但不应报错）

### MAC-UAT-12（移动端无设备时的提示）

步骤：

1. 进入 `03 数据采集`
2. 勾选 Android 或 iOS（无设备连接/无授权情况下）
3. 点击 `[开始采集]`

预期：

- 流程不应卡死
- 在 `02 设备连接` / `报告/前置检查` 中能看到明确的 precheck 结果（skipped + reason）

---

## 3. 证据、报告与导出

### MAC-UAT-20（证据查看与下载）

步骤：

1. 进入 `06 证据管理`
2. 选择一条 artifact
3. 点击 `下载快照`

预期：

- 下载成功（HTTP 200）
- 预览 JSON 可正常显示（若为非 JSON，页面提示“无法解析”但不报错）

### MAC-UAT-21（内部报告预览）

步骤：

1. 进入 `07 报告生成`
2. 在“历史报告”中选择 `internal_html` / `internal_json`

预期：

- `internal_html` 可在 iframe 中预览
- `internal_json` 可作为文本 JSON 展示（或格式化）

### MAC-UAT-22（生成取证 PDF）

步骤：

1. 进入 `07 报告生成`
2. 点击 `[生成取证 PDF]`
3. 在“历史报告”中点击下载 `forensic_pdf`

预期：

- 成功生成并登记到 reports
- 下载成功且文件非空
- 若环境缺少 UTF-8 字体，会提示 warning，但不应导出失败

### MAC-UAT-23（生成司法导出包 ZIP + 离线校验）

步骤：

1. 进入 `07 报告生成`
2. 点击 `[生成司法导出包（ZIP）]`
3. 在“历史报告”中下载 `forensic_zip`
4. CLI 校验：
   - `go run ./cmd/inspector-cli verify forensic-zip --zip <下载的zip>`

预期：

- ZIP 中包含 `manifest.json` 与 `hashes.sha256`
- `verify forensic-zip` 结果 `failed=0`

---

## 4. 审计与校验

### MAC-UAT-30（证据 sha256 复核）

步骤：

1. 进入 `08 审计校验`
2. 点击执行 `强校验`（审计链）与 `POST /verify/artifacts`（证据校验可走 API）

预期：

- 审计链强校验返回 OK（无篡改情况下）
- 证据 sha256/size 复核全部 OK（无篡改情况下）

---

## 5. 规则管理（可选但推荐）

### MAC-UAT-40（规则导入与切换）

步骤：

1. 进入 `04 规则匹配`
2. 上传钱包规则 YAML（例如 `rules/wallet_signatures.template.yaml`）并启用
3. 上传交易所规则 YAML（例如 `rules/exchange_domains.template.yaml`）并启用

预期：

- UI 显示导入成功
- active 路径发生变化（页面底部 active wallet/exchange 显示）
- 下一次采集使用新规则（rule_bundles 版本留痕可追溯）

