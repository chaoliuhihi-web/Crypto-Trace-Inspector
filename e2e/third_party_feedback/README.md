# 第三方测试反馈（third_party_feedback）

目标：为“其他 AI/测试同学”提供一个固定入口，用于对当前仓库做更完整的验证，并把发现的问题/建议以可复现的形式回灌到仓库中，方便后续快速修复与回归。

## 1. 你应该先读什么（避免跑偏）

按顺序阅读（都在仓库根目录）：

1. `AGENTS.md`
2. `SOUL.md`
3. `USER.md`
4. `MEMORY.md`
5. `memory/YYYY-MM-DD.md`（今天 + 昨天）
6. `TODOLIST.md`
7. `测试报告.md`

## 2. 你应该做什么（建议的验证范围）

最小回归（强烈建议每次都做）：

1. `go test ./...`
2. `bash scripts/e2e.sh`（Playwright：建案 -> 采集 -> 导出 ZIP -> verify）

增强验证（建议按平台补齐）：

- Windows：
  - 构建 Inno Setup 安装器并执行静默安装/启动/卸载冒烟（见 `scripts/windows/installer_smoke_test.ps1`）
- macOS：
  - 构建 DMG/PKG 并实际启动一次（`scripts/package_macos_installer.sh`）
- 手工 UI 验收：
  - 报告页：ZIP/PDF 生成与下载
  - 审计页：强校验（`/verify/audits`）是否可用
  - 证据页：证据下载与 JSON 预览

## 3. 反馈应该怎么写（务必可复现）

请在本目录下新增一份反馈文件（建议放到 `reports/`）：

- 路径：`e2e/third_party_feedback/reports/YYYY-MM-DD_<os>_<who>.md`
- 模板：`e2e/third_party_feedback/FEEDBACK_TEMPLATE.md`

要求：

- 写清楚 OS/版本、Go/Node 版本、运行命令、实际输出（关键片段即可）。
- 如果是 bug，必须包含：
  - 复现步骤
  - 预期 vs 实际
  - 最小日志/截图/导出包（如适用）的位置

## 4. 产出物不要提交什么

不要把以下内容提交到 Git：

- 真实证据原始数据、个人隐私数据
- `data/`、`output/` 目录下的大体量运行产物（已在 `.gitignore` 忽略）
- 任何密钥/证书

