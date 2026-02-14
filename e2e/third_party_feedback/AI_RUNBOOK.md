# 给“接手验证”的 AI：怎么继续工作

目标：不做功能开发，优先把“当前已完成的工作”做更完整的验证，并把反馈写成可复现的报告，便于主工程快速修复与回归。

## 1) 必读（按顺序）

1. `AGENTS.md`
2. `SOUL.md`
3. `USER.md`
4. `MEMORY.md`
5. `memory/YYYY-MM-DD.md`（今天 + 昨天）
6. `TODOLIST.md`
7. `测试报告.md`

## 2) 你需要跑的自动化（必须）

在仓库根目录：

```bash
go test ./...
bash scripts/e2e.sh
```

如果 E2E 失败，请优先把以下内容记录下来：

- `output/playwright/report/`
- `output/playwright/test-output/`（trace/screenshot/video）
- 失败时的服务端日志（如有）

## 3) 你应该补充的“更强测试”（建议）

### A. API 负例（不依赖真机）

目标：确认接口对非法输入返回合理错误。

建议覆盖：

- `POST /api/cases/{id}/exports/forensic-zip` 用不存在 case_id
- `POST /api/cases/{id}/verify/artifacts` 指定不存在 artifact_id
- `GET /api/reports/{id}/download` 指定不存在 report_id

### B. 手工 UI 流程（不依赖真机）

目标：发现 UI “可用性/交互问题”，尤其是新同学第一次使用时的卡点。

建议覆盖：

- 新建案件（空输入/重复点击/刷新后状态）
- 采集页面（只勾选主机/勾选移动端但无设备时的提示是否清晰）
- 命中分析（命中表格可点击、详情可读）
- 报告页（ZIP/PDF 生成提示、历史报告下载）
- 审计页（快速校验 + 强校验按钮）

### C. Windows 安装器（需要 Windows 环境）

目标：验证 EXE 安装器可用，且卸载后不残留程序文件。

建议覆盖：

- 构建 Inno Setup 安装器
- 运行冒烟脚本：
  - `scripts/windows/installer_smoke_test.ps1`
- 手工验收：
  - 开始菜单/桌面图标是否正常
  - 默认数据目录是否在 `%LOCALAPPDATA%\\Crypto-Trace-Inspector\\`

## 4) 你必须输出的反馈（提交到仓库）

请在本目录新增一份反馈文件：

- 路径：`e2e/third_party_feedback/reports/YYYY-MM-DD_<os>_<who>.md`
- 用模板：`e2e/third_party_feedback/FEEDBACK_TEMPLATE.md`

核心要求：可复现、可定位、可回归。

