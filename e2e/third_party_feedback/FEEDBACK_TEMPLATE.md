# 第三方测试反馈模板

## 1. 环境信息

- 日期：
- 测试人/AI：
- OS：
- CPU 架构：
- Go：`go version`
- Node：`node -v` / `npm -v`
- 浏览器（如涉及 UI/E2E）：Playwright chromium version

## 2. 测试范围

- 目标分支/提交：`git log -1 --oneline`
- 覆盖模块：
  - [ ] 主机采集（host scan）
  - [ ] 移动采集（mobile scan）
  - [ ] 命中分析（hits）
  - [ ] 司法导出 ZIP
  - [ ] PDF 报告
  - [ ] 审计强校验
  - [ ] 证据 sha256 复核
  - [ ] 安装器（如有）

## 3. 执行命令与结果

### 3.1 go test

命令：

```bash
go test ./...
```

结果：

- PASS/FAIL：
- 失败用例（如有）：

### 3.2 E2E（Playwright）

命令：

```bash
bash scripts/e2e.sh
```

结果：

- PASS/FAIL：
- 报告目录：`output/playwright/report/`
- 失败截图/trace（如有）：`output/playwright/test-output/`

### 3.3 安装器（如适用）

Windows（安装器冒烟）：

```powershell
.\scripts\windows\installer_smoke_test.ps1 -InstallerPath <path-to-installer.exe>
```

结果：

- PASS/FAIL：
- 关键输出：

## 4. 问题清单（按优先级）

### P0（阻断使用）

- 问题：
- 复现步骤：
- 预期：
- 实际：
- 相关日志/截图/文件路径：

### P1（影响体验/可信度）

- ...

### P2（建议/优化）

- ...

## 5. 结论与建议

- 总体结论：
- 建议下一步：

