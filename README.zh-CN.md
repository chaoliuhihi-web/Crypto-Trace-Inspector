# crypto-inspector（内部试用版）

简体中文 | [English](README.md)

本仓库目标：在本地/内网环境中，对主机与移动设备进行“涉币痕迹”线索采集与规则匹配，并生成可追溯的证据快照、审计留痕与导出包，优先满足内部试用与覆盖率验证。

## 功能概览

- 主机采集（Windows/macOS）：
  - 已安装软件清单
  - 浏览器扩展（Chrome/Edge/Firefox）
  - 浏览历史（Chrome/Edge/Firefox；macOS 额外支持 Safari）
- 移动端采集（骨架/Best effort）：
  - Android：ADB 设备识别、应用包清单（需 USB 调试与授权）
  - iOS：配对/授权检查、应用清单、备份接入骨架（可尝试 `idevicebackup2`）
- 规则匹配：
  - 钱包：浏览器扩展 ID、应用关键词（置信度/判定）
  - 交易所：访问域名/URL 关键词
- 证据链与可追溯：
  - 每条证据落盘快照（`snapshot_path`）+ `sha256` + `record_hash`
  - 审计日志链式 hash（`chain_prev_hash` / `chain_hash`）
- 报告/导出：
  - 司法导出包：ZIP（`manifest.json` + `hashes.sha256` + evidence/ + reports/ + rules/）
  - 取证 PDF：二进制产物，生成后在 UI 的“历史报告”下载
- 链上余额查询（MVP）：
  - EVM 原生币余额：`eth_getBalance`（用于快速核对，不会自动写入命中/证据链）

## 目录结构（关键）

- `cmd/inspector-cli/`：CLI（扫描、查询、导出、启动 Web）
- `cmd/inspector-desktop/`：桌面启动器（启动 Web 并自动打开浏览器）
- `internal/services/webapp/`：Web UI + API（静态资源内嵌）
- `internal/adapters/store/sqlite/`：SQLite 迁移与存储
- `rules/`：规则模板（钱包/交易所）
- `docs/体验部署.md`：内测体验部署说明（更完整）

## 快速开始（开发运行）

前置：Go 1.24+

```bash
./scripts/dev_run.sh
```

构建并嵌入前端 UI（建议 clone 后执行一次）：

```bash
bash scripts/build_ui.sh
```

手工命令（可选）：

```bash
go mod tidy
go run ./cmd/inspector-cli migrate --db data/inspector.db

go run ./cmd/inspector-cli rules validate \
  --wallet rules/wallet_signatures.template.yaml \
  --exchange rules/exchange_domains.template.yaml

go run ./cmd/inspector-cli scan all \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --operator xinghe \
  --profile internal \
  --privacy-mode off

go run ./cmd/inspector-desktop \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --listen 127.0.0.1:8787
```

启动后访问（通常会自动打开）：

- `http://127.0.0.1:8787`

## 打包与分发

### 1) Bundle（解压即用）

```bash
bash scripts/package_bundle.sh
```

产物：`dist/crypto-inspector-<os>-<arch>.zip`

### 2) OS 原生安装器（推荐）

macOS（DMG/PKG）：

```bash
VERSION=0.1.0 bash scripts/package_macos_installer.sh
```

产物：

- `dist/installers/macos/*.dmg`
- `dist/installers/macos/*.pkg`

Windows（EXE 安装器，Inno Setup）：

- 参考：`installer/windows/crypto-trace-inspector.iss`
- CI：`.github/workflows/build-installers.yml`（tag `v*` 或手动触发）

安装器模式下数据目录（避免写入 Program Files/Applications）：

- macOS：`~/Library/Application Support/Crypto-Trace-Inspector/`
- Windows：`%LOCALAPPDATA%\\Crypto-Trace-Inspector\\`

## 移动端采集依赖（可选）

- Android：
  - 需要 `adb`
  - 需要设备开启 USB 调试并在主机上“允许调试/授权”
- iOS：
  - 需要 `libimobiledevice` 工具链：`idevice_id` / `idevicepair` / `ideviceinfo` / `ideviceinstaller` / `idevicebackup2`
  - 需要在设备端信任配对，并允许备份访问（否则会提示未授权/采集降级）

若工具不存在或未授权，系统会给出 precheck/warnings，不影响主机侧采集与 UI 使用。

## 文档

- 内测体验部署：`docs/体验部署.md`
- 字段与证据链规范：`docs/数据字典与证据字段规范.md`

## 使用边界（重要）

本项目仅用于具备合法授权的取证/排查场景。移动端数据采集受设备授权、系统权限与工具链能力影响，不承诺在未授权情况下获取数据。

