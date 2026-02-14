#!/usr/bin/env bash
set -euo pipefail

# 一键 E2E（Playwright）回归：
# - 自动安装 e2e/ 目录下的 Node 依赖（npm ci）
# - 安装 Playwright 浏览器（chromium）
# - 启动 Web UI/API（由 Playwright webServer 负责）并执行用例
#
# 说明：
# - 默认使用 output/ 目录存放 E2E 运行数据与 Playwright 报告（已在 .gitignore 中忽略）
# - 如本机 go 不在 PATH，可 export GO_BIN=/path/to/go

GO_BIN="${GO_BIN:-$(command -v go || true)}"
if [ -z "${GO_BIN}" ] && [ -x "/Users/xinghe/go-sdk/go/bin/go" ]; then
  GO_BIN="/Users/xinghe/go-sdk/go/bin/go"
fi
if [ -z "${GO_BIN}" ]; then
  echo "go not found. Install Go 1.24+ first or export GO_BIN=/path/to/go." >&2
  exit 1
fi
export GO_BIN

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR/e2e"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found. Install Node.js first." >&2
  exit 1
fi

echo "[1/3] npm ci"
npm ci

echo "[2/3] install playwright browsers (chromium)"
npx playwright install chromium

echo "[3/3] run playwright tests"
npx playwright test

