#!/usr/bin/env bash
set -euo pipefail

# 构建 React 前端，并把 build 输出拷贝到 Go 的 go:embed 目录：
#
#   docs/产品前端规划/数字货币痕迹检测系统/  (UI 源码)
#     -> npm run build
#     -> dist/
#     -> internal/services/webapp/ui_dist/ (被 go:embed 打包进二进制)
#
# 这样最终产物在 Windows/macOS 上“解压即可运行”，不依赖 node_modules。

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UI_SRC="${UI_SRC:-$ROOT_DIR/docs/产品前端规划/数字货币痕迹检测系统}"
UI_OUT="${UI_OUT:-$ROOT_DIR/internal/services/webapp/ui_dist}"

if [ ! -d "$UI_SRC" ]; then
  echo "ui source not found: $UI_SRC" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found. Install Node.js first." >&2
  exit 1
fi

echo "[1/3] install deps (if needed)"
cd "$UI_SRC"
if [ ! -d "node_modules" ]; then
  npm install
fi

echo "[2/3] build"
npm run build

echo "[3/3] copy dist -> ui_dist (go:embed)"
rm -rf "$UI_OUT"
mkdir -p "$UI_OUT"
cp -R dist/* "$UI_OUT/"

echo "ui built and copied:"
echo "  src: $UI_SRC"
echo "  out: $UI_OUT"

