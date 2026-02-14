#!/usr/bin/env bash
set -euo pipefail

# E2E Web Server 启动脚本（给 Playwright webServer 使用）
#
# 目标：
# - 使用独立的临时数据目录（output/e2e），避免污染开发者本机 data/
# - 启动内置 Web UI/API（/api/health 可用）后由 Playwright 开始执行用例
#
# 说明：
# - webapp.Run 内部会自动执行 migrations，不需要额外 migrate
# - 端口默认为 127.0.0.1:8787（可用 E2E_LISTEN 覆盖）

GO_BIN="${GO_BIN:-$(command -v go || true)}"
if [ -z "${GO_BIN}" ] && [ -x "/Users/xinghe/go-sdk/go/bin/go" ]; then
  GO_BIN="/Users/xinghe/go-sdk/go/bin/go"
fi
if [ -z "${GO_BIN}" ]; then
  echo "go not found. Install Go 1.24+ first or export GO_BIN=/path/to/go." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

LISTEN="${E2E_LISTEN:-127.0.0.1:8787}"

E2E_ROOT="${E2E_ROOT:-output/e2e}"
DB_PATH="${E2E_DB:-$E2E_ROOT/inspector.db}"
EVIDENCE_DIR="${E2E_EVIDENCE_DIR:-$E2E_ROOT/evidence}"
IOS_BACKUP_DIR="${E2E_IOS_BACKUP_DIR:-$EVIDENCE_DIR/ios_backups}"

rm -rf "$E2E_ROOT"
mkdir -p "$E2E_ROOT"

exec "$GO_BIN" run ./cmd/inspector-cli serve \
  --listen "$LISTEN" \
  --db "$DB_PATH" \
  --evidence-dir "$EVIDENCE_DIR" \
  --ios-backup-dir "$IOS_BACKUP_DIR" \
  --wallet "rules/wallet_signatures.template.yaml" \
  --exchange "rules/exchange_domains.template.yaml" \
  --privacy-mode off
