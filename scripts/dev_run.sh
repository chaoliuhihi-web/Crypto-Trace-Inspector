#!/usr/bin/env bash
set -euo pipefail

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

echo "[1/3] go mod tidy"
"$GO_BIN" mod tidy

echo "[2/3] run migrations"
"$GO_BIN" run ./cmd/inspector-cli migrate --db data/inspector.db

echo "[3/3] validate rules"
"$GO_BIN" run ./cmd/inspector-cli rules validate \
  --wallet rules/wallet_signatures.template.yaml \
  --exchange rules/exchange_domains.template.yaml

echo "[optional] run host scan"
"$GO_BIN" run ./cmd/inspector-cli scan host \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --operator dev \
  --auth-order DEV-TEST-ORDER || true

echo "done"
