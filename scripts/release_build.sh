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

mkdir -p dist

GOOS=darwin GOARCH=arm64 "$GO_BIN" build -o dist/inspector-cli-darwin-arm64 ./cmd/inspector-cli
GOOS=windows GOARCH=amd64 "$GO_BIN" build -o dist/inspector-cli-windows-amd64.exe ./cmd/inspector-cli

echo "build artifacts in dist/"
