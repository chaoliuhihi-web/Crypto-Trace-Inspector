#!/usr/bin/env bash
set -euo pipefail

# 体验部署打包脚本：
# - 生成可直接解压运行的离线目录（包含二进制 + rules + 启动脚本）
# - 同时生成 zip 包（如果系统存在 zip 命令）

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

DARWIN_DIR="dist/crypto-inspector-darwin-arm64"
WIN_DIR="dist/crypto-inspector-windows-amd64"

rm -rf "$DARWIN_DIR" "$WIN_DIR"
mkdir -p "$DARWIN_DIR" "$WIN_DIR"

# 版本信息（展示在 /api/meta；也方便后续对外发版）
VERSION="${VERSION:-0.1.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LDFLAGS="-X crypto-inspector/internal/app.Version=$VERSION -X crypto-inspector/internal/app.Commit=$COMMIT -X crypto-inspector/internal/app.BuildTime=$BUILD_TIME"

echo "[1/5] build embedded UI"
bash scripts/build_ui.sh

echo "[2/5] build binaries"
GOOS=darwin GOARCH=arm64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$DARWIN_DIR/inspector" ./cmd/inspector-cli
GOOS=darwin GOARCH=arm64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$DARWIN_DIR/inspector-desktop" ./cmd/inspector-desktop
GOOS=windows GOARCH=amd64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WIN_DIR/inspector.exe" ./cmd/inspector-cli
GOOS=windows GOARCH=amd64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WIN_DIR/inspector-desktop.exe" ./cmd/inspector-desktop

echo "[3/5] copy rules and docs"
cp -R rules "$DARWIN_DIR/rules"
cp -R rules "$WIN_DIR/rules"

mkdir -p "$DARWIN_DIR/data" "$WIN_DIR/data"

if [ -f "docs/体验部署.md" ]; then
  cp "docs/体验部署.md" "$DARWIN_DIR/README_DEPLOY.md"
  cp "docs/体验部署.md" "$WIN_DIR/README_DEPLOY.md"
fi

echo "[4/5] write start scripts"
cat > "$DARWIN_DIR/start.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
./inspector-desktop \
  --listen 127.0.0.1:8787 \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --ios-backup-dir data/evidence/ios_backups
EOF
chmod +x "$DARWIN_DIR/start.sh"

cat > "$WIN_DIR/start.ps1" <<'EOF'
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
.\inspector-desktop.exe `
  --listen 127.0.0.1:8787 `
  --db data\inspector.db `
  --evidence-dir data\evidence `
  --ios-backup-dir data\evidence\ios_backups
EOF

echo "[5/5] zip bundles (if zip exists)"
if command -v zip >/dev/null 2>&1; then
  (cd dist && zip -qr "crypto-inspector-darwin-arm64.zip" "crypto-inspector-darwin-arm64")
  (cd dist && zip -qr "crypto-inspector-windows-amd64.zip" "crypto-inspector-windows-amd64")
  echo "zip ready: dist/crypto-inspector-*.zip"
else
  echo "zip not found, skip. bundles are in dist/ directories"
fi

echo "bundle ready:"
echo "  $DARWIN_DIR"
echo "  $WIN_DIR"
