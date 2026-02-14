#!/usr/bin/env bash
set -euo pipefail

# macOS 原生安装包构建脚本（内部试用/发版用）：
#
# 输出产物：
# - DMG（推荐分发方式：拖拽到 Applications）
# - PKG（“安装器”形态：双击安装到 /Applications）
#
# 说明：
# - 本项目的“桌面端”本质上是一个本地 Web UI/API 服务：
#   - 默认模式：启动服务 + 打开系统浏览器
#   - macOS 可选：`--ui webview` 以内嵌窗口方式启动（依赖系统 WebKit / CGO）
#   不引入 Wails 等重量框架，便于快速内测与离线分发。
# - 安装后运行数据不会写入 /Applications（避免权限问题），而是落在：
#     ~/Library/Application Support/Crypto-Trace-Inspector/
# - 规则文件随 App 一并打包在 .app 的 Resources/rules 中（只读）。

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

if [ "$(uname -s)" != "Darwin" ]; then
  echo "this script must run on macOS (Darwin)" >&2
  exit 1
fi

if ! command -v lipo >/dev/null 2>&1; then
  echo "lipo not found (Xcode Command Line Tools required)" >&2
  exit 1
fi
if ! command -v hdiutil >/dev/null 2>&1; then
  echo "hdiutil not found" >&2
  exit 1
fi
if ! command -v pkgbuild >/dev/null 2>&1; then
  echo "pkgbuild not found (Xcode Command Line Tools required)" >&2
  exit 1
fi

APP_NAME="${APP_NAME:-CryptoTraceInspector}"
BUNDLE_ID="${BUNDLE_ID:-com.cryptoinspector.desktop}"

# 版本信息（展示在 /api/meta；也用于安装包命名）
VERSION="${VERSION:-0.1.0-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LDFLAGS="-X crypto-inspector/internal/app.Version=$VERSION -X crypto-inspector/internal/app.Commit=$COMMIT -X crypto-inspector/internal/app.BuildTime=$BUILD_TIME"

OUT_DIR="dist/installers/macos"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"

echo "[1/5] build embedded UI (go:embed)"
bash scripts/build_ui.sh

echo "[2/5] build universal binaries (darwin/arm64 + darwin/amd64 -> lipo)"
mkdir -p "$WORK_DIR/bin"

GOOS=darwin GOARCH=arm64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WORK_DIR/bin/inspector-desktop-arm64" ./cmd/inspector-desktop
GOOS=darwin GOARCH=amd64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WORK_DIR/bin/inspector-desktop-amd64" ./cmd/inspector-desktop
lipo -create -output "$WORK_DIR/bin/inspector-desktop" "$WORK_DIR/bin/inspector-desktop-arm64" "$WORK_DIR/bin/inspector-desktop-amd64"
chmod +x "$WORK_DIR/bin/inspector-desktop"

GOOS=darwin GOARCH=arm64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WORK_DIR/bin/inspector-arm64" ./cmd/inspector-cli
GOOS=darwin GOARCH=amd64 "$GO_BIN" build -ldflags "$LDFLAGS" -o "$WORK_DIR/bin/inspector-amd64" ./cmd/inspector-cli
lipo -create -output "$WORK_DIR/bin/inspector" "$WORK_DIR/bin/inspector-arm64" "$WORK_DIR/bin/inspector-amd64"
chmod +x "$WORK_DIR/bin/inspector"

echo "[3/5] build .app bundle"
APP_DIR="$OUT_DIR/${APP_NAME}.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources/rules"

cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
</dict>
</plist>
EOF

# 启动器：确保 data 目录可写，规则路径可定位，并把日志落盘便于排障。
cat > "$APP_DIR/Contents/MacOS/${APP_NAME}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RES="$(cd "$HERE/../Resources" && pwd)"

DATA_ROOT="${HOME}/Library/Application Support/Crypto-Trace-Inspector"
DATA_DIR="${DATA_ROOT}/data"
LOG_DIR="${DATA_ROOT}/logs"

mkdir -p "$DATA_DIR/evidence/ios_backups" "$LOG_DIR"

exec "$RES/inspector-desktop" \
  --ui webview \
  --listen 127.0.0.1:8787 \
  --db "$DATA_DIR/inspector.db" \
  --evidence-dir "$DATA_DIR/evidence" \
  --ios-backup-dir "$DATA_DIR/evidence/ios_backups" \
  --wallet "$RES/rules/wallet_signatures.template.yaml" \
  --exchange "$RES/rules/exchange_domains.template.yaml" \
  >> "$LOG_DIR/inspector-desktop.log" 2>&1
EOF
chmod +x "$APP_DIR/Contents/MacOS/${APP_NAME}"

cp "$WORK_DIR/bin/inspector-desktop" "$APP_DIR/Contents/Resources/inspector-desktop"
cp "$WORK_DIR/bin/inspector" "$APP_DIR/Contents/Resources/inspector"
chmod +x "$APP_DIR/Contents/Resources/inspector-desktop" "$APP_DIR/Contents/Resources/inspector"

cp "rules/wallet_signatures.template.yaml" "$APP_DIR/Contents/Resources/rules/"
cp "rules/exchange_domains.template.yaml" "$APP_DIR/Contents/Resources/rules/"

if [ -f "docs/体验部署.md" ]; then
  cp "docs/体验部署.md" "$APP_DIR/Contents/Resources/README_DEPLOY.md"
fi

if [ -n "${MACOS_CODESIGN_IDENTITY:-}" ]; then
  if ! command -v codesign >/dev/null 2>&1; then
    echo "codesign not found (Xcode Command Line Tools required)" >&2
    exit 1
  fi
  echo "[3.5/5] codesign .app bundle (optional)"
  # 先签内置二进制，再签整个 App（--deep 处理嵌套资源）。
  codesign --force --timestamp --options runtime --sign "$MACOS_CODESIGN_IDENTITY" "$APP_DIR/Contents/Resources/inspector-desktop"
  codesign --force --timestamp --options runtime --sign "$MACOS_CODESIGN_IDENTITY" "$APP_DIR/Contents/Resources/inspector"
  codesign --force --timestamp --options runtime --deep --sign "$MACOS_CODESIGN_IDENTITY" "$APP_DIR"
fi

echo "[4/5] create DMG (drag-to-install)"
DMG_TMP="$WORK_DIR/dmgroot"
mkdir -p "$DMG_TMP"
cp -R "$APP_DIR" "$DMG_TMP/"
ln -s /Applications "$DMG_TMP/Applications"

DMG_PATH="$OUT_DIR/${APP_NAME}-${VERSION}-macos-universal.dmg"
rm -f "$DMG_PATH"
hdiutil create -volname "$APP_NAME" -srcfolder "$DMG_TMP" -ov -format UDZO "$DMG_PATH" >/dev/null

echo "[5/5] create PKG (installer)"
PKG_ROOT="$WORK_DIR/pkgroot"
mkdir -p "$PKG_ROOT/Applications"
cp -R "$APP_DIR" "$PKG_ROOT/Applications/"

PKG_PATH="$OUT_DIR/${APP_NAME}-${VERSION}-macos-universal.pkg"
rm -f "$PKG_PATH"
if [ -n "${MACOS_PKG_SIGN_IDENTITY:-}" ]; then
  pkgbuild \
    --root "$PKG_ROOT" \
    --install-location "/" \
    --identifier "$BUNDLE_ID" \
    --version "$VERSION" \
    --sign "$MACOS_PKG_SIGN_IDENTITY" \
    "$PKG_PATH" >/dev/null
else
  pkgbuild \
    --root "$PKG_ROOT" \
    --install-location "/" \
    --identifier "$BUNDLE_ID" \
    --version "$VERSION" \
    "$PKG_PATH" >/dev/null
fi

if [ -n "${MACOS_NOTARY_KEYCHAIN_PROFILE:-}" ]; then
  if ! command -v xcrun >/dev/null 2>&1; then
    echo "xcrun not found (Xcode Command Line Tools required)" >&2
    exit 1
  fi
  echo "[optional] notarize DMG/PKG (notarytool)"
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$MACOS_NOTARY_KEYCHAIN_PROFILE" --wait
  xcrun stapler staple "$DMG_PATH" || true
  xcrun notarytool submit "$PKG_PATH" --keychain-profile "$MACOS_NOTARY_KEYCHAIN_PROFILE" --wait
  xcrun stapler staple "$PKG_PATH" || true
fi

echo "macOS installers ready:"
echo "  app: $APP_DIR"
echo "  dmg: $DMG_PATH"
echo "  pkg: $PKG_PATH"
