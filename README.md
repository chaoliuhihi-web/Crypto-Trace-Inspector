# crypto-inspector (scaffold)

English | [简体中文](README.zh-CN.md)

This repository now includes:

- CLI entry: `cmd/inspector-cli`
- Desktop launcher (start webapp + auto open browser): `cmd/inspector-desktop`
- SQLite migrator with embedded SQL: `internal/adapters/store/sqlite`
- Rule loader + validation: `internal/adapters/rules`
- Rule templates:
  - `rules/wallet_signatures.template.yaml`
  - `rules/exchange_domains.template.yaml`
- Web UI + API (embedded static files): `internal/services/webapp`
- UI source (React/Vite, internal trial): `docs/产品前端规划/数字货币痕迹检测系统`

## Quick Start

Prerequisite: Go 1.24+

```bash
./scripts/dev_run.sh
```

Build embedded UI (recommended once after cloning):

```bash
bash scripts/build_ui.sh
```

Manual commands:

```bash
go mod tidy
go run ./cmd/inspector-cli migrate --db data/inspector.db
go run ./cmd/inspector-cli rules validate \
  --wallet rules/wallet_signatures.template.yaml \
  --exchange rules/exchange_domains.template.yaml
go run ./cmd/inspector-cli scan host \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --operator xinghe
go run ./cmd/inspector-cli scan mobile \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --ios-backup-dir data/evidence/ios_backups \
  --operator xinghe

# One-click internal trial (maximum collection, best effort)
go run ./cmd/inspector-cli scan all \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --operator xinghe \
  --profile internal \
  --privacy-mode off

# Web UI (internal trial)
go run ./cmd/inspector-cli serve \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --listen 127.0.0.1:8787

# Desktop launcher (recommended)
go run ./cmd/inspector-desktop \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --listen 127.0.0.1:8787

# External/strict mode switches
go run ./cmd/inspector-cli scan all \
  --db data/inspector.db \
  --evidence-dir data/evidence \
  --operator xinghe \
  --auth-order AUTH-2026-0001 \
  --auth-basis "warrant-001" \
  --profile external \
  --privacy-mode masked

# Query interfaces for UI
go run ./cmd/inspector-cli query host-hits \
  --db data/inspector.db \
  --case-id <CASE_ID> \
  --json=true
go run ./cmd/inspector-cli query report \
  --db data/inspector.db \
  --case-id <CASE_ID> \
  --content=true \
  --json=true
```

## Build

```bash
./scripts/release_build.sh
```

## Bundle (Installable Trial)

```bash
./scripts/package_bundle.sh
```

## Native Installers (macOS/Windows)

- macOS (DMG/PKG):

```bash
VERSION=0.1.0 bash scripts/package_macos_installer.sh
```

- Windows (EXE installer via Inno Setup): see `installer/windows/crypto-trace-inspector.iss`.

See: `docs/体验部署.md`.
