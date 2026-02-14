# MEMORY.md (Long-Term Project Memory)

This file is a curated, long-term memory for the project. Keep it free of secrets and personal data.

## Project Goal

- Build a local/intranet tool for crypto-trace collection and rule matching, producing verifiable evidence artifacts, audit-chain logs, and export packages.

## Key Decisions (High Signal)

- Mobile acquisition is **best effort** and **authorized-only**:
  - No bypass/cracking/unauthorized access.
  - When prerequisites are missing, record `precheck=skipped` with the reasons and attempted steps.

- "Privacy mode" is a **report-layer masking** feature:
  - It masks values in internal reports (HTML/JSON) for sharing.
  - It does not mutate raw evidence artifacts (snapshots remain intact for authorized reviewers).

- Windows is the primary host OS; macOS is supported. Linux is not in scope currently.

## Current State Snapshot (as of 2026-02-14)

- P0/P1 feature loop is mostly complete (scan -> hits -> artifacts -> reports -> forensic zip -> verify).
- Remaining gaps are mainly P2 productization items:
  - True desktop shell (embedded webview, e.g. Wails).
  - Signing/notarization/release pipeline.
  - E2E automated regression (Playwright).

