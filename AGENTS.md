# AGENTS.md - Workspace Instructions (Crypto-Trace-Inspector)

This repository is the single source of truth for engineering context.

## Start Here (Required Reading Order)

Before making any change, read in this order:

1. `SOUL.md` (how to behave)
2. `USER.md` (who you are helping + preferences)
3. `MEMORY.md` (long-term project memory; curated)
4. `memory/YYYY-MM-DD.md` (today + yesterday; raw logs)
5. `TODOLIST.md` (current backlog/status)
6. `README.zh-CN.md` (product overview + run/build)
7. `docs/项目目录结构与模块接口.md` (architecture)
8. `docs/数据字典与证据字段规范.md` (schema/evidence/hit types)
9. `测试报告.md` (what was verified and how)
10. `e2e/third_party_feedback/README.md` (how to write independent QA feedback)

## Operating Rules

- Do not add secrets or personal data into this repo.
- Prefer documenting decisions in `MEMORY.md` and day-to-day progress in `memory/YYYY-MM-DD.md`.
- Keep `TODOLIST.md` accurate: when implementing an item, add a short verification note and mark it done.

## Non-Destructive Workflow

- Avoid destructive git commands (e.g. `git reset --hard`) unless explicitly requested.
- Prefer additive changes and small, reviewable commits.
