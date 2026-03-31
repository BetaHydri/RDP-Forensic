# RDP-Forensic — Prompt History

## 2026-03-31

- **Pipeline fix: Integration test failures** — Fixed `Join-Path` PS 5.1 compat across all 5 test files, fixed Integration Module Loading section, set `pwsh: true` for integration job
- **Dual PS version testing** — Added strategy matrix (PS7/PS51) to Unit and Integration jobs in azure-pipelines.yml
- **PS7 syntax investigation** — Confirmed source files have no PS7-only syntax (no `??`, `?.`, `clean {}`, etc.)
- **Memory Bank creation** — Created `.memory-bank/` with all core files
