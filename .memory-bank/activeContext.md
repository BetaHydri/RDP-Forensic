# RDP-Forensic — Active Context

## Current Focus

Pipeline stabilization — migrated to Sampler build framework and fixing CI/CD.

## Recent Changes (2026-03-31)

- Migrated to Sampler 0.119.1 build framework (source/ structure, ModuleBuilder)
- Switched from PSResourceGet to ModuleFast for dependency resolution
- Fixed all test files for PS 5.1 compatibility (nested Join-Path)
- Added PS7 + PS51 matrix strategy to Azure Pipelines (Unit & Integration jobs)
- Fixed Integration test Module Loading section to use built module
- GitVersion.yml: master → main

## Pending

- Push to GitHub and verify pipeline passes end-to-end
- Integration tests may fail on CI (no admin, no real RDP event logs) — may need mocking
- Code coverage threshold set at 85% for unit tests — verify coverage is sufficient
- CHANGELOG.md has no entries yet (only template)
- Deploy stage not yet tested

## Active Decisions

- ModuleFast over PSResourceGet (V2 bug workaround)
- Code coverage collected from PS7 unit tests only (not PS51)
- Integration tests run with CodeCoverageThreshold 0

## References

- See [techContext.md](techContext.md) for build commands and pipeline details
- See [systemPatterns.md](systemPatterns.md) for test conventions
