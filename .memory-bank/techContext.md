# RDP-Forensic — Tech Context

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | PowerShell | 5.1+ (Desktop & Core) |
| Build Framework | Sampler | 0.119.1 |
| Module Builder | ModuleBuilder | 3.1.8 |
| Test Framework | Pester | 5.7.1 |
| Versioning | GitVersion | 5.x (ContinuousDelivery) |
| CI/CD | Azure DevOps Pipelines | YAML |
| Dependency Resolver | ModuleFast | (default in Resolve-Dependency) |
| Code Analysis | PSScriptAnalyzer | 1.25.0 |
| Source Control | Git / GitHub | BetaHydri/RDP-Forensic |

## Development Setup

1. Clone: `git clone https://github.com/BetaHydri/RDP-Forensic.git`
2. Build: `./build.ps1 -ResolveDependency -Tasks build`
3. Test: `./build.ps1 -Tasks test`
4. Pack: `./build.ps1 -ResolveDependency -Tasks pack`

## Build Output

- Built module: `output/module/RDP-Forensic/<version>/`
- Test results: `output/testResults/`
- NuGet package: `output/`

## Key Constraints

- Must support PowerShell 5.1 (Windows PowerShell) and 7.x (pwsh)
- `Join-Path` with 3+ args is PS 7+ only — always use nested calls
- No PS 7-only syntax: no `??`, `?.`, `??=`, `clean {}`, pipeline chain operators
- Tests run on `windows-latest` Azure DevOps agents (no admin, no real event logs)
- ModuleFast used instead of PSResourceGet (PSResourceGet V2 has bugs with Sampler)

## Dependencies (RequiredModules.psd1)

InvokeBuild, PSScriptAnalyzer, Pester, Configuration, ModuleBuilder, ChangelogManagement, Sampler, Sampler.GitHubTasks, MarkdownLinkCheck

## Pipeline Stages

1. **Build** (ubuntu-latest): GitVersion → Build & Package → Publish artifact
2. **Test** (windows-latest):
   - Unit tests: PS7 + PS51 matrix
   - Integration tests: PS7 + PS51 matrix (WinRM configured)
   - Code Coverage: publishes JaCoCo from PS7 unit results
3. **Deploy**: Conditional on main branch or tags
