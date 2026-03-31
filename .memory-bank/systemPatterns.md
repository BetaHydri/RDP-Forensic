# RDP-Forensic — System Patterns

## Architecture

`
source/
  Public/              # Exported functions (auto-discovered by ModuleBuilder)
    Get-RDPForensics.ps1        # Main forensic analysis (1526 lines)
    Get-CurrentRDPSessions.ps1  # Live session monitoring (677 lines)
  en-US/
    about_RDP-Forensic.help.txt
  RDP-Forensic.psd1    # Module manifest (source)
  RDP-Forensic.psm1    # Root module (empty — ModuleBuilder compiles)
`

## Build Pattern (Sampler)

- Source lives in `source/` with `Public/` subfolder for exported functions
- ModuleBuilder compiles into `output/module/RDP-Forensic/<version>/`
- `FunctionsToExport` is auto-populated from `source/Public/` at build time
- No `Private/`, `Classes/`, or `Enum/` folders currently in use

## Test Structure

`
Tests/
  Get-RDPForensics.Tests.ps1           # Main function unit tests
  Get-CurrentRDPSessions.Tests.ps1     # Session monitoring unit tests
  Get-RDPForensics.Correlation.Tests.ps1  # Event correlation tests
  Integration.Tests.ps1                # End-to-end integration tests (15 tests)
  PowerShellVersion.Tests.ps1          # PS version compatibility tests
  CompatibilityTest.ps1                # Manual compatibility checker
`

## Test Conventions

- All test files use BeforeAll to locate and import the built module from `output/module/`
- Use nested `Join-Path` for PS 5.1 compatibility (never 3+ args)
- Module path discovery pattern:
  `powershell
  $root = Split-Path -Parent $PSScriptRoot
  $builtModule = Get-ChildItem -Path (Join-Path (Join-Path (Join-Path $root 'output') 'module') 'RDP-Forensic') -Filter 'RDP-Forensic.psd1' -Recurse
  `

## Versioning

- GitVersion ContinuousDelivery mode
- Main branch tagged `preview`
- Feature branches: `f(eature)?/` prefix, Minor bump
- Hotfix branches: `(hot)?fix/` prefix, Patch bump
- Next version: 0.0.1
