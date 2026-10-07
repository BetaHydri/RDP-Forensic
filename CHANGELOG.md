# Changelog for RDP-Forensic

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.3] - 2026-10-07

### Fixed

- Corrected PowerShell Gallery links in `README.md`.

## [2.2.2] - 2026-05-27

### Added

- Added `info` emoji to the emoji map for both PowerShell 5.1 and 7.x.
- Added `[ValidateNotNullOrEmpty()]` attribute to `-DomainController` parameter
  to reject empty strings early with a clear error message.
- Added visible info message when `-DomainController` or `-AllDomainControllers`
  implicitly enables `-IncludeCredentialValidation`.
- Added comprehensive DC query parameter documentation to README explaining
  when to use `-IncludeCredentialValidation` vs `-DomainController` vs
  `-AllDomainControllers` with Kerberos/NTLM coverage comparison table.
- Added `-GroupBySession` sample output and LogonType explanation to README
  and GETTING_STARTED.md.

## [2.2.1] - 2026-05-27

### Fixed

- Fixed variable name collision where inner `$sourceIP` assignments in nested
  parsing functions overwrote the `-SourceIP` parameter (PowerShell variables
  are case-insensitive). This caused the `-SourceIP` filter to always apply
  with the last parsed event's source IP, even when not specified by the user.
  Renamed all inner usages to `$eventSourceIP`.

## [2.2.0] - 2026-05-27

### Added

- Added `-DomainController` parameter to query specific Domain Controller(s)
  for Kerberos (4768-4772) and NTLM (4776) pre-authentication events remotely.
- Added `-AllDomainControllers` switch to query ALL DCs in the domain for
  complete pre-authentication event coverage.
- Added automatic secure channel DC discovery via `nltest /sc_query` when
  `-IncludeCredentialValidation` is used without explicit DC parameters.
- Added WinRM (Invoke-Command) transport with automatic RPC/DCOM fallback
  for Domain Controller event queries.
- Added DC hostname in parsed event Details for traceability.
- Added DC target display in analysis header output.
- Added `Get-RDPForensics.DomainController.Tests.ps1` test file with
  comprehensive parameter, parsing, and compatibility tests.
- Added scenarios 19-21 to `Examples.ps1` for DC query workflows.

### Changed

- `-IncludeCredentialValidation` no longer requires running on a Domain
  Controller. The tool now queries DCs remotely from any Terminal Server.
- `-DomainController` and `-AllDomainControllers` implicitly enable
  `-IncludeCredentialValidation`.
- Updated `KERBEROS_NTLM_AUTHENTICATION.md` documentation to reflect
  remote DC query capability and removed DC-only constraint.
- Updated `GETTING_STARTED.md` and `QUICK_REFERENCE.md` with new
  DC query parameters and examples.

## [2.1.3] - 2026-03-31

### Changed

- Replaced manual `Import-Module .\RDP-Forensic.psm1` with
  `Install-Module` in all documentation and examples.
- Removed outdated `NEW v1.0.x` labels from examples.
- Replaced deprecated `Get-EventLog` with `Get-WinEvent` in
  Quick Reference guide.
- Fixed `.AllEvents` to `.Events` property name in Kerberos/NTLM
  authentication documentation.
- Removed hardcoded version `1.0.8` from `Examples.ps1`.
- Updated file structure description from "5 files" to module cmdlets.
- Fixed relative link paths in Kerberos/NTLM See Also section.
- Renamed "Scripts" section to "Cmdlets" in README.

## [2.1.1] - 2026-03-31

### Changed

- Increased code coverage from ~26% to ~74% with comprehensive mock-based
  Pester tests for all internal parsing functions of `Get-RDPForensics`.

## [2.1.0] - 2026-03-31

### Changed

- Renamed `Get-CurrentRDPSessions` to `Get-RDPCurrentSessions` to follow
  PowerShell verb-noun naming conventions and align with the module prefix
  pattern - **BREAKING CHANGE**.
- Refactored `Get-RDPForensics` with modular internal functions:
  `Get-CorrelatedSessions`, `Get-RDPConnectionAttempts`,
  `Get-RDPAuthenticationEvents`, `Get-RDPSessionEvents`,
  `Get-RDPLockUnlockEvents`, `Get-RDPSessionReconnectEvents`,
  `Get-RDPLogoffEvents`, and `Get-OutboundRDPConnections`.
- Updated all documentation, examples, integration tests, and references to
  use the new `Get-RDPCurrentSessions` name.

### Added

- Added `-ShowProcesses` parameter to `Get-RDPCurrentSessions` to display
  running processes per session.
- Added `-Watch` and `-RefreshInterval` parameters for continuous monitoring
  mode.
- Added `-LogPath` parameter for session logging.

## [2.0.0] - 2026-03-31

### Added

- For new features.

### Changed

- For changes in existing functionality.

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- For any bug fix.

### Security

- In case of vulnerabilities.
