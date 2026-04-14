# Changelog for RDP-Forensic

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Removed Code of Conduct section from README.md.
- Removed Contributing section from README.md.
- Updated PowerShell Gallery badge to include prerelease version.
- Cleaned up `.gitignore` by removing unnecessary entries.

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
