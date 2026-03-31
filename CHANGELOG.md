# Changelog for RDP-Forensic

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

