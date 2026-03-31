# RDP-Forensic — Project Brief

## Purpose

Comprehensive PowerShell toolkit for RDP forensic analysis, tracking connection attempts, authentication, sessions, and logoffs across Windows Event Logs for security monitoring and incident response.

## Core Requirements

- Analyze RDP connections across all lifecycle stages (Network, Credentials, Auth, Logon, Lock/Unlock, Disconnect/Reconnect, Logoff)
- Correlate events from 5+ Windows Event Log sources (Security, TerminalServices-LocalSessionManager, TerminalServices-RemoteConnectionManager, System)
- Filter by User, IP, Date range, LogonID, SessionID
- Detect brute force attacks
- Monitor current live RDP sessions with auto-refresh
- Export results to CSV and summary reports
- Support both PowerShell 5.1 (Desktop) and 7.x (Core)

## Scope

- **In scope**: Windows Event Log analysis, RDP session lifecycle tracking, forensic reporting, real-time monitoring
- **Out of scope**: Linux/macOS, non-RDP remote access, network-level packet capture

## Key Event IDs

| Stage | Event IDs |
|-------|-----------|
| Network Connection | 1149 |
| Credential Submission | 4648 |
| Authentication | 4624, 4625 |
| Logon | 21, 22 |
| Lock/Unlock | 4800, 4801 |
| Disconnect/Reconnect | 24, 25, 39, 40, 4778, 4779 |
| Logoff | 23, 4634, 4647, 9009 |

## Author

Jan Tiedemann (BetaHydri)
