# RDP-Forensic — Product Context

## Why This Project Exists

Organizations need to investigate RDP activity for security incidents, compliance audits, and forensic analysis. Native Windows tools (Event Viewer, Get-EventLog) require manual querying across multiple log sources with no correlation. This module automates and correlates the entire RDP lifecycle from network connection to logoff.

## Problems Solved

- **Manual event correlation**: Combines 5+ event log sources into unified timeline
- **Brute force detection**: Automatically identifies repeated failed auth attempts
- **Session lifecycle gaps**: Tracks the full chain: connect → auth → logon → disconnect → logoff
- **Incident response speed**: Pre-built forensic workflows replace hours of manual investigation
- **Real-time visibility**: Live monitoring of current RDP sessions with change logging

## Target Users

- Security analysts performing incident response
- System administrators auditing RDP access
- Forensic investigators reconstructing attack timelines
- Compliance teams verifying remote access policies

## UX Goals

- Single command (Get-RDPForensics) to get complete RDP forensic data
- Filterable output (User, IP, Date, LogonID, SessionID)
- CSV export for downstream analysis
- Live monitoring mode (Get-CurrentRDPSessions) with auto-refresh
- Works offline — no internet or external services required
- Lightweight (~25KB), copy-and-run deployment
