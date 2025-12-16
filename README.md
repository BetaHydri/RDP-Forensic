# RDP Forensics Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.6-brightgreen)
![Requires Admin](https://img.shields.io/badge/Requires-Administrator-red)
![Event Logs](https://img.shields.io/badge/Event%20Logs-Security%20%7C%20TerminalServices-orange)

A comprehensive PowerShell toolkit for analyzing and tracking Remote Desktop Protocol (RDP) connections in Windows environments. This toolkit follows forensic best practices as documented in the Windows OS Hub RDP forensics guide.

## Why This Toolkit?

This is the **only comprehensive, open-source PowerShell-native RDP forensics solution** available. Unlike basic event log queries or expensive commercial tools, this toolkit provides complete lifecycle tracking, multiple log source correlation, and production-ready forensic capabilities.

### Comparison Matrix

| Feature | This Toolkit | Basic PowerShell<br/>(Get-EventLog) | Manual Event Viewer |
|---------|--------------|-------------------------------------|---------------------|
| **Cost** | ✅ Free & Open Source | ✅ Built-in | ✅ Built-in |
| **Event Coverage** | ✅ 15+ Event IDs | ⚠️ Manual queries | ⚠️ Manual filtering |
| **Multi-Log Correlation** | ✅ 5 log sources | ❌ One at a time | ❌ Manual switching |
| **Event Correlation** | ✅ Session grouping by LogonID | ❌ No | ❌ No |
| **Lifecycle Tracking** | ✅ 6 stages | ❌ No | ❌ No |
| **Brute Force Detection** | ✅ Built-in | ❌ Manual analysis | ❌ No |
| **Session Duration Analysis** | ✅ Automatic | ❌ No | ❌ No |
| **Export Capabilities** | ✅ CSV + Summary | ⚠️ Basic | ⚠️ Manual export |
| **Real-time Monitoring** | ✅ Current sessions | ❌ No | ⚠️ Limited |
| **Filtering** | ✅ User/IP/Date | ⚠️ Basic Where-Object | ⚠️ Basic |
| **Documentation** | ✅ Comprehensive | ⚠️ Microsoft Docs | ⚠️ Basic |
| **Learning Curve** | ✅ Low (examples included) | ⚠️ Medium | ✅ Low |
| **Deployment** | ✅ Copy & run | ✅ Built-in | ✅ Built-in |
| **Customization** | ✅ Full source access | ✅ Script yourself | ❌ No |
| **Forensic Focus** | ✅ Purpose-built | ❌ General purpose | ❌ General purpose |
| **Incident Response** | ✅ Ready-to-use scenarios | ❌ DIY | ❌ Manual |
| **No Internet Required** | ✅ Offline capable | ✅ Yes | ✅ Yes |
| **Script Size** | ✅ Lightweight (~25KB) | N/A | N/A |

### Key Differentiators

**vs. Basic PowerShell Commands:**
- 🎯 Pre-built forensic workflows instead of manual queries
- 🔍 Correlates 5 different log sources automatically
- 📊 Generates summary statistics and reports
- 🛡️ Built-in brute force attack detection
- 📝 Comprehensive event parsing (no regex needed)
- 📺 **Real-time session monitoring with auto-refresh**
- 📝 **Automatic change logging for forensic analysis**

**vs. Manual Event Viewer:**
- ⚡ Automated collection across multiple logs
- 🔗 Correlates events by LogonID and SessionID
- 📈 Statistical analysis and trending
- 💾 Export to formats suitable for analysis
- ⏱️ Saves hours of manual investigation time
- 🔴 **Live monitoring mode** - tracks sessions in real-time
- 📋 **Change detection** - logs new/ended sessions and state changes

## Overview

This toolkit provides detailed analysis of RDP connections across all connection stages:

1. **Network Connection** - Initial RDP connection attempts (EventID 1149)
2. **Authentication** - Successful and failed authentication (EventID 4624, 4625)
3. **Logon** - Session establishment (EventID 21, 22)
4. **Lock/Unlock** - Workstation lock state changes (EventID 4800, 4801)
5. **Disconnect/Reconnect** - Session state changes (EventID 24, 25, 39, 40, 4778, 4779)
6. **Logoff** - Session termination (EventID 23, 4634, 4647, 9009)

## Scripts

### RDP-Forensic.psm1

The main forensics analysis cmdlet (Get-RDPForensics) collects and analyzes RDP connection logs from multiple Windows Event Log sources.

**Features:**
- Collects events from Security, TerminalServices, and System logs
- **Event Correlation** - Groups events by LogonID/SessionID across all log sources
- **Session Lifecycle Tracking** - Visualizes complete session stages (connection → auth → logon → active → disconnect → logoff)
- **Session Duration Analysis** - Calculates actual session time
- Filters by date range, username, or source IP
- Exports results to CSV format (events + sessions)
- Generates summary reports
- Supports outbound RDP connection tracking
- **Real-time Monitoring** - Watch mode with auto-refresh
- **Change Logging** - Tracks session state changes to CSV

**Requirements:**
- Windows Server 2012 R2 or later / Windows 8.1 or later
- Administrator privileges (required to read Security event logs)
- PowerShell 5.1 or later
- **Windows Audit Policies enabled** (see below)

**Audit Policy Requirements:**

Most RDP events (1149, 21-25, 39, 40, 9009) are logged by default in Terminal Services Operational logs. However, **Security log events require specific audit policies** to be enabled:

**Events requiring audit policies:**
- EventID 4624, 4625 (Logon/Failed Logon) - Requires "Audit Logon Events"
- EventID 4634, 4647 (Logoff) - Requires "Audit Logon Events"
- EventID 4778, 4779 (Session Reconnect/Disconnect) - Requires "Audit Other Logon/Logoff Events"
- EventID 4800, 4801 (Workstation Lock/Unlock) - Requires "Audit Other Logon/Logoff Events"

**Enable via PowerShell (recommended):**
```powershell
# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Verify settings
auditpol /get /category:"Logon/Logoff"
```

**Enable via Group Policy (for domain environments):**
```
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Logon/Logoff

Enable:
- Audit Logon (Success, Failure)
- Audit Logoff (Success)
- Audit Other Logon/Logoff Events (Success, Failure)
```

**Note:** Most Windows systems have logon auditing enabled by default. The tool will still work without these policies, but event correlation may be less complete (missing 4624/4634/4778/4779 events).

**PowerShell 5.1 & 7.x Compatibility:**

This toolkit is fully compatible with both PowerShell 5.1 and 7.x:
- ✅ **Box Drawing** - Beautiful Unicode borders work in both versions (╔═╗║╚╝)
- ✅ **Icons** - PS 7.x shows full emoji (💻📊⏱️), PS 5.1 uses Unicode symbols (▣■◔)
- ✅ **Logging** - UTF-8 encoding without BOM for maximum compatibility
- ✅ **All Features** - Real-time monitoring, change logging, and forensic analysis work identically
- ✅ **Performance** - Optimized for Windows Console in both versions

The tool automatically detects your PowerShell version and adapts the output accordingly, ensuring a professional and visually appealing experience regardless of which version you use.

**Installation:**

You can run the scripts directly or import the module for easier access:

```powershell

# Option 1: Import as module (recommended)
Import-Module .\RDP-Forensic.psm1

# Now you can call functions directly
Get-RDPForensics
Get-CurrentRDPSessions
```

**Usage Examples:**

```powershell
# Get all RDP events for today
.\Get-RDPForensics.ps1
# OR if module imported:
Get-RDPForensics

# Get last 7 days of RDP events
Get-RDPForensics -StartDate (Get-Date).AddDays(-7)

# Get RDP events for specific user
Get-RDPForensics -Username "john.doe" -StartDate (Get-Date).AddMonths(-1)

# Filter by source IP address (IPv4)
Get-RDPForensics -SourceIP "192.168.1.100"

# Filter by IPv6 address
Get-RDPForensics -SourceIP "fe80::1" -StartDate (Get-Date).AddDays(-7)

# Export results to CSV
Get-RDPForensics -StartDate (Get-Date).AddDays(-30) -ExportPath "C:\Reports\RDP"

# **NEW v1.0.4** - Group events by session with correlation
Get-RDPForensics -GroupBySession

# **NEW v1.0.4** - Analyze complete session lifecycles with export
Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -GroupBySession -ExportPath "C:\Reports\RDP"

# **NEW v1.0.6** - Include NTLM credential validation (4776) with time-based correlation
Get-RDPForensics -IncludeCredentialValidation -GroupBySession

# Include outbound RDP connections
Get-RDPForensics -IncludeOutbound

# Get events for last month with export
Get-RDPForensics -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\RDP_Analysis" -IncludeOutbound
```

**Session Correlation & Lifecycle Analysis (NEW in v1.0.4):**

```powershell
# Group all events by LogonID/SessionID to see complete session lifecycles
Get-RDPForensics -GroupBySession

# Export both events AND correlated sessions to CSV
Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -GroupBySession -ExportPath "C:\Reports"
# Creates: RDP_Forensics_<timestamp>.csv (individual events)
#          RDP_Sessions_<timestamp>.csv (session summary)

# Find incomplete sessions (missing logoff, suspicious disconnects)
Get-RDPForensics -GroupBySession | Where-Object { -not $_.LifecycleComplete }

# Analyze session durations for specific user
Get-RDPForensics -Username "john.doe" -GroupBySession -StartDate (Get-Date).AddMonths(-1)

# Identify long-running sessions (over 8 hours)
$sessions = Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddDays(-7)
$sessions | Where-Object { 
    $_.Duration -and 
    [timespan]::Parse($_.Duration).TotalHours -gt 8 
}

# Track user activity patterns with session correlation
Get-RDPForensics -Username "admin" -GroupBySession -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\Audit"
```

**Session Correlation Features:**
- **Automatic Event Grouping** - Links events across Security, TerminalServices, and System logs using ActivityID/LogonID/SessionID
- **Complete Lifecycle Visualization** - Shows which stages completed: Connection → Auth → Logon → Active → Disconnect → Logoff
- **Duration Calculation** - Accurate session time from first event to last
- **Anomaly Detection** - Identifies incomplete sessions (e.g., logon without logoff)
- **Dual Export** - Saves both raw events AND session summaries to CSV
- **Optional Credential Validation (NEW v1.0.6)** - Include EventID 4776 (NTLM auth) with time-based correlation for pre-session authentication tracking

**Advanced Forensic Filtering Examples:**

```powershell
# Filter specific IPv4 subnet - find all connections from 10.0.0.0/24
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-30)
$events | Where-Object { $_.SourceIP -match '^10\.0\.0\.' }

# Filter IPv6 link-local addresses (fe80::/10)
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-7)
$events | Where-Object { $_.SourceIP -match '^fe80:' }

# Find all external IPs (not private IPv4 ranges)
$events = Get-RDPForensics -StartDate (Get-Date).AddMonths(-1)
$events | Where-Object { 
    $_.SourceIP -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:)' -and
    $_.SourceIP -ne 'N/A' -and $_.SourceIP -ne '-' -and $_.SourceIP -ne 'LOCAL'
}

# Group connections by IP address to identify suspicious activity
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-7)
$events | Where-Object { $_.SourceIP -ne 'N/A' } | 
    Group-Object SourceIP | 
    Sort-Object Count -Descending | 
    Select-Object Count, Name

# Find failed login attempts from specific IPv4 network
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-1)
$events | Where-Object { 
    $_.EventType -match 'Failed' -and 
    $_.SourceIP -match '^192\.168\.1\.'
}

# Identify IPv6 connections for compliance reporting
$events = Get-RDPForensics -StartDate (Get-Date).AddMonths(-1)
$ipv6Events = $events | Where-Object { $_.SourceIP -match ':' }
$ipv6Events | Select-Object TimeCreated, User, SourceIP, EventType | 
    Export-Csv "C:\Reports\IPv6_RDP_Connections.csv" -NoTypeInformation

# Track connections from specific IPv4 address over time
Get-RDPForensics -SourceIP "203.0.113.45" -StartDate (Get-Date).AddMonths(-3) |
    Group-Object @{Expression={$_.TimeCreated.Date}} |
    Select-Object @{N='Date';E={$_.Name}}, Count |
    Sort-Object Date
```

**Parameters:**

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `StartDate` | DateTime | Start date for log collection | Beginning of current day |
| `EndDate` | DateTime | End date for log collection | Current time |
| `ExportPath` | String | Path to export CSV files | None (display only) |
| `Username` | String | Filter by specific username | None |
| `SourceIP` | String | Filter by source IP address | None |
| `IncludeOutbound` | Switch | Include outbound RDP connections | False |

### Get-CurrentRDPSessions.ps1

Quick analysis script for viewing currently active RDP sessions.

**Features:**
- Shows active RDP sessions with user information
- Displays session states (Active/Disconnected)
- Lists running processes per session
- Shows recent logon information for active users
- **Auto-refresh monitoring mode** for real-time session tracking
- Customizable refresh intervals (1-300 seconds)
- **Change logging** - Records session changes to CSV for forensic analysis

**Usage Examples:**

```powershell
# Display all current sessions (one-time check)
Get-CurrentRDPSessions

# Show processes for all sessions
Get-CurrentRDPSessions -ShowProcesses

# Get detailed info for specific session
Get-CurrentRDPSessions -SessionID 3 -ShowProcesses

# REAL-TIME MONITORING: Auto-refresh every 5 seconds (default)
Get-CurrentRDPSessions -Watch

# Monitor with custom 10-second refresh interval
Get-CurrentRDPSessions -Watch -RefreshInterval 10

# Monitor with processes shown and 15-second refresh
Get-CurrentRDPSessions -Watch -ShowProcesses -RefreshInterval 15

# Monitor during incident response with 3-second updates
Get-CurrentRDPSessions -Watch -RefreshInterval 3

# CHANGE LOGGING: Monitor with automatic change logging for forensic analysis
Get-CurrentRDPSessions -Watch -LogPath "C:\Logs\RDP_Monitor"

# Full monitoring - Watch mode with logging and process tracking
Get-CurrentRDPSessions -Watch -RefreshInterval 5 -LogPath "C:\SecurityLogs\RDP" -ShowProcesses

# Single check with logging (no Watch mode)
Get-CurrentRDPSessions -LogPath "C:\Logs\RDP_Audit"
```

**Real-Time Monitoring:**

The `-Watch` parameter enables continuous monitoring mode that automatically refreshes the display at your specified interval. Perfect for:
- Security incident response and live threat monitoring
- System maintenance windows
- Detecting unauthorized access attempts
- Tracking session state changes in real-time
- Monitoring user activity during audits

Press `Ctrl+C` to exit watch mode at any time.

**Change Logging:**

The `-LogPath` parameter enables forensic change logging:
- **New Sessions** - Logs when new RDP connections are established
- **State Changes** - Records when sessions change state (Active ↔ Disconnected)
- **Session Ended** - Logs when sessions terminate
- **CSV Format** - Timestamped entries for easy analysis in Excel or log analysis tools
- **Works with or without Watch mode** - Can log single checks or continuous monitoring
- **Forensic Timeline** - Creates complete audit trail of all session activity

Example log output:
```
Timestamp,EventType,SessionName,Username,SessionID,State,SourceIP,Details
2025-12-16 09:15:23,NEW_SESSION,rdp-tcp#2,john.doe,3,Active,,New RDP session detected
2025-12-16 09:45:10,STATE_CHANGE,rdp-tcp#2,john.doe,3,Disc,,State changed from Active to Disc
2025-12-16 10:02:45,SESSION_ENDED,rdp-tcp#2,john.doe,3,Disc,,Session ended or disconnected
```

> **Note:** Import the module first with `Import-Module .\RDP-Forensic.psm1` to use these commands directly.

## Event IDs Reference

### Connection Attempts
- **1149** - Remote Desktop Services: User authentication succeeded (RemoteConnectionManager)

### Authentication
- **4624** - An account was successfully logged on
- **4625** - An account failed to log on

### Session Events (TerminalServices-LocalSessionManager)
- **21** - Session logon succeeded
- **22** - Shell start notification received
- **23** - Session logoff succeeded
- **24** - Session has been disconnected
- **25** - Session reconnection succeeded
- **39** - Session disconnected by another session
- **40** - Session disconnected with reason code

### Reconnect/Disconnect (Security Log)
- **4778** - Session reconnected to Window Station
- **4779** - Session disconnected from Window Station

### Logoff
- **4634** - An account was logged off
- **4647** - User-initiated logoff
- **9009** - Desktop Window Manager has exited

### Outbound Connections
- **1102** - RDP client connection initiated (TerminalServices-RDPClient)

## Logon Types

The scripts filter and report on the following RDP-related logon types:

| Type | Description |
|------|-------------|
| 10 | RemoteInteractive (standard RDP connection) |
| 7 | Unlock or reconnect to existing session |
| 3 | Network logon (can include RDP) |
| 5 | Service or console connection (/admin mode) |

## Event Log Locations

The scripts query the following event logs:

1. **Security** (`Security`)
   - Authentication and logon/logoff events
   - Session reconnect/disconnect events

2. **TerminalServices-RemoteConnectionManager** (`Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`)
   - Connection attempts and authentication

3. **TerminalServices-LocalSessionManager** (`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`)
   - Session lifecycle events

4. **TerminalServices-RDPClient** (`Microsoft-Windows-TerminalServices-RDPClient/Operational`)
   - Outbound RDP connections

5. **System** (`System`)
   - DWM exit events indicating session termination

## Output Format

### CSV Export

When using the `-ExportPath` parameter, two files are generated:

1. **RDP_Forensics_TIMESTAMP.csv** - Detailed event log with columns:
   - TimeCreated
   - EventID
   - EventType
   - User
   - Domain
   - SourceIP
   - SessionID
   - LogonID
   - Details

2. **RDP_Summary_TIMESTAMP.txt** - Summary report containing:
   - Analysis period
   - Total event count
   - Events grouped by type
   - Unique users
   - Unique source IPs

## Common Use Cases

### Incident Response
```powershell
# Investigate suspicious activity from specific IP
.\Get-RDPForensics.ps1 -SourceIP "203.0.113.50" -StartDate (Get-Date).AddDays(-7) -ExportPath "C:\IR\RDP"
```

### Compliance Auditing
```powershell
# Monthly RDP access audit
.\Get-RDPForensics.ps1 -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\Compliance\RDP_$(Get-Date -Format 'yyyy-MM')"
```

### User Activity Tracking
```powershell
# Track specific user's RDP sessions
.\Get-RDPForensics.ps1 -Username "admin" -StartDate (Get-Date).AddDays(-30) -ExportPath "C:\UserActivity"
```

### Real-time Monitoring
```powershell
# Check current sessions
.\Get-CurrentRDPSessions.ps1 -ShowProcesses
```

### Failed Logon Analysis (Brute Force Detection)
```powershell
# Export events and filter for failed attempts
$events = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-1)
$events | Where-Object { $_.EventID -eq 4625 } | Group-Object SourceIP | Sort-Object Count -Descending
```

## Troubleshooting

### No Events Returned

1. **Check Administrator Rights**: Ensure you're running as Administrator
   ```powershell
   # Verify admin rights
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

2. **Verify Event Logs Exist**: Ensure the required logs are enabled
   ```powershell
   Get-WinEvent -ListLog *TerminalServices* | Select-Object LogName, IsEnabled, RecordCount
   ```

3. **Check Date Range**: Events may be outside your specified date range or logs may have rotated

4. **Increase Log Size**: If logs are rotating too quickly, increase the maximum log size
   ```powershell
   wevtutil sl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /ms:104857600
   ```

### Parsing Errors

If you encounter regex parsing issues (Username showing as "-\-"), ensure you're using the latest version of the script which includes updated regex patterns.

### Performance Considerations

For large environments with extensive logs:
- Use specific date ranges to limit query scope
- Filter by username or IP to reduce result sets
- Consider scheduled exports rather than real-time queries
- Increase available memory for PowerShell if processing large result sets

## Security Best Practices

1. **Protect exported logs**: Store forensic data in secure locations with restricted access
2. **Regular monitoring**: Schedule regular analysis to detect anomalies early
3. **Log retention**: Ensure adequate log retention policies (30-90 days minimum)
4. **Baseline establishment**: Create baselines of normal RDP activity for comparison
5. **Alert on anomalies**: Set up alerts for:
   - Multiple failed logons from same IP
   - Logons from unusual geographic locations
   - After-hours administrative access
   - Unusual session durations

## Additional Resources

- [Microsoft: Audit logon events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
- [Microsoft: Remote Desktop Services event logs Troubeshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/log-files-to-troubleshoot-rds-issues)

## Version History

- **1.0** - Initial release
  - Core forensics functionality
  - Multi-log source collection
  - CSV export capability
  - Current session monitoring

## License

This toolkit is provided as-is for forensic analysis and security monitoring purposes.

## Contributing

Contributions, issues, and feature requests are welcome. Please ensure any modifications maintain compatibility with Windows Server 2012 R2+ and Windows 8.1+.
