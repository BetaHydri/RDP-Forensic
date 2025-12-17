# RDP Forensics Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.8-brightgreen)
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
2. **Credential Submission** - Explicit credential usage (EventID 4648) - NEW in v1.0.8
3. **Authentication** - Successful and failed authentication (EventID 4624, 4625)
4. **Logon** - Session establishment (EventID 21, 22)
5. **Lock/Unlock** - Workstation lock state changes (EventID 4800, 4801)
6. **Disconnect/Reconnect** - Session state changes (EventID 24, 25, 39, 40, 4778, 4779)
7. **Logoff** - Session termination (EventID 23, 4634, 4647, 9009)

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

**Event Logging Locations (IMPORTANT):**

| Event Type | Event IDs | Logged On | Tool Scope |
|------------|-----------|-----------|------------|
| **RDP Sessions** | 1149, 21-25, 39, 40, 4624, 4778, 4779 | Terminal Server | ✅ Primary use case |
| **Kerberos Auth** | 4768-4772 | **Domain Controller** | ⚠️ DC only |
| **NTLM Auth** | 4776 | **Domain Controller** | ⚠️ DC only |

⚠️ **Key Limitation:** This tool queries the **local Security log** where it runs. Kerberos and NTLM authentication events (4768-4772, 4776) are logged on the Domain Controller, not the Terminal Server. The `-IncludeCredentialValidation` parameter will return ZERO events when running on a Terminal Server.

**Audit Policy Requirements:**

Most RDP events (1149, 21-25, 39, 40, 9009) are logged by default in Terminal Services Operational logs. However, **Security log events require specific audit policies** to be enabled:

**Events requiring audit policies (ON TERMINAL SERVER):**
- EventID 4624, 4625 (Logon/Failed Logon) - Requires "Audit Logon Events"
- EventID 4634, 4647 (Logoff) - Requires "Audit Logon Events"
- EventID 4778, 4779 (Session Reconnect/Disconnect) - Requires "Audit Other Logon/Logoff Events"
- EventID 4800, 4801 (Workstation Lock/Unlock) - Requires "Audit Other Logon/Logoff Events"

**Events requiring audit policies (ON DOMAIN CONTROLLER):**
- **EventID 4768-4772 (Kerberos) - Requires "Audit Kerberos Authentication Service" (optional, DC only)**
- **EventID 4776 (NTLM) - Requires "Audit Credential Validation" (optional, DC only)**

**Enable via PowerShell (recommended):**
```powershell
# Run on Terminal Server - Required for RDP session tracking
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Run on Domain Controller - Optional for Kerberos/NTLM authentication tracking
# ⚠️ WARNING: Only run this on DC, not on Terminal Servers
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Verify settings
auditpol /get /category:"Logon/Logoff"  # Check on Terminal Server
auditpol /get /category:"Account Logon"  # Check on Domain Controller
```

**Enable via Group Policy (for domain environments):**
```
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies

**Required:**
Logon/Logoff:
- Audit Logon (Success, Failure)
- Audit Logoff (Success)
- Audit Other Logon/Logoff Events (Success, Failure)

**Optional (for -IncludeCredentialValidation):**
Account Logon:
- Audit Kerberos Authentication Service (Success, Failure)
- Audit Credential Validation (Success, Failure)
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

**You must import the module before using the cmdlets:**

```powershell
# Navigate to the toolkit directory
cd "C:\Path\To\RDP-Forensic"

# Import the module (required)
Import-Module .\RDP-Forensic.psm1

# Now you can call the cmdlets
Get-RDPForensics
Get-CurrentRDPSessions
```

> **Note:** All examples in this documentation assume the module has been imported.

**Usage Examples:**

> **⚠️ IMPORTANT:** Import the module first before running any commands:
> ```powershell
> Import-Module .\RDP-Forensic.psm1
> ```

```powershell
# Get all RDP events for today
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

# **NEW v1.0.6** - Include Kerberos (4768-4772) and NTLM (4776) authentication events
# ⚠️ NOTE: These events are on Domain Controller, not Terminal Server
# Only shows events when running tool on DC
Get-RDPForensics -IncludeCredentialValidation -GroupBySession

# **NEW v1.0.8** - Deep dive forensic analysis with credential validation and Event 4648
# Filter by username, source IP, and specific LogonID for complete session correlation
Get-RDPForensics -IncludeCredentialValidation -Username "AO-VPN\Administrator" -SourceIP "172.16.0.2" -LogonID 0x144533

# Include outbound RDP connections
Get-RDPForensics -IncludeOutbound

# Get events for last month with export
Get-RDPForensics -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\RDP_Analysis" -IncludeOutbound
```

**Example: Complete Forensic Investigation**

The following example demonstrates comprehensive RDP forensic analysis with credential validation, showing Event 4648 (credential submission), Event 4624 (successful logon), and complete session correlation:

```powershell
Get-RDPForensics -IncludeCredentialValidation -Username "AO-VPN\Administrator" -SourceIP "172.16.0.2" -LogonID 0x144533
```

![RDP Forensics Complete Analysis Example](docs/rdpForensic-Sample1.png)

This screenshot shows:
- **Event 4648** - Credential submission with source IP and target user
- **Event 4624** - Successful logon with Logon Type 10 (RemoteInteractive)
- **Complete timeline** - Full authentication flow from credential entry to session establishment
- **Correlation** - All events linked by LogonID for complete session picture
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
| `GroupBySession` | Switch | Correlate events by LogonID/SessionID | False |
| `LogonID` | String | Filter by specific LogonID (hex format: 0x12345) | None |
| `SessionID` | String | Filter by specific SessionID | None |

> **⚠️ MUTUAL EXCLUSIVITY:** LogonID and SessionID parameters cannot be used together (enforced via PowerShell Parameter Sets). PowerShell will automatically prevent this combination and display a clear error message.
| `IncludeCredentialValidation` | Switch | Include Kerberos/NTLM events (DC only) | False |

## 🎯 Forensic Analysis Best Practices

### Understanding LogonID vs SessionID Filtering

⚠️ **IMPORTANT:** LogonID and SessionID parameters are **mutually exclusive** - you cannot use both in the same command. PowerShell enforces this automatically via Parameter Sets and will display an error if you attempt to use both.

When investigating RDP sessions, understanding the difference between **LogonID** and **SessionID** filtering is crucial for comprehensive forensic analysis:

#### **LogonID Filtering (Recommended for Complete Investigation)**

**Use `-LogonID` when you need:**
- ✅ **Complete session correlation** across all log sources
- ✅ **Security log events** (4624 auth, 4778/4779 reconnect/disconnect)
- ✅ **TerminalServices events** (21-25 session lifecycle)
- ✅ **Full forensic picture** including authentication and reconnection history
- ✅ **Cross-log correlation** (Security + TerminalServices-LocalSessionManager)

**Example:**
```powershell
# Get complete session with all Security and TerminalServices events
Get-RDPForensics -GroupBySession -Username administrator -LogonID 0x6950A4
```

**Output includes:**
- 4778/4779 reconnect/disconnect events from Security log
- 4624 authentication events
- Event 21-25 session events from TerminalServices
- Complete session timeline with all state changes
- Multiple reconnect/disconnect cycles

**Why LogonID is Priority 1:**
- **Consistent across logs** - Same LogonID appears in both Security and TerminalServices logs
- **Created at authentication** - Assigned when user authenticates (4624 event)
- **Persists through session** - Remains constant even through reconnects/disconnects
- **Hex format** - Unique identifier (e.g., 0x6950A4)

#### **SessionID Filtering (Limited Use Cases)**

**Use `-SessionID` only when:**
- ⚠️ You need to isolate **TerminalServices-only** events
- ⚠️ You're investigating **specific session IDs** from TerminalServices logs
- ⚠️ You want to see **partial session view** without Security log context

**Example:**
```powershell
# Get only TerminalServices events for SessionID 4
Get-RDPForensics -GroupBySession -Username administrator -SessionID 4
```

**Output limited to:**
- Event 21: Session Logon Succeeded
- Event 22: Shell Start Notification
- Event 23: Session Logoff Succeeded
- Event 24: Session Disconnected
- **Missing:** 4624 auth events, 4778/4779 reconnect events from Security log

**Why SessionID is Limited:**
- **TerminalServices-only** - Not present in Security log events
- **Missing authentication context** - No 4624 events to show how user authenticated
- **No reconnect history** - Missing 4778/4779 events from Security log
- **Partial timeline** - Only shows TerminalServices perspective

### Recommended Forensic Workflow

**1. Start with broad correlation (no filters):**
```powershell
# Get all sessions for investigation period
Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddDays(-7) -Username targetuser
```

**2. Identify sessions of interest:**
- Review session summary table
- Note LogonID values (e.g., "LogonID:0x6950A4")
- Check session duration and lifecycle completeness

**3. Deep dive with LogonID filter:**
```powershell
# Get complete forensic picture for specific session
Get-RDPForensics -GroupBySession -LogonID 0x6950A4 -Username targetuser
```

**4. Export for further analysis:**
```powershell
# Export complete session with all correlated events
Get-RDPForensics -GroupBySession -LogonID 0x6950A4 -ExportPath "C:\Forensics\Investigation"
```

### Why LogonID-Based Correlation is Superior

| Aspect | LogonID Correlation | SessionID Correlation |
|--------|---------------------|----------------------|
| **Log Coverage** | Security + TerminalServices | TerminalServices only |
| **Event Types** | 4624, 4778/4779, 21-25 | 21-25 only |
| **Authentication Context** | ✅ Yes (4624 events) | ❌ No |
| **Reconnect History** | ✅ Yes (4778/4779) | ❌ No |
| **Session Duration** | ✅ Accurate (full timeline) | ⚠️ Partial (TS events only) |
| **Forensic Value** | ✅ Complete investigation | ⚠️ Limited view |
| **Best For** | Security investigations | TS log troubleshooting |

### Example: Investigating Suspicious Long Session

```powershell
# Step 1: Find long-running sessions
$sessions = Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddDays(-1)
$longSessions = $sessions | Where-Object { 
    $_.Duration -and [timespan]::Parse($_.Duration).TotalHours -gt 8 
}

# Step 2: Identify LogonID for suspicious session
$suspiciousLogonID = $longSessions[0].LogonID  # e.g., "0x6950A4"

# Step 3: Get complete session details with LogonID filter
Get-RDPForensics -GroupBySession -LogonID $suspiciousLogonID -ExportPath "C:\Investigation"
```

**This approach gives you:**
- Initial authentication event (4624) with logon type
- All reconnect/disconnect cycles (4778/4779)
- Complete TerminalServices session events (21-25)
- Full timeline showing exactly when and how session was active
- Evidence of disconnects vs logoffs

### Parameter Combinations

**✅ VALID Combinations:**
```powershell
# LogonID with other parameters
Get-RDPForensics -GroupBySession -LogonID 0x12345 -Username user -ExportPath "C:\Reports"

# SessionID with other parameters
Get-RDPForensics -GroupBySession -SessionID 4 -SourceIP "192.168.1.100" -ExportPath "C:\Reports"

# No filter (all sessions)
Get-RDPForensics -GroupBySession -Username user -SourceIP "192.168.1.100"
```

**❌ INVALID Combination (PowerShell will reject):**
```powershell
# This will produce an error:
Get-RDPForensics -GroupBySession -LogonID 0x12345 -SessionID 4

# Error message:
# Parameter set cannot be resolved using the specified named parameters.
# One or more parameters issued cannot be used together or an insufficient number of parameters were provided.
```

### Quick Reference

| Investigation Goal | Recommended Command |
|-------------------|---------------------|
| **Complete session analysis** | `-GroupBySession -LogonID 0x12345` |
| **Find all user sessions** | `-GroupBySession -Username john.doe` |
| **TerminalServices log only** | `-GroupBySession -SessionID 4` |
| **Broad investigation** | `-GroupBySession -StartDate (date)` |
| **Export for forensics** | Add `-ExportPath "C:\path"` to any command |

### Get-CurrentRDPSessions.ps1

Real-time RDP session monitoring with comprehensive forensic properties.

**Features:**
- **Extended session properties** via Win32 API (WTS) integration
- Shows ClientIP, ClientName, ClientBuild, ClientDisplay resolution
- **ConnectTime** with multi-source event correlation:
  * Security Events: 4778 (reconnection), 4624 (initial logon)
  * Terminal Services Events: 25 (reconnection), 21/22 (session logon)
  * Automatically uses most recent event across all sources
  * Works with or without Security audit policies enabled
- Displays session states (Active/Disconnected)
- Lists running processes per session
- Shows recent logon information for active users
- **Auto-refresh monitoring mode** for real-time session tracking
- Customizable refresh intervals (1-300 seconds)
- **Change logging** - Records session changes to CSV for forensic analysis
- IdleTime tracking (shows user inactivity duration when available)

**Usage Examples:**

```powershell
# Display all current sessions (one-time check)
Get-CurrentRDPSessions

# Show processes for all sessions
Get-CurrentRDPSessions -ShowProcesses

# Filter to specific session using PowerShell pipeline
Get-CurrentRDPSessions | Where-Object { $_.ID -eq 3 }

# Filter by username
Get-CurrentRDPSessions | Where-Object { $_.Username -like "*admin*" }

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

**Extended Properties (v1.0.8):**

The tool now displays comprehensive session information:
- **ClientIP** - Source IP address of RDP connection
- **ClientName** - Computer name of connecting client
- **ClientBuild** - Windows build number of client OS
- **ClientDisplay** - Screen resolution and color depth (e.g., "2048x1152 (32bit)")
- **ConnectTime** - Most recent connection timestamp (uses multi-source event correlation)
- **IdleTime** - User inactivity duration

> ⚠️ **IdleTime Limitation:** This property often shows "N/A" because:
> - WTS API only provides meaningful data when user has **stopped** interacting
> - Returns null/0 for actively used sessions (typing, mouse movement)
> - May not be available for disconnected sessions
> - Most useful in watch mode for detecting inactive sessions

> **Note:** Import the module first with `Import-Module .\RDP-Forensic.psm1` to use these commands directly.

## Event IDs Reference

### Connection Attempts
- **1149** - Remote Desktop Services: User authentication succeeded (RemoteConnectionManager)

### Authentication
- **4624** - An account was successfully logged on
- **4625** - An account failed to log on

### Pre-Authentication (Optional with -IncludeCredentialValidation)
**Kerberos Events:**
- **4768** - Kerberos TGT (Ticket Granting Ticket) request
- **4769** - Kerberos service ticket request
- **4770** - Kerberos service ticket renewed
- **4771** - Kerberos pre-authentication failed (shows why Kerberos failed before NTLM fallback)
- **4772** - Kerberos authentication ticket request failed

**NTLM Events:**
- **4776** - NTLM credential validation (used when Kerberos unavailable or fails)

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
Get-RDPForensics -SourceIP "203.0.113.50" -StartDate (Get-Date).AddDays(-7) -ExportPath "C:\IR\RDP"
```

### Compliance Auditing
```powershell
# Monthly RDP access audit
Get-RDPForensics -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\Compliance\RDP_$(Get-Date -Format 'yyyy-MM')"
```

### User Activity Tracking
```powershell
# Track specific user's RDP sessions
Get-RDPForensics -Username "admin" -StartDate (Get-Date).AddDays(-30) -ExportPath "C:\UserActivity"
```

### Real-time Monitoring
```powershell
# Check current sessions
Get-CurrentRDPSessions -ShowProcesses
```

### Failed Logon Analysis (Brute Force Detection)
```powershell
# Export events and filter for failed attempts
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-1)
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
