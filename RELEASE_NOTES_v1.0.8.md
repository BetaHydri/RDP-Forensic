# Release Notes - RDP Forensics Toolkit v1.0.8

**Release Date:** December 17, 2025  
**Status:** Stable

## Overview

Version 1.0.8 introduces comprehensive Event 4648 (Explicit Credential Usage) support, fixes critical SessionID filtering bugs, implements PowerShell Parameter Sets for LogonID/SessionID mutual exclusivity, and enhances lifecycle tracking with realistic warnings.

## 🎯 Major Changes

### 1. Event 4648 Support (Credential Submission)

**NEW EVENT TYPE: Explicit Credential Usage**

Event 4648 logs credential submission **before** the actual logon occurs (seconds before Event 4624). This provides valuable forensic insight into:
- Who submitted credentials (Subject)
- Which account was authenticated (Target)
- Target server name
- Process that initiated connection (usually mstsc.exe)
- Source IP address

**Key Implementation Details:**
- Event 4648 uses `SubjectLogonID` (different from the session LogonID created by Event 4624)
- Requires **time-based correlation** instead of direct LogonID matching
- Matches events 0-10 seconds BEFORE session start using Username + Source IP
- Automatically filters out non-RDP credential submissions
- Works with `-IncludeCredentialValidation` parameter

**Example Output:**
```
TimeCreated          EventID EventType                User                  SourceIP    Details
-----------          ------- ---------                ----                  --------    -------
2025-12-17 10:15:23  4648    Credential Submission    DOMAIN\targetuser     172.16.0.2  Subject: DOMAIN\sourceuser → Target: DOMAIN\targetuser | Server: SERVER01 | Process: mstsc.exe
2025-12-17 10:15:28  4624    Successful Logon         DOMAIN\targetuser     172.16.0.2  Logon Type: 10 (RemoteInteractive) | LogonID: 0x144533
```

**Usage:**
```powershell
# Include Event 4648 with credential validation
Get-RDPForensics -IncludeCredentialValidation -GroupBySession -Username "administrator"
```

### 2. SessionID Filtering Fix

**Problem:** When filtering by `-SessionID 3`, events with SessionID 2, 4, 5 also appeared in results.

**Root Cause:** 
- One LogonID can span multiple SessionIDs (disconnect/reconnect cycles)
- SessionID filter was applied AFTER correlation, including all events with matching LogonID
- Example: LogonID 0x144533 spans SessionID 2, 3, 4, 5 → filtering for SessionID 3 showed ALL

**Solution:**
- Moved SessionID filter to **pre-correlation** stage (early filtering)
- Now filters raw event list BEFORE grouping into sessions
- Terminal Services events MUST match SessionID
- Security events whitelisted by EventID (1149, 4624-4648, 4768-4779, 4800-4801, 4634, 4647, 9009)

**Impact:** SessionID filtering now shows ONLY events for the specified SessionID (plus correlated Security events without SessionID).

### 3. PowerShell Parameter Sets (Mutual Exclusivity)

**Problem:** Users could specify both `-LogonID` and `-SessionID`, creating logical conflict.

**Understanding the Conflict:**
- **LogonID:** Authentication session identifier, persists across disconnect/reconnect cycles
- **SessionID:** Terminal session instance identifier, changes on each disconnect/reconnect
- **Relationship:** One LogonID → Multiple SessionIDs over time
- **Conflict:** Filtering by both creates ambiguity (which tracking level do you want?)

**Solution: PowerShell Parameter Sets**

```powershell
# Parameter declarations
[Parameter(ParameterSetName = 'ByLogonID')]
[string]$LogonID,

[Parameter(ParameterSetName = 'BySessionID')]
[string]$SessionID,
```

**Enforcement:**
- PowerShell **automatically prevents** using both parameters together
- Clear error message when attempted:
  ```
  Parameter set cannot be resolved using the specified named parameters.
  ```
- Other parameters (Username, SourceIP, ExportPath, IncludeOutbound, IncludeCredentialValidation) work with **any combination**
- Only LogonID and SessionID are mutually exclusive

**Valid Combinations:**
```powershell
# ✅ LogonID with other parameters
Get-RDPForensics -GroupBySession -LogonID 0x144533 -Username admin -ExportPath "C:\Reports"

# ✅ SessionID with other parameters
Get-RDPForensics -GroupBySession -SessionID 3 -SourceIP "172.16.0.2" -IncludeCredentialValidation

# ✅ Neither (all sessions)
Get-RDPForensics -GroupBySession -Username admin -SourceIP "172.16.0.2"
```

**Invalid Combination:**
```powershell
# ❌ This produces error:
Get-RDPForensics -GroupBySession -LogonID 0x144533 -SessionID 3
```

### 4. Lifecycle Completion Logic Enhancement

**Problem:** Every session showed "⚠️ Incomplete session lifecycle!" warning, even active sessions.

**Old Logic (too strict):**
```
Complete = (ConnectionAttempt OR Authentication) AND Logon AND Logoff
```
- Required Logoff for every session
- Active sessions always flagged as incomplete
- False positives for normal operations

**New Logic (realistic):**
```
Complete = (Authentication AND (Logon OR Active)) OR Logoff
```
- Recognizes active sessions as valid
- Complete if: Has auth + (logon OR active state)
- OR: Session was terminated (has logoff)
- No false warnings for active sessions or time window limitations

**Enhanced Warning Messages:**
```powershell
# Missing authentication/logon
⚠️ Missing authentication/logon events (Yellow)

# Suspicious pattern
⚠️ Suspicious: Logoff without Logon (Red)

# Partial data (expected for active sessions)
⚠️ Partial session data (may be active or outside time window) (Yellow)
```

**Impact:** Realistic warnings, no false positives, clear indication of actual issues.

### 5. GroupBySession Event Table Display

**Problem:** `-GroupBySession` showed session summaries but no detailed event lists.

**Solution:** Added event table display after each session summary.

### 6. Get-CurrentRDPSessions: Removed -SessionID Parameter

**Design Decision:** Removed `-SessionID` parameter from Get-CurrentRDPSessions in favor of standard PowerShell filtering.

**Rationale:**
- **Simpler code:** No parameter validation or filtering logic needed
- **More flexible:** Users can filter by ANY property using Where-Object
- **PowerShell best practice:** Get cmdlets return objects, users apply their own filters
- **Previous behavior was misleading:** SessionID only filtered process display, not session list

**Migration:**
```powershell
# OLD (removed):
Get-CurrentRDPSessions -SessionID 3 -ShowProcesses

# NEW (recommended):
Get-CurrentRDPSessions | Where-Object { $_.ID -eq 3 }
Get-CurrentRDPSessions -ShowProcesses  # Shows processes for ALL sessions
```

**Benefits:**
- Filter by ANY property: ID, Username, State, ClientIP, etc.
- Combine filters: `Where-Object { $_.Username -like "*admin*" -and $_.State -eq "Active" }`
- Standard PowerShell patterns
- `-ShowProcesses` still works perfectly (shows processes for all active sessions)

**Output Format:**
```
╔════════════════════════════════════════════════════════════════╗
║ Session 1: LogonID:0x144533                                    ║
╚════════════════════════════════════════════════════════════════╝
📋 User: DOMAIN\Administrator
⏱️ Duration: 00:15:23
🌐 Source IP: 172.16.0.2
📂 Events: 11  ✓ Complete lifecycle

TimeCreated          EventID EventType                User                  SourceIP    SessionID LogonID    Details
-----------          ------- ---------                ----                  --------    --------- -------    -------
2025-12-17 10:15:23  4648    Credential Submission    DOMAIN\Administrator  172.16.0.2  N/A       0x143210   Subject: ... → Target: ...
2025-12-17 10:15:28  4624    Successful Logon         DOMAIN\Administrator  172.16.0.2  N/A       0x144533   Logon Type: 10
2025-12-17 10:15:29  21      Session Logon Succeeded  DOMAIN\Administrator  172.16.0.2  3         N/A        Session 3
...
```

**Impact:** Complete forensic view with both summary and detailed timeline per session.

## 📝 Updated Documentation

### Help Text
- Added RECOMMENDED note for `-LogonID` (persists across disconnect/reconnect)
- Added NOTE for `-SessionID` (changes on disconnect/reconnect)
- Documented mutual exclusivity for both parameters
- Clear guidance on when to use each parameter

### README.md
- New section: "Understanding LogonID vs SessionID Filtering"
- Comparison table: LogonID vs SessionID correlation
- Best practice workflows for forensic investigations
- Valid/Invalid parameter combinations with examples
- Example PowerShell error message for invalid combinations

### Examples (Validated)
- All examples use EITHER LogonID OR SessionID, never both
- Clear use cases for each filtering approach
- No outdated examples using both parameters

## 🔧 Technical Details

### Event 4648 Parsing
```powershell
4648 {
    # Parse Subject (who submitted credentials)
    $subjectUserName = # regex: 'Subject:[\s\S]*?Account Name:\s+([^\r\n]+)'
    $subjectLogonID = # regex: 'Subject:[\s\S]*?Logon ID:\s+([^\r\n]+)'
    
    # Parse Target (account being authenticated)
    $targetUserName = # regex: 'Account Whose Credentials Were Used:[\s\S]*?Account Name:\s+([^\r\n]+)'
    
    # Parse context
    $targetServerName = # regex: 'Target Server:[\s\S]*?Target Server Name:\s+([^\r\n]+)'
    $sourceIP = # regex: 'Network Information:[\s\S]*?Network Address:\s+([^\r\n]+)'
    $processName = # regex: 'Process Information:[\s\S]*?Process Name:\s+([^\r\n]+)'
}
```

### Time-Based Correlation Logic
```powershell
# Events requiring time-based correlation: 4648, 4768-4772, 4776
foreach ($preAuthEvent in $preAuthEvents) {
    foreach ($session in $sessions) {
        $matchUser = ($session.User -eq $preAuthEvent.User)
        $matchIP = ($session.SourceIP -eq $preAuthEvent.SourceIP)
        
        $sessionStart = ($session.Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        $timeDiff = $sessionStart - $preAuthEvent.TimeCreated
        
        # Match if: 0-10 seconds BEFORE session start
        if ($timeDiff.TotalSeconds -ge 0 -and $timeDiff.TotalSeconds -le 10) {
            if ($matchUser -and $matchIP) {
                # Add to session
                $session.Events += $preAuthEvent
            }
        }
    }
}
```

### SessionID Early Filtering
```powershell
# CRITICAL: Filter BEFORE correlation (line ~1303)
if ($SessionID) {
    $allEvents = $allEvents | Where-Object {
        # Terminal Services events MUST match SessionID
        ($_.SessionID -eq $SessionID) -or
        # Security events: whitelist by EventID (no SessionID field)
        ((-not $_.SessionID) -and $_.EventID -in @(1149, 4624, 4625, 4648, ...))
    }
}
```

## 🐛 Bug Fixes

1. **Event 4648 correlation** - Now correctly associates with Event 4624 session (time-based correlation)
2. **SessionID filtering** - Shows only events for specified SessionID (moved to pre-correlation)
3. **Lifecycle warnings** - Realistic completion logic (active sessions not flagged as incomplete)
4. **Double session table** - Removed duplicate output in GroupBySession mode
5. **Missing event tables** - Added detailed event list display per session

## ⚠️ Breaking Changes

**None.** All changes are additive or fix existing bugs. Existing scripts continue to work.

**Migration Notes:**
- Commands using `-LogonID` and `-SessionID` together will now produce an error (this was already a logical conflict)
- Separate commands into two: one with `-LogonID`, one with `-SessionID`

## 🎓 Recommendations

### For Complete Forensic Analysis
```powershell
# RECOMMENDED: Use LogonID for complete session tracking
Get-RDPForensics -GroupBySession -LogonID 0x144533 -IncludeCredentialValidation
```
- Shows ALL Security + TerminalServices events
- Includes authentication (4624), reconnect/disconnect (4778/4779), session lifecycle (21-25)
- Tracks complete session history across disconnect/reconnect cycles
- Best for security investigations and incident response

### For TerminalServices Troubleshooting
```powershell
# Use SessionID for specific terminal session instance
Get-RDPForensics -GroupBySession -SessionID 3
```
- Shows only TerminalServices events (21-25)
- Useful for investigating specific terminal session behavior
- Limited forensic value (missing Security log context)

### For Initial Investigation
```powershell
# Start broad, then narrow down
Get-RDPForensics -GroupBySession -Username admin -SourceIP "172.16.0.2"
# Review sessions, identify LogonID of interest
# Deep dive with LogonID filter
Get-RDPForensics -GroupBySession -LogonID 0x144533 -ExportPath "C:\Investigation"
```

## 📊 Testing Performed

- ✅ Event 4648 parsing and correlation
- ✅ SessionID filtering accuracy (no cross-contamination)
- ✅ LogonID/SessionID mutual exclusivity enforcement
- ✅ Lifecycle completion logic (active sessions, terminated sessions, partial data)
- ✅ GroupBySession event table display
- ✅ All parameter combinations (valid and invalid)
- ✅ Export functionality with all new features
- ✅ PowerShell 5.1 and 7.x compatibility

## 🔄 Compatibility

- **PowerShell:** 5.1, 7.x
- **Windows:** Server 2012 R2+, Windows 8.1+
- **Privileges:** Administrator (required for Security log)
- **Dependencies:** None (native PowerShell cmdlets only)

## 📚 Related Documentation

- [README.md](README.md) - Complete toolkit documentation
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Event ID quick lookup
- [GETTING_STARTED.md](GETTING_STARTED.md) - Quick start guide
- [Examples.ps1](Examples.ps1) - Usage scenarios

## 🙏 Acknowledgments

Special thanks to users who reported the SessionID filtering bug and suggested the Parameter Sets solution for LogonID/SessionID mutual exclusivity.

## 📝 Changelog Summary

**Added:**
- Event 4648 (Explicit Credential Usage) support with time-based correlation
- PowerShell Parameter Sets for LogonID/SessionID mutual exclusivity
- Event table display in GroupBySession output
- Enhanced lifecycle warning messages (specific, contextual)
- Comprehensive documentation for LogonID vs SessionID filtering

**Fixed:**
- SessionID filtering now shows only events for specified SessionID (pre-correlation filtering)
- Event 4648 correlation (time-based, not direct LogonID)
- Lifecycle completion logic (realistic, no false positives for active sessions)
- Double output in GroupBySession mode (removed duplicate table)

**Changed:**
- Lifecycle completion definition (more realistic)
- SessionID filter execution order (now pre-correlation)
- Warning messages (more specific and helpful)

**Removed:**
- Get-CurrentRDPSessions `-SessionID` parameter (use PowerShell filtering instead)

**Improved:**
- Help documentation (RECOMMENDED/NOTE annotations)
- README.md (forensic best practices section)
- Parameter guidance (when to use LogonID vs SessionID)
- Get-CurrentRDPSessions simplicity (standard PowerShell filtering patterns)

---

**Version:** 1.0.8  
**Author:** Jan Tiedemann  
**License:** MIT
