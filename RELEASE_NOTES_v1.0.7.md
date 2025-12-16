# Release Notes - RDP-Forensic v1.0.7

**Release Date:** December 16, 2025

## 🎯 Overview

Version 1.0.7 introduces **major bug fixes and enhancements** to the correlation engine, focusing on Domain Controller compatibility and improved session merging capabilities. This release includes critical fixes for 4624 event parsing, username format standardization, and intelligent synchronized event detection.

---

## ✨ New Features

### Session Filtering Parameters

**New command-line parameters for targeted session analysis:**

```powershell
-LogonID <string>     # Filter by specific LogonID (e.g., '0x6950A4')
-SessionID <string>   # Filter by specific SessionID (e.g., '5')
```

**Benefits:**
- ✅ **Direct Session Access** - No need for Where-Object pipelines
- ✅ **Cleaner Syntax** - Built-in parameter validation
- ✅ **Better UX** - Informative filtering messages with warnings
- ✅ **Combines with Existing Filters** - Works alongside `-Username`, `-SourceIP`

**Examples:**
```powershell
# Filter by LogonID
Get-RDPForensics -GroupBySession -LogonID "0x6950A4"

# Filter by SessionID
Get-RDPForensics -GroupBySession -SessionID "5"

# Combine filters
Get-RDPForensics -GroupBySession -Username "administrator" -LogonID "0x6950A4"
```

---

## 🐛 Critical Bug Fixes

### 1. Domain Controller 4624 Event Parsing

**Issue:** On Domain Controllers, 4624 events were not creating LogonID-based sessions, causing all sessions to show as "SessionID" correlation only.

**Root Cause:** 4624 events have **two sections**:
- **Subject** (initiator): Account Name='-', Logon ID='0x0' (SYSTEM account)
- **New Logon** (session): Account Name='administrator', Logon ID='0x582f1b' (actual session)

The regex patterns matched the FIRST occurrence (Subject section) instead of the actual session data (New Logon section).

**Fix Applied:**
```powershell
# OLD (matched Subject section):
$userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { ... }
# Result: User='-', LogonID='0x0'

# NEW (matches New Logon section):
$userName = if ($message -match 'New Logon:[\s\S]*?Account Name:\s+([^\r\n]+)') { ... }
# Result: User='administrator', LogonID='0x582f1b'
```

**Impact:**
- ✅ Domain Controllers now correctly create LogonID-based sessions
- ✅ Complete session lifecycle tracking on DCs
- ✅ Proper correlation between Security and TerminalServices events

---

### 2. LogonType Regex Trailing Space Requirement

**Issue:** RDP LogonType filter required trailing space, failing on some event formats.

**Fix Applied:**
```powershell
# OLD: Required trailing space
$_.Message -match 'Logon Type:\s+(10|7|3|5)\s'

# NEW: Space optional
$_.Message -match 'Logon Type:\s+(10|7|3|5)'
```

**Impact:**
- ✅ Works on all Windows Server versions (2012 R2 - 2025)
- ✅ Compatible with different event message formats

---

### 3. Username Format Standardization

**Issue:** Username format mismatch prevented secondary correlation from merging sessions:
- Security events (4624, 4778, 4779): Returned separate `Account Name` and `Account Domain` fields
- TerminalServices events (21-25): Returned `DOMAIN\User` format
- Comparison: `'administrator' ≠ 'CONTOSO\administrator'` → No match

**Fix Applied:** All Security log events now construct `DOMAIN\User` format:
```powershell
# Extract domain and username
$accountName = if ($message -match 'New Logon:[\s\S]*?Account Name:\s+([^\r\n]+)') { ... }
$userDomain = if ($message -match 'New Logon:[\s\S]*?Account Domain:\s+([^\r\n]+)') { ... }

# Construct consistent format
if ($userDomain -ne 'N/A' -and $userDomain -ne '-' -and $accountName -ne 'N/A') {
    $userName = "$userDomain\$accountName"  # e.g., 'CONTOSO\administrator'
}
```

**Events Updated:**
- ✅ 4624 (Successful Logon)
- ✅ 4778/4779 (Session Reconnect/Disconnect)
- ✅ 4634/4647 (Logoff)
- ✅ 4800/4801 (Lock/Unlock)

**Impact:**
- ✅ Works on both **Domain-joined** systems (`DOMAIN\User`)
- ✅ Works on **Workgroup** systems (`COMPUTERNAME\User`)
- ✅ Secondary correlation now successfully merges sessions

---

### 4. Secondary Correlation - Type Conversion Error

**Issue:** Comparing TimeSpan object to double (seconds) caused InvalidOperationException.

**Fix Applied:**
```powershell
# OLD: Type mismatch
$closestTimeDiff = [TimeSpan]::MaxValue  # TimeSpan object
$timeDiff = [Math]::Abs(...).TotalSeconds  # Double
if ($timeDiff -lt $closestTimeDiff) { ... }  # ❌ Comparison failed

# NEW: Consistent types
$closestTimeDiff = [double]::MaxValue  # Double
$timeDiff = [Math]::Abs(...).TotalSeconds  # Double
if ($timeDiff -lt $closestTimeDiff) { ... }  # ✅ Works
```

---

### 5. Synchronized Event Detection

**Issue:** Secondary correlation only checked if FIRST events were within 10 seconds, failing when:
- SessionID session starts at 4:59:25 PM (EventID 21 - Logon)
- LogonID session starts at 5:06:37 PM (first 4779 - Disconnect)
- Gap: 7 minutes > 10 second threshold → No merge

**Even though** multiple events were perfectly synchronized:
- 5:06:37/38 PM - Disconnect (1 sec apart)
- 5:48:31 PM - Reconnect (0 sec apart)
- 6:49:34/35 PM - Disconnect (1 sec apart)
- 7:56:34 PM - Reconnect (0 sec apart)
- 9:00:53/54 PM - Disconnect (1 sec apart)

**Old Logic:**
```powershell
$sessionIDStart = ($sessionIDSession.Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
$logonIDStart = ($logonIDSession.Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
$timeDiff = [Math]::Abs(($logonIDStart - $sessionIDStart).TotalSeconds)

if ($timeDiff -le 10) {  # Only checked first event
    # Merge
}
```

**New Logic - Synchronized Event Counting:**
```powershell
# Count synchronized events (events within 3 seconds of each other)
$synchronizedCount = 0
foreach ($sessionIDEvent in $sessionIDSession.Events) {
    foreach ($logonIDEvent in $logonIDSession.Events) {
        $timeDiff = [Math]::Abs(($logonIDEvent.TimeCreated - $sessionIDEvent.TimeCreated).TotalSeconds)
        if ($timeDiff -le 3) {
            $synchronizedCount++
            break
        }
    }
}

# If we found multiple synchronized events, this is a strong match
if ($synchronizedCount -ge 2) {
    # Merge sessions
}
```

**Benefits:**
- ✅ **Smarter Detection** - Analyzes entire session timeline, not just first event
- ✅ **Handles Delayed LogonID Sessions** - Works when 4778/4779 events appear after initial logon
- ✅ **More Accurate** - Requires 2+ synchronized events (reduces false positives)
- ✅ **Workgroup Compatible** - Solves workgroup server correlation where 4624 events may be absent

**Impact:**
- ✅ Workgroup servers now correctly merge SessionID + LogonID sessions
- ✅ Works when Security log events start minutes after TerminalServices logon
- ✅ Handles audit logging gaps gracefully

---

## 🔧 Improvements

### Event Collection Functions

**All Security log event functions now standardize username format:**

1. **Get-RDPAuthenticationEvents** (4624, 4625)
   - Extract from "New Logon:" section
   - Construct `DOMAIN\User` format

2. **Get-RDPSessionReconnectEvents** (4778, 4779)
   - Construct `DOMAIN\User` format
   - Consistent with TerminalServices events

3. **Get-RDPLogoffEvents** (4634, 4647)
   - Construct `DOMAIN\User` format
   - Matches session username for correlation

4. **Get-RDPLockUnlockEvents** (4800, 4801)
   - Construct `DOMAIN\User` format (from Subject section)
   - Consistent format across all events

### Correlation Engine

**Secondary Correlation Enhanced:**
- **Old**: Time-based proximity (first events within ±10 seconds)
- **New**: Synchronized event pattern matching (2+ events within 3 seconds)

**Scoring System:**
```powershell
$bestMatchScore = 0  # Track number of synchronized event pairs

foreach ($logonIDKey in $logonIDSessions) {
    $synchronizedCount = 0
    # Count how many events align between SessionID and LogonID sessions
    
    if ($synchronizedCount -ge 2 -and $synchronizedCount -gt $bestMatchScore) {
        $bestMatchScore = $synchronizedCount
        $matchedLogonIDKey = $logonIDKey
    }
}
```

**Benefits:**
- Picks the LogonID session with the **most** synchronized events
- Handles multiple potential matches gracefully
- More resilient to timing variations

---

## 📊 Examples

### Using New Filtering Parameters

**Filter Specific Session:**
```powershell
# By LogonID (Security log sessions)
Get-RDPForensics -GroupBySession -LogonID "0x6950A4"

# By SessionID (TerminalServices sessions)
Get-RDPForensics -GroupBySession -SessionID "5"
```

**Combine with Existing Filters:**
```powershell
# Username + LogonID
Get-RDPForensics -GroupBySession -Username "administrator" -LogonID "0x6950A4"

# Source IP + SessionID
Get-RDPForensics -GroupBySession -SourceIP "172.16.0.2" -SessionID "5"
```

**Export Specific Session:**
```powershell
Get-RDPForensics -GroupBySession -LogonID "0x6950A4" -ExportPath "C:\Reports"
```

### Testing Correlation on Different Systems

**Domain Controller:**
```powershell
# Test 4624 event parsing (New Logon section)
Get-RDPForensics -GroupBySession -Username "contoso\administrator" -StartDate (Get-Date).AddHours(-5)

# Expected: Sessions show as "LogonID:0x..." with complete event timeline
```

**Workgroup Server:**
```powershell
# Test synchronized event detection
Get-RDPForensics -GroupBySession -Username "ao-vpn\administrator" -StartDate (Get-Date).AddHours(-5)

# Expected: SessionID sessions merge with LogonID sessions (count reduced)
```

**Verify Session Merge:**
```powershell
$sessions = Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddDays(-1)

# Before fix: Multiple sessions (SessionID:5 + LogonID:0x6950A4 separate)
# After fix: Single merged session with combined events

$sessions | Select-Object CorrelationKey, @{N='Events';E={$_.Events.Count}}, Duration, User
```

---

## 🔍 Technical Background

### Domain Controller Event Structure

**4624 Successful Logon Event Anatomy:**

```
Subject:
    Security ID:        SYSTEM
    Account Name:       -
    Account Domain:     -
    Logon ID:           0x0         ← WRONG (initiator account)

New Logon:
    Security ID:        CONTOSO\administrator
    Account Name:       administrator
    Account Domain:     CONTOSO
    Logon ID:           0x582f1b    ← CORRECT (session account)
```

**Why This Matters:**
- Subject section = the account that initiated the logon (often SYSTEM on DC)
- New Logon section = the actual user session being created
- Regex must use section-aware matching: `'New Logon:[\s\S]*?Account Name:\s+([^\r\n]+)'`

### Workgroup vs Domain Authentication

**Domain-Joined Systems:**
```
Security Event 4778: User='CONTOSO\administrator', Domain='CONTOSO'
TerminalServices 25: User='CONTOSO\administrator'
✅ Match: Both use DOMAIN\User format
```

**Workgroup Systems:**
```
Security Event 4778: User='Administrator', Domain='AO-VPN'
Constructed format: 'AO-VPN\Administrator'
TerminalServices 25: User='AO-VPN\Administrator'
✅ Match: Computer name acts as "domain"
```

### Secondary Correlation Algorithm

**Scenario:** Long-running session with reconnect/disconnect cycles

```
Timeline:
4:59:25 PM - EventID 21 (Session Logon) → SessionID:5 created
5:06:37 PM - EventID 4779 (Disconnect) → LogonID:0x6950A4 created
5:48:31 PM - EventID 4778 (Reconnect) + EventID 25 (Reconnect) ← 0 sec apart
6:49:34 PM - EventID 4779 (Disconnect) + EventID 24 (Disconnect) ← 1 sec apart
7:56:34 PM - EventID 4778 (Reconnect) + EventID 25 (Reconnect) ← 0 sec apart
9:00:53 PM - EventID 4779 (Disconnect) + EventID 24 (Disconnect) ← 1 sec apart
```

**Detection:**
- Old: First events 7 minutes apart → No merge ❌
- New: 4 synchronized pairs found → Merge! ✅

---

## 📝 Breaking Changes

**None** - This release is fully backward compatible. All existing scripts continue to work unchanged.

---

## 📋 Compatibility

- **PowerShell:** 5.1, 7.x, 8.0+
- **Windows:** Server 2012 R2+, Windows 8.1+
- **Requires:** Administrator privileges for Security log access
- **Tested On:**
  - ✅ Windows Server 2019 (Domain Controller)
  - ✅ Windows Server 2022 (Domain Controller)
  - ✅ Windows Server 2019 (Workgroup)
  - ✅ Windows Server 2022 (Workgroup)

---

## 🚀 Upgrade Instructions

### From v1.0.6 or Earlier

1. **Update Module:**
   ```powershell
   Remove-Module RDP-Forensic -ErrorAction SilentlyContinue
   Import-Module .\RDP-Forensic.psm1 -Force
   ```

2. **Verify Version:**
   ```powershell
   Get-RDPForensics -StartDate (Get-Date).AddHours(-1) | Select-Object -First 1
   # Should show "v1.0.7" in the header
   ```

3. **Test Correlation:**
   ```powershell
   # Domain Controller
   Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-5)
   # Should show LogonID-based sessions
   
   # Workgroup Server
   Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-5)
   # Should show merged sessions (reduced count)
   ```

### No Configuration Changes Required

- All existing parameters work identically
- Export formats unchanged
- No changes needed to existing scripts
- New parameters are optional

---

## 🔬 Testing Scenarios

### Scenario 1: Domain Controller Correlation

**Objective:** Verify 4624 events create LogonID-based sessions

```powershell
# Run on Domain Controller
Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-5) -Username "contoso\administrator"
```

**Expected Results:**
- ✅ Sessions show as "LogonID:0x..." (not "SessionID:...")
- ✅ Duration > 0 seconds (complete timeline)
- ✅ Multiple events per session (merged)
- ✅ User format: `DOMAIN\username`

### Scenario 2: Workgroup Server Correlation

**Objective:** Verify synchronized event detection merges sessions

```powershell
# Run on Workgroup Server
Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-5) -Username "administrator"
```

**Expected Results:**
- ✅ Fewer sessions than before (merge reduces count)
- ✅ Merged session has 10+ events (SessionID + LogonID combined)
- ✅ User format: `COMPUTERNAME\username`
- ✅ Complete duration tracking

### Scenario 3: New Filtering Parameters

**Objective:** Test LogonID and SessionID filtering

```powershell
# Get all sessions first
$sessions = Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddDays(-1)

# Pick a specific LogonID
$logonID = $sessions[0].LogonID

# Filter by LogonID
Get-RDPForensics -GroupBySession -LogonID $logonID

# Filter by SessionID
Get-RDPForensics -GroupBySession -SessionID "5"
```

**Expected Results:**
- ✅ Only matching session displayed
- ✅ Filtering message shown
- ✅ Warning if no matches found
- ✅ Works with -ExportPath

### Scenario 4: Username Format Validation

**Objective:** Verify consistent username format across all events

```powershell
$sessions = Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-8)

# Check username format consistency
$sessions.Events | Select-Object EventID, User -Unique | Format-Table
```

**Expected Results:**
- ✅ All events show consistent format: `DOMAIN\User` or `COMPUTER\User`
- ✅ No bare usernames (e.g., 'administrator' without prefix)
- ✅ 4624, 4778, 4779, 4634 all match TerminalServices format

---

## 🐛 Known Issues

None at this time.

---

## 📞 Feedback & Support

- **Issues:** [GitHub Issues](https://github.com/BetaHydri/RDP-Forensic/issues)
- **Discussions:** [GitHub Discussions](https://github.com/BetaHydri/RDP-Forensic/discussions)
- **Author:** Jan Tiedemann

---

## 🗺️ Roadmap

### Planned for Future Releases

- **v1.0.8:** ActivityID correlation implementation (cross-log GUID matching)
- **v1.1.0:** Timeline visualization with session lifecycle graphs
- **v1.2.0:** Cross-machine RDP session tracking for RDP gateway scenarios
- **v2.0.0:** GUI dashboard with real-time monitoring

---

## 📜 Changelog

### v1.0.7 (2025-12-16)

#### 🐛 Bug Fixes
- **Fixed:** Domain Controller 4624 event parsing - now extracts from "New Logon:" section instead of "Subject:" section
- **Fixed:** LogonType regex trailing space requirement - now works without trailing space
- **Fixed:** Username format standardization - all Security events now construct `DOMAIN\User` format
- **Fixed:** Secondary correlation type conversion error - changed `[TimeSpan]::MaxValue` to `[double]::MaxValue`
- **Fixed:** Synchronized event detection - correlation now checks entire session timeline, not just first event

#### ✨ New Features
- **Added:** `-LogonID` parameter for filtering specific Security log sessions
- **Added:** `-SessionID` parameter for filtering specific TerminalServices sessions

#### 🔧 Improvements
- **Enhanced:** Secondary correlation algorithm - uses synchronized event pattern matching
- **Enhanced:** Username extraction for 4624, 4778, 4779, 4634, 4647, 4800, 4801 events
- **Improved:** Workgroup server compatibility - handles sessions without 4624 events
- **Improved:** Correlation resilience - works with timing gaps between event sources

#### 📝 Documentation
- **Updated:** Help documentation with new parameter descriptions
- **Added:** Examples for LogonID/SessionID filtering
- **Added:** Domain Controller event structure documentation
- **Added:** Testing scenarios for correlation validation

### Previous Versions
- **v1.0.6:** Pre-authentication event correlation (4768-4772, 4776) with RDP-only filtering
- **v1.0.5:** ActivityID extraction from all event sources
- **v1.0.4:** Event correlation engine, session lifecycle tracking
- **v1.0.3:** PowerShell 5.1 Unicode compatibility fixes
- **v1.0.2:** Real-time monitoring with Watch mode
- **v1.0.1:** Initial event collection and forensics
- **v1.0.0:** Initial release

---

**Thank you for using RDP-Forensic!** 🎉

This release significantly improves correlation accuracy on Domain Controllers and Workgroup servers. Please test thoroughly and report any issues on GitHub.
