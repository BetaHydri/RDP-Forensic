# Release Notes - RDP-Forensic v1.0.5

**Release Date:** December 16, 2025

## 🎯 Overview

Version 1.0.5 introduces **ActivityID-based event correlation** for significantly improved session tracking accuracy across Windows Event Logs. This enhancement leverages the built-in Windows Event Correlation infrastructure to provide precise cross-log event correlation.

---

## ✨ New Features

### Enhanced Event Correlation with ActivityID

**Priority-based Correlation:**
- **ActivityID** (Priority 1) - Windows Event Correlation GUID for precise cross-log correlation
- **LogonID** (Priority 2) - Security log event correlation (fallback)
- **SessionID** (Priority 3) - TerminalServices event correlation (fallback)

**Benefits:**
- ✅ **More Precise Correlation** - ActivityID is specifically designed for linking related operations
- ✅ **Better Cross-Log Tracking** - Correlates events across Security, TerminalServices, and System logs
- ✅ **Improved Incomplete Session Detection** - Helps when LogonID/SessionID are missing or inconsistent
- ✅ **Globally Unique Identifiers** - ActivityID GUIDs eliminate ambiguity

**Technical Details:**
- ActivityID extracted from `<Correlation ActivityID="{GUID}">` element in event XML
- All event collection functions now parse and include ActivityID
- Session objects include ActivityID field for export and analysis

---

## 🔧 Improvements

### Event Collection Functions

All event parsing functions now extract ActivityID:
- `Get-RDPConnectionAttempts` (EventID 1149)
- `Get-RDPAuthenticationEvents` (EventID 4624, 4625)
- `Get-RDPSessionEvents` (EventID 21-25, 39, 40)
- `Get-RDPSessionReconnectEvents` (EventID 4778, 4779)
- `Get-RDPLogoffEvents` (EventID 4634, 4647, 9009)

### Correlation Engine

**Get-CorrelatedSessions** function enhanced:
- Priority-based correlation key selection
- ActivityID as primary correlation method
- Automatic fallback to LogonID/SessionID when ActivityID unavailable
- Session objects include all three correlation IDs for reference

### User Experience

- Updated correlation messages to reflect ActivityID-based correlation
- Session objects now export with ActivityID column
- Parameter descriptions updated to reflect enhanced correlation
- Version updated across all module files

---

## 📊 Examples

### Using Enhanced Correlation

```powershell
# Analyze RDP sessions with ActivityID-based correlation
Get-RDPForensics -GroupBySession

# Output shows ActivityID in session summary
# CorrelationKey: ActivityID:{946a6f55-ab87-4229-9a5b-5158bd87914b}
```

### Session Object Fields

```powershell
$sessions = Get-RDPForensics -StartDate (Get-Date).AddDays(-1) -GroupBySession

$sessions | Select-Object ActivityID, LogonID, SessionID, User, SourceIP, Duration
```

**Sample Output:**
```
ActivityID                           LogonID    SessionID User          SourceIP      Duration
----------                           -------    --------- ----          --------      --------
{946a6f55-ab87-4229-9a5b-5158bd...} 0x1a2b3c   2         Administrator 172.16.0.2    00:15:32
```

---

## 🔍 Technical Background

### What is ActivityID?

ActivityID is a GUID stored in the `<Correlation>` element of Windows Event Log entries. It's part of the Event Tracing for Windows (ETW) infrastructure and is specifically designed to track related operations across different event logs and providers.

**XML Example:**
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager" />
    <EventID>21</EventID>
    <TimeCreated SystemTime="2025-12-16T12:02:09.4989377Z" />
    <Correlation ActivityID="{946a6f55-ab87-4229-9a5b-5158bd87914b}" />
  </System>
</Event>
```

### Why ActivityID Improves Correlation

1. **Cross-Provider Correlation** - Same ActivityID across TerminalServices and Security logs
2. **Unique Identification** - GUIDs eliminate collision risks
3. **Microsoft Design** - Built into Windows specifically for event correlation
4. **Session Lifecycle** - Tracks entire RDP session from connection to logoff

---

## 📝 Breaking Changes

**None** - This release is fully backward compatible. Existing scripts and workflows continue to work unchanged.

---

## 🐛 Bug Fixes

- No bugs fixed in this release (enhancement-only release)

---

## 📋 Compatibility

- **PowerShell:** 5.1, 7.x, 8.0+
- **Windows:** Server 2012 R2+, Windows 8.1+
- **Requires:** Administrator privileges for Security log access
- **Audit Policies:** See documentation for required audit policies

---

## 🚀 Upgrade Instructions

### From v1.0.4

1. **Update Module:**
   ```powershell
   Remove-Module RDP-Forensic -ErrorAction SilentlyContinue
   Import-Module .\RDP-Forensic.psd1 -Force
   ```

2. **Verify Version:**
   ```powershell
   Get-RDPForensics | Select-Object -First 1
   # Should show "v1.0.5" in the header
   ```

3. **Test Correlation:**
   ```powershell
   Get-RDPForensics -StartDate (Get-Date).AddHours(-1) -GroupBySession
   # Look for "ActivityID:{GUID}" in CorrelationKey
   ```

### No Configuration Changes Required

- All existing parameters work identically
- Export formats unchanged (adds ActivityID column)
- No changes needed to existing scripts

---

## 🎓 Learning Resources

### Understanding ActivityID Correlation

**Documentation Links:**
- [Windows Event Correlation (Microsoft)](https://docs.microsoft.com/en-us/windows/win32/wes/consuming-events)
- [Event Tracing for Windows](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

**Example Queries:**

```powershell
# View ActivityIDs in a specific session
$session = Get-RDPForensics -GroupBySession | Select-Object -First 1
$session.Events | Select-Object EventID, EventType, ActivityID

# Compare correlation methods
$session | Select-Object ActivityID, LogonID, SessionID, CorrelationKey
```

---

## 🔬 Testing

**Validation Steps:**

1. **Extract ActivityID:**
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
       Id = 21
   } -MaxEvents 1 | ForEach-Object {
       ([xml]$_.ToXml()).Event.System.Correlation.ActivityID
   }
   ```

2. **Verify Correlation:**
   ```powershell
   $sessions = Get-RDPForensics -StartDate (Get-Date).AddDays(-1) -GroupBySession
   
   # Check ActivityID presence
   $sessions | Where-Object { $_.ActivityID } | Measure-Object
   
   # Should show sessions correlated by ActivityID
   ```

---

## 📞 Feedback & Support

- **Issues:** [GitHub Issues](https://github.com/BetaHydri/RDP-Forensic/issues)
- **Discussions:** [GitHub Discussions](https://github.com/BetaHydri/RDP-Forensic/discussions)
- **Author:** Jan Tiedemann

---

## 🗺️ Roadmap

### Planned for Future Releases

- **v1.0.6:** Enhanced filtering by ActivityID
- **v1.1.0:** Timeline visualization with ActivityID grouping
- **v1.2.0:** Cross-machine RDP session tracking for RDP gateway scenarios

---

## 📜 Changelog

### v1.0.5 (2025-12-16)
- **Added:** ActivityID extraction from all event sources
- **Added:** Priority-based correlation (ActivityID > LogonID > SessionID)
- **Enhanced:** Get-CorrelatedSessions with ActivityID support
- **Updated:** All event collection functions to parse Correlation element
- **Updated:** Session objects to include ActivityID field
- **Updated:** Documentation to reflect enhanced correlation
- **Updated:** Examples showing ActivityID usage

### Previous Versions
- **v1.0.4:** Event correlation engine, session lifecycle tracking
- **v1.0.3:** PowerShell 5.1 Unicode compatibility fixes
- **v1.0.2:** Real-time monitoring with Watch mode
- **v1.0.1:** Initial event collection and forensics
- **v1.0.0:** Initial release

---

**Thank you for using RDP-Forensic!** 🎉

This enhancement significantly improves session correlation accuracy. Please report any issues or suggestions on GitHub.
