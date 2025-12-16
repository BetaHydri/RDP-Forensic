# RDP Forensics Toolkit - Getting Started

## What You Have

A complete PowerShell-based RDP forensics toolkit with 5 files:

### 1. **Get-RDPForensics.ps1** (Main Script)
   - Comprehensive RDP forensics analysis
   - Collects events from all relevant Windows logs
   - Supports filtering, exporting, and detailed reporting
   - ~700 lines of production-ready code

### 2. **Get-CurrentRDPSessions.ps1** (Live Monitoring)
   - Quick view of active RDP sessions
   - Shows current users, session states, and processes
   - Useful for real-time monitoring

### 3. **Examples.ps1** (Usage Scenarios)
   - 10 ready-to-use example scenarios
   - Uncomment and run for your specific needs
   - Covers daily monitoring, incident response, compliance, etc.

### 4. **README.md** (Full Documentation)
   - Complete guide with all parameters and options
   - Event ID reference
   - Troubleshooting tips
   - Security best practices

### 5. **QUICK_REFERENCE.md** (Quick Lookup)
   - Event ID cheat sheet
   - PowerShell one-liners
   - Common investigation workflows
   - Registry locations

## Quick Start (3 Steps)

### Step 0: Import the Module (REQUIRED)
```powershell
# Navigate to the toolkit directory and import the module
cd "c:\Users\jantiede\OneDrive\Develop\PowerShell\Security\RDP-Forensic"
Import-Module .\RDP-Forensic.psm1
```

> **⚠️ IMPORTANT:** You must import the module before using any cmdlets. All examples below assume this step is completed.

### Step 1: Test Basic Functionality
```powershell
# Run this to see today's RDP activity
Get-RDPForensics
```

### Step 2: Check Current Sessions
```powershell
# See who's currently connected
Get-CurrentRDPSessions -ShowProcesses
```

### Step 3: Generate a Report
```powershell
# Export last 7 days to CSV
Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -ExportPath "C:\RDP_Reports"
```

## Common Use Cases

### Daily Security Check
```powershell
Get-RDPForensics
```

### Investigate Suspicious Activity
```powershell
Get-RDPForensics -SourceIP "203.0.113.50" -StartDate (Get-Date).AddDays(-7)
```

### Track Specific User
```powershell
Get-RDPForensics -Username "admin" -StartDate (Get-Date).AddMonths(-1) -ExportPath "C:\Investigation"
```

### Find Brute Force Attacks
```powershell
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-1)
$events | Where-Object {$_.EventID -eq 4625} | Group-Object SourceIP | Sort-Object Count -Descending
```

### Include Credential Validation Events (NEW v1.0.6)
```powershell
# Track NTLM authentication attempts with time-based correlation
Get-RDPForensics -IncludeCredentialValidation -GroupBySession

# Find failed credential validations (potential brute force)
$events = Get-RDPForensics -IncludeCredentialValidation -StartDate (Get-Date).AddDays(-1)
$events | Where-Object {$_.EventType -match 'Credential Validation Failed'} | Group-Object User, SourceIP
```

## What Events Are Tracked

The toolkit monitors the complete RDP connection lifecycle:

**Connection Stage:**
- EventID 1149: Connection attempts

**Authentication Stage:**
- EventID 4624: Successful logons
- EventID 4625: Failed logons (brute force indicator)
- EventID 4776: NTLM credential validation (optional with -IncludeCredentialValidation)

**Session Stage:**
- EventID 21: Session logon
- EventID 4800/4801: Workstation lock/unlock
- EventID 24/25: Disconnect/reconnect
- EventID 4778/4779: Session state changes

**Termination Stage:**
- EventID 23: Session logoff
- EventID 4634/4647: Account logoff
- EventID 9009: Desktop termination

## Output Example

When you run the main script, you'll see:

```
=== RDP Forensics Analysis Tool ===
Analysis Period: 2025-12-09 00:00:00 to 2025-12-09 15:30:00

[1/6] Collecting RDP Connection Attempts (EventID 1149)...
  Found 15 connection attempts
[2/6] Collecting RDP Authentication Events (EventID 4624, 4625)...
  Found 23 authentication events
[3/6] Collecting RDP Session Events (EventID 21-25, 39, 40)...
  Found 18 session events
...

=== Analysis Summary ===
Total Events: 78

Events by Type:
  Successful Logon: 23
  Connection Attempt: 15
  Session Logon Succeeded: 12
  ...

=== Recent RDP Events (Top 50) ===
TimeCreated         EventID EventType           User        SourceIP      Details
-----------         ------- ---------           ----        --------      -------
2025-12-09 14:30:15 4624    Successful Logon    john.doe    192.168.1.50  RemoteInteractive (RDP)
...
```

## Export Output

When using `-ExportPath`, you get:

1. **RDP_Forensics_TIMESTAMP.csv** - All events in spreadsheet format
2. **RDP_Summary_TIMESTAMP.txt** - Human-readable summary

Perfect for:
- Compliance reports
- Security audits
- Incident investigation
- Evidence collection

## Prerequisites

✅ **Windows Server 2012 R2+ or Windows 8.1+**
✅ **PowerShell 5.1 or later** (Built into Windows)
✅ **Administrator privileges** (Required for Security log access)
✅ **Event logs enabled** (Default on Windows)
✅ **Audit policies enabled** (See below)

## Enable Windows Audit Policies

⚠️ **Important:** Security log events (4624, 4634, 4778, 4779) require specific audit policies to be enabled. Terminal Services logs work by default.

⚠️ **Critical Limitation:** Kerberos (4768-4772) and NTLM (4776) events are logged on the **Domain Controller**, not the Terminal Server. The tool queries the local Security log, so `-IncludeCredentialValidation` will return ZERO events when running on a Terminal Server.

**Quick Enable via PowerShell:**
```powershell
# Run on TERMINAL SERVER - Required for RDP session tracking
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Run on DOMAIN CONTROLLER - Optional for Kerberos/NTLM tracking
# ⚠️ These events are NOT on Terminal Server!
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Verify
auditpol /get /category:"Logon/Logoff"  # On Terminal Server
auditpol /get /category:"Account Logon"  # On Domain Controller
```

**Or via Local Security Policy:**
1. Run `secpol.msc`
2. Navigate to: Security Settings → Local Policies → Audit Policy
3. Enable:
   - Audit Logon Events → Success, Failure
   - Audit Account Logon Events → Success, Failure
   - **OPTIONAL:** Audit Kerberos Authentication Service → Success, Failure (for EventIDs 4768-4772)
   - **OPTIONAL:** Audit Credential Validation → Success, Failure (for EventID 4776)

**For domain environments**, configure via Group Policy:
```
Computer Configuration → Policies → Windows Settings → 
Security Settings → Advanced Audit Policy Configuration → Audit Policies

Required:
  Logon/Logoff:
  - Audit Logon (Success, Failure)
  - Audit Logoff (Success)
  - Audit Other Logon/Logoff Events (Success, Failure)

Optional (for -IncludeCredentialValidation):
  Account Logon:
  - Audit Kerberos Authentication Service (Success, Failure)
  - Audit Credential Validation (Success, Failure)
```

**Note:** Most systems already have these enabled. Check with:
```powershell
auditpol /get /subcategory:"Logon","Logoff","Other Logon/Logoff Events"
```

## Verify Administrator Rights

Before running, verify you have admin rights:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

Should return: `True`

If not, right-click PowerShell and select "Run as Administrator"

## Troubleshooting

### "Access Denied" Errors
- Run PowerShell as Administrator
- Security log requires elevated privileges

### No Events Returned
- Check if RDP is enabled on the system
- Verify date range (logs may have rotated)
- Ensure events exist: `Get-WinEvent -ListLog *TerminalServices* | Select RecordCount`

### Slow Performance
- Use specific date ranges: `-StartDate (Get-Date).AddDays(-7)`
- Filter by user or IP to reduce results
- Export to file rather than displaying all results

## Next Steps

1. **Run the basic script** to familiarize yourself with output
2. **Review Examples.ps1** for your specific use case
3. **Set up scheduled tasks** for automated monitoring
4. **Customize filters** based on your environment
5. **Increase log retention** if needed (see QUICK_REFERENCE.md)

## Scheduled Monitoring (Optional)

Create a daily report task:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"C:\Users\jantiede\OneDrive\Develop\PowerShell\Security\RDP-Forensic\Get-RDPForensics.ps1`" -ExportPath `"C:\RDP_Reports`""
$trigger = New-ScheduledTaskTrigger -Daily -At 6AM
Register-ScheduledTask -TaskName "Daily RDP Report" -Action $action -Trigger $trigger -RunLevel Highest
```

## Security Considerations

- **Protect exported files**: Contain sensitive security data
- **Regular monitoring**: Review reports weekly at minimum
- **Baseline activity**: Establish normal patterns to detect anomalies
- **Retention policy**: Keep logs 90+ days for compliance
- **Alert on anomalies**: Failed logons, unusual IPs, after-hours access

## Support and Resources

- **README.md**: Full documentation with all parameters
- **QUICK_REFERENCE.md**: Event IDs and PowerShell one-liners
- **Examples.ps1**: Ready-to-use scenarios
- **Original Article**: https://woshub.com/rdp-connection-logs-forensics-windows/

## Features Overview

✅ Tracks all RDP connection stages (6 phases)
✅ Monitors 15+ critical Event IDs
✅ Filters by date, user, IP address
✅ CSV export for analysis
✅ Real-time session monitoring
✅ Brute force detection
✅ Session duration tracking
✅ Outbound connection monitoring
✅ Failed logon analysis
✅ Comprehensive reporting

---

**Ready to start?** Run this command:

```powershell
cd "c:\Users\jantiede\OneDrive\Develop\PowerShell\Security\RDP-Forensic"
Get-RDPForensics
```

This will show you today's RDP activity and demonstrate the toolkit in action!
