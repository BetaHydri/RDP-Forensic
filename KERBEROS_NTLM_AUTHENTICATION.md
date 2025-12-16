# Kerberos and NTLM Authentication Tracking

## Overview

Version 1.0.6 adds comprehensive pre-authentication event tracking with the `-IncludeCredentialValidation` parameter. This feature collects both **Kerberos** (EventIDs 4768-4772) and **NTLM** (EventID 4776) authentication events to provide complete visibility into the authentication protocol flow.

## Why Track Pre-Authentication Events?

When a user attempts to connect via RDP, Windows first tries **Kerberos authentication**. If Kerberos fails or is unavailable, Windows falls back to **NTLM authentication**. Understanding this process is crucial for:

- **Security Analysis** - Identify why secure Kerberos failed and NTLM fallback occurred
- **Attack Detection** - NTLM-only connections may indicate downgrade attacks or misconfiguration
- **Compliance** - Track which authentication protocols are being used
- **Troubleshooting** - Diagnose authentication failures before session creation

## Authentication Flow

### Successful Kerberos Flow
```
1. EventID 4768 - Kerberos TGT Request (user requests ticket from domain)
2. EventID 4769 - Kerberos Service Ticket Request (user requests ticket for TERMSRV)
3. EventID 4624 - Successful Logon (RDP session begins)
```

### Kerberos Failure → NTLM Fallback
```
1. EventID 4768 - Kerberos TGT Request (user tries Kerberos)
2. EventID 4771 - Kerberos Pre-authentication Failed (shows error code/reason)
3. EventID 4776 - NTLM Credential Validation (Windows falls back to NTLM)
4. EventID 4624 - Successful Logon (RDP session begins)
```

### Pure NTLM Authentication
```
1. EventID 4776 - NTLM Credential Validation (Kerberos not attempted)
2. EventID 4624 - Successful Logon (RDP session begins)
```

## Event Details

### Kerberos Events (4768-4772)

#### EventID 4768 - Kerberos TGT Request
- **Purpose**: User requests a Ticket Granting Ticket from the domain controller
- **Key Fields**:
  - Account Name (username)
  - Client Address (source IP)
  - Result Code (0x0 = success, other codes = specific failures)
  - Ticket Options
- **Forensic Value**: First step in Kerberos authentication

#### EventID 4769 - Kerberos Service Ticket Request
- **Purpose**: User requests a service ticket for a specific service (e.g., TERMSRV for RDP)
- **Key Fields**:
  - Account Name
  - Service Name (look for "TERMSRV" for RDP)
  - Client Address
  - Failure Code (0x0 = success)
- **Forensic Value**: Shows which service was accessed with Kerberos

#### EventID 4770 - Kerberos Service Ticket Renewal
- **Purpose**: User renews an existing service ticket
- **Key Fields**:
  - Account Name
  - Service Name
  - Client Address
- **Forensic Value**: Indicates long-running sessions

#### EventID 4771 - Kerberos Pre-authentication Failed ⚠️ **KEY EVENT**
- **Purpose**: Shows WHY Kerberos authentication failed before NTLM fallback
- **Key Fields**:
  - Account Name
  - Client Address
  - **Failure Code** - Critical for understanding the failure reason
- **Common Failure Codes**:
  - `0x6` - Client not found in Kerberos database
  - `0x7` - Server not found in Kerberos database
  - `0xC` - Workstation restriction violated
  - `0x12` - Client account disabled or revoked
  - `0x17` - Password expired
  - `0x18` - Wrong password provided
  - `0x25` - Clock skew too large (time sync issue)
- **Forensic Value**: **MOST IMPORTANT** - Explains why Kerberos failed and NTLM was used

#### EventID 4772 - Kerberos Authentication Ticket Request Failed
- **Purpose**: Kerberos ticket request failed for other reasons
- **Key Fields**:
  - Account Name
  - Failure Code
- **Forensic Value**: Additional Kerberos failure tracking

### NTLM Event (4776)

#### EventID 4776 - NTLM Credential Validation
- **Purpose**: NTLM authentication attempt (used when Kerberos fails/unavailable)
- **Key Fields**:
  - Logon Account (DOMAIN\Username format)
  - Source Workstation
  - Error Code (0x0 = success, 0xC0000064 = wrong password)
  - Authentication Package (usually "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")
- **Forensic Value**: Shows NTLM fallback occurred; may indicate Kerberos issues

## Security Implications

### When to Investigate

**🔴 High Priority:**
- Multiple EventID 4771 (Kerberos failures) followed by 4776 (NTLM)
  - May indicate downgrade attacks or misconfiguration
  - Check failure codes to understand why Kerberos failed

- EventID 4771 with error code 0x18 (wrong password)
  - Possible brute-force attempts
  - Especially if followed by successful 4776/4624

- Only EventID 4776 with no Kerberos attempts
  - Client may not support Kerberos
  - Could indicate legacy systems or attack tools

**🟡 Medium Priority:**
- EventID 4771 with error code 0x25 (clock skew)
  - Time synchronization issues
  - Can cause legitimate authentication failures

- EventID 4771 with error code 0x12 (client revoked)
  - Account may be disabled or expired
  - Verify account status

### Normal Patterns

**✅ Expected Behavior:**
- Successful 4768 → 4769 → 4624 (normal Kerberos flow)
- 4768 → 4771 (0x17) → 4776 → 4624 (password expired, NTLM fallback)
- Multiple 4776 events with same ActivityID (normal Windows authentication rounds)

## Usage Examples

### Basic Authentication Tracking
```powershell
# Include Kerberos and NTLM events in analysis
# ⚠️ NOTE: Will only find events if running on Domain Controller
# Running on Terminal Server will show NO Kerberos/NTLM events
Get-RDPForensics -IncludeCredentialValidation -GroupBySession
```

⚠️ **Expected Result on Terminal Server:**
- Kerberos event count: 0 (events are on DC, not Terminal Server)
- NTLM event count: 0 (events are on DC, not Terminal Server)  
- RDP session events: Normal (events are local)

✅ **Expected Result on Domain Controller:**
- Kerberos event count: High (all domain Kerberos authentications)
- NTLM event count: High (all NTLM authentications)
- RDP session events: Only if DC is also an RDP target

### Find Kerberos Failures
```powershell
# Get all events with authentication details
$events = Get-RDPForensics -IncludeCredentialValidation -StartDate (Get-Date).AddDays(-7)

# Filter for Kerberos pre-auth failures (EventID 4771)
$events | Where-Object { $_.EventID -eq 4771 } | 
    Select-Object TimeCreated, User, EventType, Details, SourceIP |
    Format-Table -AutoSize
```

### Identify NTLM Fallback Sessions
```powershell
# Group by session and look for sessions with 4776 but no 4768/4769
$sessions = Get-RDPForensics -IncludeCredentialValidation -GroupBySession -StartDate (Get-Date).AddDays(-7)

# Sessions that used NTLM (have 4776 events)
$ntlmSessions = $sessions | Where-Object { 
    ($_.AllEvents | Where-Object { $_.EventID -eq 4776 }).Count -gt 0 
}

# Check if they also have Kerberos attempts
foreach ($session in $ntlmSessions) {
    $kerberosAttempts = ($session.AllEvents | Where-Object { $_.EventID -in 4768,4769,4771,4772 }).Count
    $ntlmAttempts = ($session.AllEvents | Where-Object { $_.EventID -eq 4776 }).Count
    
    [PSCustomObject]@{
        SessionStart = $session.SessionStart
        User = $session.User
        KerberosAttempts = $kerberosAttempts
        NTLMAttempts = $ntlmAttempts
        AuthType = if ($kerberosAttempts -eq 0) { "Pure NTLM" } else { "Kerberos → NTLM Fallback" }
    }
}
```

### Analyze Authentication Protocol Usage
```powershell
# Get authentication statistics for last 30 days
$events = Get-RDPForensics -IncludeCredentialValidation -StartDate (Get-Date).AddDays(-30)

$stats = @{
    KerberosTGT = ($events | Where-Object { $_.EventID -eq 4768 }).Count
    KerberosService = ($events | Where-Object { $_.EventID -eq 4769 }).Count
    KerberosFailures = ($events | Where-Object { $_.EventID -eq 4771 }).Count
    NTLM = ($events | Where-Object { $_.EventID -eq 4776 }).Count
}

Write-Host "`nAuthentication Protocol Statistics (Last 30 Days):" -ForegroundColor Cyan
Write-Host "  Kerberos TGT Requests: $($stats.KerberosTGT)" -ForegroundColor Green
Write-Host "  Kerberos Service Tickets: $($stats.KerberosService)" -ForegroundColor Green
Write-Host "  Kerberos Failures: $($stats.KerberosFailures)" -ForegroundColor Yellow
Write-Host "  NTLM Validations: $($stats.NTLM)" -ForegroundColor $(if ($stats.NTLM -gt $stats.KerberosService) { "Red" } else { "Green" })

if ($stats.NTLM -gt $stats.KerberosService) {
    Write-Host "`n⚠️  WARNING: More NTLM than Kerberos - investigate configuration!" -ForegroundColor Red
}
```

## Correlation Strategy

The toolkit uses **two different correlation methods** depending on event location:

### 1. ActivityID Correlation (Terminal Server Events)
For events logged locally on the Terminal Server:
- ✅ **EventIDs**: 1149, 4624, 21-25, 4778, 4779, 4634, 4647
- ✅ **Method**: ActivityID (Windows native correlation)
- ✅ **Accuracy**: Exact - all events share the same ActivityID
- ✅ **Use Case**: Perfect for tracking RDP session lifecycle

### 2. Time-Based Correlation (Domain Controller Events)  
For pre-authentication events from the Domain Controller:
- ⚠️ **EventIDs**: 4768-4772 (Kerberos), 4776 (NTLM)
- ⚠️ **Method**: Username match + timestamp proximity (0-10 seconds before session)
- ⚠️ **Accuracy**: Heuristic - best-effort matching
- ⚠️ **Why**: These events have DC's ActivityID, which doesn't match TS's ActivityID

**Correlation Rules:**
1. Pre-auth events occur **0-10 seconds before** the RDP session (EventID 4624 with Logon Type 10/7/3/5)
2. Username must match exactly
3. Closest timestamp match wins if multiple candidates
4. **Only RDP-correlated pre-auth events are included** - non-RDP authentications (SMB, SQL, Exchange, etc.) are filtered out

⚠️ **CRITICAL LIMITATION: Where Events Are Logged**

| Event Type | Event IDs | Logged On | Available When Running on TS? |
|------------|-----------|-----------|-------------------------------|
| **RDP Session** | 4624, 1149, 21-25, 4778, 4779 | Terminal Server | ✅ YES |
| **Kerberos Auth** | 4768-4772 | **Domain Controller** | ❌ NO |
| **NTLM Auth** | 4776 | **Domain Controller** | ❌ NO |

**Why ActivityID Cannot Correlate Across Machines:**
- ActivityID is **provider-specific** and **machine-local**
- Kerberos events (4768-4772) are logged on the **Domain Controller** with DC's ActivityID
- RDP session events (4624) are logged on the **Terminal Server** with TS's ActivityID
- These ActivityIDs are **completely unrelated** - they come from different systems
- **Time-based correlation (username + timestamp)** is the only viable method for cross-machine correlation

**Use Cases:**

✅ **PRIMARY USE CASE:** Running tool on Terminal Server to analyze RDP sessions
- Excellent ActivityID correlation between 4624 → 4778 → 4634 (all on same machine)
- Perfect for session lifecycle tracking
- `-IncludeCredentialValidation` will return ZERO Kerberos/NTLM events (they're on DC)

⚠️ **LIMITED USE CASE:** Running tool on Domain Controller
- Will see authentication events (4768-4772, 4776) for ALL domain authentications
- But will NOT see Terminal Server session events (21-25, 4778, 4779)
- Different purpose (DC authentication monitoring, not RDP session tracking)

🔧 **ADVANCED SCENARIO:** Multi-system correlation
- Collect DC logs separately: `Get-RDPForensics -IncludeCredentialValidation` on DC
- Collect TS logs separately: `Get-RDPForensics -GroupBySession` on Terminal Server
- Correlate manually using username + timestamp matching

## Audit Policy Configuration

⚠️ **CRITICAL:** These audit policies must be enabled on the **Domain Controller**, not the Terminal Server!

Kerberos and NTLM authentication events are logged where authentication validation occurs:
- **Kerberos (4768-4772)** → Logged on Domain Controller
- **NTLM (4776)** → Logged on Domain Controller (or authenticating server)
- **RDP Sessions (4624)** → Logged on Terminal Server

### PowerShell (Run on Domain Controller)
```powershell
# Enable Kerberos authentication tracking (ON DOMAIN CONTROLLER)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Enable NTLM credential validation tracking (ON DOMAIN CONTROLLER)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Verify
auditpol /get /category:"Account Logon"
```

### Group Policy (Enterprise - Apply to Domain Controllers)
```
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Account Logon

Apply to: Domain Controllers OU

Enable:
- Audit Kerberos Authentication Service (Success, Failure)
- Audit Credential Validation (Success, Failure)
```

## Event Volume Considerations

**Note**: Enabling Kerberos and NTLM auditing generates significantly more events than just RDP tracking:

- **4768** - Fires for ALL Kerberos TGT requests (not just RDP)
- **4769** - Fires for ALL service ticket requests (file shares, SQL, HTTP, etc.)
- **4776** - Fires for ALL NTLM authentication (not just RDP)

**Impact:**
- Security log on Domain Controller will grow much faster
- May need to increase Security log size (Default: 20 MB → Recommend: 100+ MB on DC)
- Event collection will initially gather ALL authentications from DC

**Automatic Filtering:**
✅ The tool **automatically filters** pre-authentication events to show only those that correlate to RDP sessions (Logon Type 10/7/3/5):
- Non-RDP authentications (SMB file shares, SQL, Exchange, HTTP) are excluded from results
- Only pre-auth events within 0-10 seconds before an RDP logon with matching username are kept
- This dramatically reduces noise in the output

**Mitigation:**
- Use `-IncludeCredentialValidation` only when needed for detailed analysis
- Set appropriate retention policies
- Consider dedicated logging server for high-volume environments

## Performance Notes

When `-IncludeCredentialValidation` is used:

✅ **Optimized:**
- Events filtered to relevant time range (StartDate/EndDate)
- 4776 events filtered to exclude local/localhost (remote only)
- Time-based correlation only processes events within 10-second window

⚠️ **Consider:**
- First run may be slow in high-activity environments (many events to process)
- Subsequent runs with narrow date ranges are fast
- Kerberos events (4768-4772) are not filtered by source - may include non-RDP events

## Best Practices

1. **Enable Auditing in Test Environment First**
   - Assess event volume before production deployment
   - Verify log size requirements

2. **Use Time Ranges**
   - Always specify `-StartDate` and `-EndDate` for faster processing
   - Example: `-StartDate (Get-Date).AddHours(-4)` for recent activity

3. **Monitor Security Log Size**
   - Check current size: `Get-EventLog -List | Where-Object {$_.Log -eq "Security"}`
   - Increase if needed: `Limit-EventLog -LogName Security -MaximumSize 200MB`

4. **Combine with Session Grouping**
   - Use `-GroupBySession` to see complete authentication + session lifecycle
   - Easier to identify which sessions used which authentication method

5. **Review Kerberos Failures**
   - EventID 4771 is KEY - always investigate these first
   - Error codes tell you exactly why Kerberos failed
   - Fix root cause rather than accepting NTLM fallback

## Troubleshooting

### No Kerberos/NTLM Events Showing

**Check Audit Policy:**
```powershell
auditpol /get /category:"Account Logon"
```

Should show:
- Kerberos Authentication Service: Success and Failure
- Credential Validation: Success and Failure

**Check Event Logs:**
```powershell
# Test if events exist
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4768,4769,4771,4776
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 10
```

### Events Not Correlating with Sessions

- **Time Window**: Events must occur 0-10 seconds before session
- **Username**: Must match exactly (domain\username format)
- **Date Range**: Ensure date range includes pre-authentication time

### Too Many Events / Slow Performance

- Narrow date range: `-StartDate (Get-Date).AddHours(-4)`
- Use specific username: `-Username "john.doe"`
- Consider separate analysis runs for different purposes

## Summary

The `-IncludeCredentialValidation` parameter provides comprehensive authentication visibility by tracking:

✅ **What**: Kerberos (4768-4772) and NTLM (4776) pre-authentication events  
✅ **Why**: Understand authentication protocol flow and failure reasons  
✅ **When**: Time-correlated 0-10 seconds before session creation  
✅ **Who**: Username-matched and ActivityID-linked where available  
✅ **Value**: Security analysis, compliance, troubleshooting, attack detection  

Use this feature when you need to understand not just **what** happened in an RDP session, but **how** the user authenticated to get there.

---

**See Also:**
- [README.md](README.md) - Main documentation
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command reference
- [GETTING_STARTED.md](GETTING_STARTED.md) - Tutorial
- [RELEASE_NOTES_v1.0.6.md](RELEASE_NOTES_v1.0.6.md) - Version details
