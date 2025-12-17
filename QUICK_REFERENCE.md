# RDP Forensics Quick Reference

> **⚠️ PREREQUISITE:** Import the module before using any cmdlets:
> ```powershell
> Import-Module .\RDP-Forensic.psm1
> ```

## Event ID Quick Lookup

### Critical RDP Event IDs

```
CONNECTION ATTEMPTS
├─ 1149: Connection attempt (RemoteConnectionManager)

CREDENTIAL SUBMISSION (NEW v1.0.8)
└─ 4648: Explicit credential usage (Security) - Logs credential submission BEFORE logon

AUTHENTICATION
├─ 4624: Successful logon (Security)
├─ 4625: Failed logon (Security)

PRE-AUTHENTICATION (Optional with -IncludeCredentialValidation)
├─ 4768: Kerberos TGT request (Security)
├─ 4769: Kerberos service ticket request (Security)
├─ 4770: Kerberos ticket renewed (Security)
├─ 4771: Kerberos pre-authentication failed (Security) ⚠️ Shows why Kerberos failed
├─ 4772: Kerberos ticket request failed (Security)
└─ 4776: NTLM credential validation (Security) - Fallback when Kerberos fails

SESSION LIFECYCLE
├─ 21: Session logon succeeded (LocalSessionManager)
├─ 22: Shell started (LocalSessionManager)
├─ 23: Session logoff (LocalSessionManager)
├─ 24: Session disconnected (LocalSessionManager)
├─ 25: Session reconnected (LocalSessionManager)
├─ 39: Disconnected by another session (LocalSessionManager)
├─ 40: Disconnected with reason code (LocalSessionManager)

LOCK/UNLOCK
├─ 4800: Workstation locked (Security)
├─ 4801: Workstation unlocked (Security)

RECONNECT/DISCONNECT
├─ 4778: Session reconnected (Security)
├─ 4779: Session disconnected (Security)

LOGOFF
├─ 4634: Account logged off (Security)
├─ 4647: User-initiated logoff (Security)
└─ 9009: DWM exited (System)

OUTBOUND
└─ 1102: RDP client connection (RDPClient)
```

## Logon Type Reference

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Local keyboard/screen logon |
| 3 | Network | Network connection (shared folder, etc.) |
| 5 | Service | Service started by Service Control Manager |
| 7 | Unlock | Workstation unlock or session reconnect |
| 10 | RemoteInteractive | Terminal Services/RDP logon |
| 11 | CachedInteractive | Logon with cached credentials |

## Session Disconnect Reason Codes

| Code | Meaning |
|------|---------|
| 0 | No additional information available (user closed RDP window) |
| 5 | Client connection replaced by another connection |
| 11 | User activity initiated the disconnect (clicked Disconnect) |

## Common PowerShell One-Liners

### Get Today's RDP Logons
```powershell
Get-EventLog security -after (Get-date -hour 0 -minute 0 -second 0) | Where-Object {$_.eventid -eq 4624 -and $_.Message -match 'logon type:\s+(10)\s'} | Select-Object TimeGenerated, @{N='User';E={$_.ReplacementStrings[5]}}, @{N='SourceIP';E={$_.ReplacementStrings[18]}}
```

### Get Failed RDP Attempts (Brute Force Detection)
```powershell
Get-EventLog security -after (Get-date).AddHours(-24) | Where-Object {$_.eventid -eq 4625 -and $_.Message -match 'logon type:\s+(10)\s'} | Group-Object @{E={$_.ReplacementStrings[19]}} | Sort-Object Count -Descending
```

### Get Pre-Authentication Events (Kerberos & NTLM) - NEW v1.0.6
```powershell
# Using toolkit with time-based correlation (RECOMMENDED)
Get-RDPForensics -IncludeCredentialValidation -GroupBySession

# Direct Kerberos event query
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4768 or EventID=4771)]]' -MaxEvents 20

# Direct NTLM event query
Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4776]]' | ForEach-Object { [xml]$xml=$_.ToXml(); [PSCustomObject]@{Time=$_.TimeCreated; User=$xml.Event.EventData.Data[0].'#text'; Workstation=$xml.Event.EventData.Data[1].'#text'; ErrorCode=$xml.Event.EventData.Data[2].'#text'}}
```

### Get RDP Connection Attempts with User Info
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '*[System[EventID=1149]]' | ForEach-Object { [xml]$xml=$_.ToXml(); [PSCustomObject]@{Time=$_.TimeCreated; User=$xml.Event.UserData.EventXML.Param1; Domain=$xml.Event.UserData.EventXML.Param2; IP=$xml.Event.UserData.EventXML.Param3}}
```

### Get Session Disconnect Events
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | Where-Object {$_.Id -in 24,25,39,40} | Select-Object TimeCreated, Id, Message
```

### Current Active Sessions
```powershell
qwinsta
```

### Kill Specific Session
```powershell
logoff <SessionID>
```

### Get Processes in Session
```powershell
qprocess /id:<SessionID>
```

## Event Log Paths

```powershell
# Security Log
Get-WinEvent -LogName Security

# Terminal Services - Remote Connection Manager
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'

# Terminal Services - Local Session Manager
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'

# Terminal Services - RDP Client
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational'

# System Log
Get-WinEvent -LogName System
```

## Useful Filters

### Get Events from Last N Days
```powershell
$startDate = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$startDate}
```

### Filter by User
```powershell
Get-EventLog Security | Where-Object {$_.Message -match 'Account Name:\s+username'}
```

### Filter by IP
```powershell
Get-EventLog Security | Where-Object {$_.Message -match 'Source Network Address:\s+192.168.1.100'}
```

## Audit Policy Requirements

### Check Current Audit Settings
```powershell
# Check logon/logoff auditing
auditpol /get /category:"Logon/Logoff"

# Check account logon auditing (Kerberos/NTLM)
auditpol /get /category:"Account Logon"

# Check all
auditpol /get /category:*
```

### Enable Required Policies
```powershell
# Required for basic RDP tracking (4624, 4634, 4778, 4779, 4800, 4801)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Optional for -IncludeCredentialValidation (4768-4772, 4776)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

### Disable Optional Policies (Reduce Log Volume)
```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable
```

## Export Examples

### Export to CSV
```powershell
Get-EventLog Security -After (Get-Date).AddDays(-7) | Where-Object {$_.EventId -eq 4624} | Export-Csv -Path "C:\RDP_Logons.csv" -NoTypeInformation
```

### Export Event Log to EVTX
```powershell
wevtutil epl Security C:\Security_Backup.evtx
```

### Export with WinEvent
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | Export-Csv C:\RDP_Sessions.csv -NoTypeInformation
```

## Increase Event Log Size

```powershell
# Increase Security log to 1GB
wevtutil sl Security /ms:1073741824

# Increase TerminalServices logs
wevtutil sl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /ms:104857600
wevtutil sl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /ms:104857600
```

## Enable RDP Connection Logging

```powershell
# Enable via Group Policy or Registry
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableWinStation' -Value 1
```

## Clear RDP Connection History (Forensics - Incident Detection)

```powershell
# Check for cleared logs (suspicious activity)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}

# Event ID 1102 = Security log was cleared
```

## Remote Analysis

### Query Remote Computer
```powershell
Get-WinEvent -ComputerName SERVER01 -FilterHashtable @{LogName='Security'; Id=4624}
```

### Multiple Computers
```powershell
$computers = @('SERVER01','SERVER02','SERVER03')
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-1)} | Where-Object {$_.Message -match 'logon type:\s+(10)\s'}
}
```

## Forensic Investigation Workflow

1. **Identify Time Window**
   - When was suspicious activity reported?
   - Set appropriate StartDate/EndDate

2. **Collect Initial Data**
   ```powershell
   Get-RDPForensics -StartDate $incidentDate -ExportPath C:\Investigation
   ```

3. **Analyze Connection Attempts**
   - Look for EventID 1149 (connection attempts)
   - Identify unusual IPs or times

4. **Check Authentication**
   - EventID 4625 (failed logons) - brute force indicators
   - EventID 4624 (successful logons) - compromised account

5. **Track Session Activity**
   - Session duration analysis
   - Disconnect/reconnect patterns
   - Unusual session times

6. **Cross-Reference**
   - Compare with firewall logs
   - Check application logs
   - Review file access logs

## Alert Thresholds (Recommendations)

- **Failed Logons**: >5 from same IP in 10 minutes
- **After Hours Access**: Administrative logons outside 9-5
- **Geographic Anomalies**: Logons from unexpected countries
- **Session Duration**: Sessions >12 hours
- **Rapid Reconnects**: >3 reconnects in 5 minutes

## Common Investigation Scenarios

### Scenario 1: Brute Force Attack
```powershell
# Get failed attempts grouped by IP
$events = Get-RDPForensics -StartDate (Get-Date).AddHours(-24)
$events | Where-Object {$_.EventID -eq 4625} | Group-Object SourceIP | Where-Object {$_.Count -gt 5} | Sort-Object Count -Descending
```

### Scenario 2: Compromised Account
```powershell
# Track all activity for specific user
Get-RDPForensics -Username "admin" -StartDate (Get-Date).AddDays(-7) -ExportPath C:\Investigation
```

### Scenario 3: Unauthorized Access
```powershell
# Find logons from unusual IPs
$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-30)
$events | Where-Object {$_.EventID -eq 4624 -and $_.SourceIP -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))'}
```

## Registry Locations (Additional Forensics)

```powershell
# RDP Connection History
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Terminal Server Client\Default'

# Saved RDP Connections
Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'

# RDP Port Configuration
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber
```

## Performance Tips

1. Use specific date ranges
2. Filter early in pipeline
3. Export to file for large datasets
4. Use FilterHashtable instead of Where-Object for Get-WinEvent
5. Process data in chunks for very large logs

## Retention Recommendations

| Log Type | Minimum Retention | Recommended |
|----------|-------------------|-------------|
| Security | 30 days | 90 days |
| TerminalServices | 30 days | 60 days |
| System | 7 days | 30 days |

## Related Commands

```powershell
# Disable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Check RDP Status
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"

# Enable NLA (Network Level Authentication)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# View RDP Listeners
Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices
```
