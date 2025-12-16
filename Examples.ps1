<#
.SYNOPSIS
    Example usage scenarios for RDP forensics tools.

.DESCRIPTION
    This script demonstrates various usage scenarios for the RDP forensics toolkit.
    Run the examples that match your needs.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.8
    Uncomment the scenarios you want to run.
#>

# Ensure we're in the script directory
Set-Location $PSScriptRoot

Write-Host "`n=== RDP Forensics Toolkit - Usage Examples ===" -ForegroundColor CyanWrite-Host "\n⚠️  IMPORTANT: Import the module first!" -ForegroundColor Yellow
Write-Host "   Import-Module .\RDP-Forensic.psm1\n" -ForegroundColor WhiteWrite-Host "Uncomment and run the scenarios that match your needs.`n" -ForegroundColor Yellow

# ============================================================================
# SCENARIO 1: Daily Security Review
# ============================================================================
<#
Write-Host "SCENARIO 1: Daily Security Review" -ForegroundColor Green
Write-Host "Get all RDP activity for today and display summary"

Get-RDPForensics
#>

# ============================================================================
# SCENARIO 2: Weekly Compliance Report
# ============================================================================
<#
Write-Host "SCENARIO 2: Weekly Compliance Report" -ForegroundColor Green
Write-Host "Export last 7 days of RDP activity to CSV for compliance review"

$reportPath = "C:\RDP_Reports\Weekly"
$startDate = (Get-Date).AddDays(-7)

Get-RDPForensics -StartDate $startDate -ExportPath $reportPath

Write-Host "`nReport generated in: $reportPath" -ForegroundColor Cyan
#>

# ============================================================================
# SCENARIO 3: Investigate Specific User
# ============================================================================
<#
Write-Host "SCENARIO 3: User Activity Investigation" -ForegroundColor Green
Write-Host "Track all RDP activity for a specific user"

$targetUser = "admin"  # Change to target username
$investigationPath = "C:\Investigations\$targetUser"

Get-RDPForensics -Username $targetUser -StartDate (Get-Date).AddMonths(-1) -ExportPath $investigationPath

Write-Host "`nInvestigation results saved to: $investigationPath" -ForegroundColor Cyan
#>

# ============================================================================
# SCENARIO 4: Brute Force Attack Detection
# ============================================================================
<#
Write-Host "SCENARIO 4: Brute Force Attack Detection" -ForegroundColor Green
Write-Host "Identify IPs with multiple failed logon attempts"

$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-1)

# Find IPs with more than 5 failed attempts
$bruteForceAttempts = $events | 
    Where-Object { $_.EventID -eq 4625 -and $_.SourceIP -ne 'N/A' } |
    Group-Object SourceIP |
    Where-Object { $_.Count -gt 5 } |
    Sort-Object Count -Descending

if ($bruteForceAttempts) {
    Write-Host "`nPotential Brute Force Attacks Detected:" -ForegroundColor Red
    $bruteForceAttempts | ForEach-Object {
        Write-Host "  IP: $($_.Name) - Failed Attempts: $($_.Count)" -ForegroundColor Yellow
    }
    
    # Export detailed information
    $bruteForceAttempts | ForEach-Object {
        $ip = $_.Name
        $events | Where-Object { $_.SourceIP -eq $ip -and $_.EventID -eq 4625 } |
            Export-Csv "C:\SecurityAlerts\BruteForce_$ip.csv" -NoTypeInformation
    }
} else {
    Write-Host "`nNo brute force patterns detected." -ForegroundColor Green
}
#>

# ============================================================================
# SCENARIO 5: After-Hours Access Monitoring
# ============================================================================
<#
Write-Host "SCENARIO 5: After-Hours Access Monitoring" -ForegroundColor Green
Write-Host "Detect RDP logons outside business hours (6 PM - 6 AM)"

$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-7)

$afterHoursLogons = $events | Where-Object {
    $_.EventID -eq 4624 -and
    ($_.TimeCreated.Hour -lt 6 -or $_.TimeCreated.Hour -ge 18)
}

if ($afterHoursLogons) {
    Write-Host "`nAfter-Hours RDP Logons Detected:" -ForegroundColor Yellow
    $afterHoursLogons | Select-Object TimeCreated, User, SourceIP, Details |
        Format-Table -AutoSize
    
    # Export for review
    $afterHoursLogons | Export-Csv "C:\SecurityAlerts\AfterHours_Logons.csv" -NoTypeInformation
} else {
    Write-Host "`nNo after-hours logons detected." -ForegroundColor Green
}
#>

# ============================================================================
# SCENARIO 6: Unauthorized Source IP Detection
# ============================================================================
<#
Write-Host "SCENARIO 6: Unauthorized Source IP Detection" -ForegroundColor Green
Write-Host "Identify RDP connections from outside authorized IP ranges"

# Define authorized IP ranges (modify as needed)
$authorizedRanges = @(
    '^192\.168\.',      # Local network
    '^10\.',            # Private network
    '^172\.(1[6-9]|2[0-9]|3[01])\.'  # Private network
)

$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-30)

$unauthorizedIPs = $events | Where-Object {
    $_.EventID -eq 4624 -and
    $_.SourceIP -ne 'N/A' -and
    $_.SourceIP -ne '-' -and
    -not ($authorizedRanges | Where-Object { $_.SourceIP -match $_ })
}

if ($unauthorizedIPs) {
    Write-Host "`nUnauthorized IP Connections Detected:" -ForegroundColor Red
    $unauthorizedIPs | Select-Object TimeCreated, User, SourceIP, Details |
        Format-Table -AutoSize
    
    $unauthorizedIPs | Export-Csv "C:\SecurityAlerts\Unauthorized_IPs.csv" -NoTypeInformation
} else {
    Write-Host "`nAll connections from authorized IP ranges." -ForegroundColor Green
}
#>

# ============================================================================
# SCENARIO 7: Session Duration Analysis
# ============================================================================
<#
Write-Host "SCENARIO 7: Session Duration Analysis" -ForegroundColor Green
Write-Host "Calculate session durations and identify long-running sessions"

$events = Get-RDPForensics -StartDate (Get-Date).AddDays(-7)

# Group logon and logoff events by user and LogonID
$logons = $events | Where-Object { $_.EventID -eq 4624 }
$logoffs = $events | Where-Object { $_.EventID -in 4634, 4647, 23 }

$sessionDurations = @()

foreach ($logon in $logons) {
    $matchingLogoff = $logoffs | 
        Where-Object { 
            $_.User -eq $logon.User -and 
            $_.LogonID -eq $logon.LogonID -and
            $_.TimeCreated -gt $logon.TimeCreated 
        } | 
        Select-Object -First 1
    
    if ($matchingLogoff) {
        $duration = $matchingLogoff.TimeCreated - $logon.TimeCreated
        
        $sessionDurations += [PSCustomObject]@{
            User = $logon.User
            LogonTime = $logon.TimeCreated
            LogoffTime = $matchingLogoff.TimeCreated
            Duration = $duration
            DurationHours = [math]::Round($duration.TotalHours, 2)
            SourceIP = $logon.SourceIP
        }
    }
}

if ($sessionDurations) {
    Write-Host "`nSession Duration Analysis:" -ForegroundColor Yellow
    $sessionDurations | Sort-Object DurationHours -Descending |
        Select-Object User, LogonTime, LogoffTime, DurationHours, SourceIP |
        Format-Table -AutoSize
    
    # Flag sessions longer than 12 hours
    $longSessions = $sessionDurations | Where-Object { $_.DurationHours -gt 12 }
    if ($longSessions) {
        Write-Host "`nLong-running sessions (>12 hours):" -ForegroundColor Red
        $longSessions | Format-Table -AutoSize
    }
}
#>

# ============================================================================
# SCENARIO 8: Monitor Current Sessions
# ============================================================================
<#
Write-Host "SCENARIO 8: Monitor Current Active Sessions" -ForegroundColor Green
Write-Host "Display currently active RDP sessions with process information"

Get-CurrentRDPSessions -ShowProcesses
#>

# ============================================================================
# SCENARIO 9: Monthly Executive Report
# ============================================================================
<#
Write-Host "SCENARIO 9: Monthly Executive Report" -ForegroundColor Green
Write-Host "Generate comprehensive monthly RDP access report"

$reportMonth = (Get-Date).AddMonths(-1)
$startDate = Get-Date -Year $reportMonth.Year -Month $reportMonth.Month -Day 1 -Hour 0 -Minute 0 -Second 0
$endDate = $startDate.AddMonths(1).AddSeconds(-1)
$reportPath = "C:\Reports\RDP\Monthly\$($reportMonth.ToString('yyyy-MM'))"

Write-Host "Generating report for: $($reportMonth.ToString('MMMM yyyy'))" -ForegroundColor Cyan

$events = Get-RDPForensics -StartDate $startDate -EndDate $endDate -ExportPath $reportPath

# Generate statistics
$stats = @{
    TotalEvents = $events.Count
    UniqueUsers = ($events | Where-Object { $_.User -ne 'N/A' } | Select-Object -ExpandProperty User -Unique).Count
    UniqueIPs = ($events | Where-Object { $_.SourceIP -ne 'N/A' } | Select-Object -ExpandProperty SourceIP -Unique).Count
    SuccessfulLogons = ($events | Where-Object { $_.EventID -eq 4624 }).Count
    FailedLogons = ($events | Where-Object { $_.EventID -eq 4625 }).Count
    TotalSessions = ($events | Where-Object { $_.EventID -eq 21 }).Count
}

Write-Host "`nMonthly Statistics:" -ForegroundColor Yellow
$stats.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Gray
}

Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
#>

# ============================================================================
# SCENARIO 11: Real-Time Session Monitoring (Auto-Refresh)
# ============================================================================
<#
Write-Host "SCENARIO 11: Real-Time Session Monitoring (Auto-Refresh)" -ForegroundColor Green
Write-Host "Continuously monitor active RDP sessions with auto-refresh"
Write-Host ""
Write-Host "Use Case: Security incident response, maintenance windows, or live threat monitoring" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to exit monitoring mode" -ForegroundColor Yellow
Write-Host ""

# Option 1: Basic real-time monitoring with 5-second refresh (default)
Get-CurrentRDPSessions -Watch

# Option 2: Fast monitoring during incident response (3-second refresh)
# Get-CurrentRDPSessions -Watch -RefreshInterval 3

# Option 3: Detailed monitoring with processes shown (10-second refresh)
# Get-CurrentRDPSessions -Watch -ShowProcesses -RefreshInterval 10

# Option 4: Slower monitoring for long-term observation (30-second refresh)
# Get-CurrentRDPSessions -Watch -RefreshInterval 30

# Option 5: Monitor with change logging for forensic analysis
# Get-CurrentRDPSessions -Watch -LogPath "C:\Logs\RDP_Monitor"

# Option 6: Full monitoring - Watch, logging, and process tracking
# Get-CurrentRDPSessions -Watch -RefreshInterval 5 -LogPath "C:\SecurityLogs\RDP" -ShowProcesses

Write-Host "`nReal-time monitoring provides:" -ForegroundColor Yellow
Write-Host "  - Automatic screen refresh at configured intervals" -ForegroundColor Gray
Write-Host "  - Live session state tracking (Active/Disconnected)" -ForegroundColor Gray
Write-Host "  - Immediate detection of new connections" -ForegroundColor Gray
Write-Host "  - Continuous user activity monitoring" -ForegroundColor Gray
Write-Host "  - Real-time logon information updates" -ForegroundColor Gray
Write-Host "  - Change logging to CSV for forensic analysis (with -LogPath)" -ForegroundColor Gray
Write-Host "  - Logs new sessions, state changes, and disconnections" -ForegroundColor Gray
#>

# ============================================================================
# SCENARIO 10: Incident Response - Full Investigation
# ============================================================================
<#
Write-Host "SCENARIO 10: Incident Response - Full Investigation" -ForegroundColor Green
Write-Host "Comprehensive RDP forensics collection for incident response"

$incidentDate = Get-Date "2025-12-01"  # Change to incident date
$investigationPath = "C:\IncidentResponse\RDP_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

Write-Host "Investigation started at: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Incident date: $incidentDate" -ForegroundColor Cyan
Write-Host "Output path: $investigationPath" -ForegroundColor Cyan

# Collect 7 days before and after incident
$startDate = $incidentDate.AddDays(-7)
$endDate = $incidentDate.AddDays(7)

# Full collection including outbound connections
$events = Get-RDPForensics -StartDate $startDate -EndDate $endDate -ExportPath $investigationPath -IncludeOutbound

Write-Host "`n=== Investigation Summary ===" -ForegroundColor Yellow

# Failed logon attempts
$failedLogons = $events | Where-Object { $_.EventID -eq 4625 }
Write-Host "Failed Logon Attempts: $($failedLogons.Count)" -ForegroundColor $(if ($failedLogons.Count -gt 10) { 'Red' } else { 'Gray' })

# Unique suspicious IPs
$suspiciousIPs = $failedLogons | Group-Object SourceIP | Where-Object { $_.Count -gt 3 }
if ($suspiciousIPs) {
    Write-Host "Suspicious IPs (>3 failed attempts):" -ForegroundColor Red
    $suspiciousIPs | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) attempts" -ForegroundColor Yellow
    }
}

# Get current sessions at time of investigation
Write-Host "`n=== Current RDP Sessions ===" -ForegroundColor Yellow
Get-CurrentRDPSessions -ShowProcesses

Write-Host "`nInvestigation complete. Results saved to: $investigationPath" -ForegroundColor Green
#>

# ============================================================================
# SCENARIO 12: Session Correlation & Lifecycle Analysis (NEW in v1.0.4)
# ============================================================================
<#
Write-Host "SCENARIO 12: Session Correlation & Lifecycle Analysis" -ForegroundColor Green
Write-Host "Correlate events across all log sources to track complete session lifecycles"

$reportPath = "C:\RDP_Reports\Sessions"

# Analyze last 7 days with session grouping
Write-Host "`nAnalyzing sessions from last 7 days..." -ForegroundColor Cyan
$sessions = Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -GroupBySession -ExportPath $reportPath

# Find incomplete sessions (missing logoff, etc.)
$incompleteSessions = $sessions | Where-Object { -not $_.LifecycleComplete }
if ($incompleteSessions) {
    Write-Host "`n=== Incomplete Sessions Detected ===" -ForegroundColor Yellow
    Write-Host "Found $($incompleteSessions.Count) incomplete sessions (missing logoff or other stages)" -ForegroundColor Red
    $incompleteSessions | Select-Object User, SourceIP, StartTime, Duration | Format-Table
}

# Find long-running sessions (over 8 hours)
Write-Host "`n=== Long-Running Sessions ===" -ForegroundColor Yellow
$longSessions = $sessions | Where-Object { 
    $_.Duration -and 
    [timespan]::Parse($_.Duration).TotalHours -gt 8 
}
if ($longSessions) {
    Write-Host "Found $($longSessions.Count) sessions over 8 hours" -ForegroundColor Cyan
    $longSessions | Select-Object User, SourceIP, StartTime, Duration | Format-Table
}

# User activity summary
Write-Host "`n=== User Activity Summary ===" -ForegroundColor Yellow
$userActivity = $sessions | Where-Object { $_.User -ne 'N/A' } | Group-Object User | Sort-Object Count -Descending
$userActivity | Select-Object @{N='User';E={$_.Name}}, Count, @{N='FirstSession';E={($_.Group | Sort-Object StartTime)[0].StartTime}} | Format-Table

Write-Host "`nSession analysis complete. Exported to:" -ForegroundColor Green
Write-Host "  Events: $reportPath\RDP_Forensics_<timestamp>.csv" -ForegroundColor Gray
Write-Host "  Sessions: $reportPath\RDP_Sessions_<timestamp>.csv" -ForegroundColor Gray
#>

# ============================================================================
# SCENARIO 13: Test v1.0.7 Enhanced Correlation (NEW)
# ============================================================================
<#
Write-Host "SCENARIO 13: Test v1.0.7 Enhanced Correlation" -ForegroundColor Green
Write-Host "Demonstrates improved LogonID-first correlation with SessionID merging"
Write-Host ""

# Test 1: View improved session correlation
Write-Host "Test 1: Session Correlation with LogonID-first + SessionID Merge" -ForegroundColor Cyan
Write-Host "Should show fewer fragmented sessions, higher event counts per session" -ForegroundColor Yellow
Write-Host ""

$sessions = Get-RDPForensics -StartDate (Get-Date).AddHours(-2) -GroupBySession

# Display first 3 sessions with detailed info
$sessions | Select-Object -First 3 | Format-List `
    CorrelationKey, 
    User, 
    SourceIP, 
    EventCount, 
    StartTime, 
    EndTime, 
    Duration, 
    ConnectionAttempt, 
    Logon, 
    Active, 
    Logoff, 
    LifecycleComplete

Write-Host "`nKey Improvements in v1.0.7:" -ForegroundColor Green
Write-Host "  ✓ LogonID-first correlation (better cross-log matching)" -ForegroundColor Gray
Write-Host "  ✓ Secondary correlation merges SessionID into LogonID sessions" -ForegroundColor Gray
Write-Host "  ✓ Matching criteria: Username + Time (±10s) + RDP LogonType (10/7/3)" -ForegroundColor Gray
Write-Host ""

# Test 2: View merged events in a single session
Write-Host "Test 2: View All Events in First Session (Security + TerminalServices merged)" -ForegroundColor Cyan
Write-Host ""

$firstSession = $sessions | Select-Object -First 1
Write-Host "Session: $($firstSession.CorrelationKey)" -ForegroundColor White
Write-Host "Total Events: $($firstSession.EventCount) (should include both Security + TerminalServices)" -ForegroundColor Yellow
Write-Host ""

$firstSession.Events | Select-Object TimeCreated, EventID, EventType, User, SessionID, LogonID | 
    Format-Table -AutoSize

Write-Host "`nExpected Event Types in Complete Session:" -ForegroundColor Green
Write-Host "  • Connection Attempt (1149)" -ForegroundColor Gray
Write-Host "  • Successful Logon (4624)" -ForegroundColor Gray
Write-Host "  • Session Logon Succeeded (21)" -ForegroundColor Gray
Write-Host "  • Shell Start Notification (22)" -ForegroundColor Gray
Write-Host "  • Session Reconnected (4778) or Disconnected (4779)" -ForegroundColor Gray
Write-Host "  • Session Logoff Succeeded (23)" -ForegroundColor Gray
Write-Host "  • Account Logged Off (4634)" -ForegroundColor Gray
Write-Host ""

# Test 3: Compare correlation efficiency
Write-Host "Test 3: Correlation Efficiency Statistics" -ForegroundColor Cyan
Write-Host ""

$totalSessions = $sessions.Count
$completeLifecycle = ($sessions | Where-Object { $_.LifecycleComplete }).Count
$avgEventCount = ($sessions | Measure-Object -Property EventCount -Average).Average
$logonIDSessions = ($sessions | Where-Object { $_.CorrelationKey -like "LogonID:*" }).Count
$sessionIDOnly = ($sessions | Where-Object { $_.CorrelationKey -like "SessionID:*" }).Count

Write-Host "Total Sessions: $totalSessions" -ForegroundColor White
Write-Host "Complete Lifecycle: $completeLifecycle ($([math]::Round($completeLifecycle/$totalSessions*100, 1))%)" -ForegroundColor Green
Write-Host "Average Events/Session: $([math]::Round($avgEventCount, 1))" -ForegroundColor Yellow
Write-Host "LogonID-correlated: $logonIDSessions" -ForegroundColor Cyan
Write-Host "SessionID-only (not merged): $sessionIDOnly" -ForegroundColor $(if($sessionIDOnly -eq 0){'Green'}else{'Yellow'})"
Write-Host ""

Write-Host "✓ Test complete! Sessions should show better correlation in v1.0.7" -ForegroundColor Green
#>

# ============================================================================
# SCENARIO 14: Filter by LogonID (NEW in v1.0.7)
# ============================================================================
<#
Write-Host "SCENARIO 14: Filter Specific Session by LogonID" -ForegroundColor Green
Write-Host "Use the new -LogonID parameter to analyze a specific Security log session"
Write-Host ""

# First, get all sessions to find LogonIDs
Write-Host "Step 1: Get all sessions and list LogonIDs" -ForegroundColor Cyan
$sessions = Get-RDPForensics -StartDate (Get-Date).AddHours(-4) -GroupBySession
$sessions | Select-Object CorrelationKey, User, @{N='Events';E={$_.Events.Count}}, Duration | 
    Format-Table -AutoSize

# Pick a specific LogonID to investigate
Write-Host "`nStep 2: Investigate specific LogonID session" -ForegroundColor Cyan
$targetLogonID = $sessions[0].LogonID  # Or manually specify: '0x6950A4'
Write-Host "Filtering for LogonID: $targetLogonID" -ForegroundColor Yellow
Write-Host ""

# Get detailed view of this specific session
Get-RDPForensics -StartDate (Get-Date).AddHours(-4) -GroupBySession -LogonID $targetLogonID

Write-Host "`nUse Case: Forensic analysis of specific authentication event" -ForegroundColor Green
Write-Host "  ✓ Direct access to session by Security log identifier" -ForegroundColor Gray
Write-Host "  ✓ No need for Where-Object pipelines" -ForegroundColor Gray
Write-Host "  ✓ Cleaner syntax for incident response" -ForegroundColor Gray
#>

# ============================================================================
# SCENARIO 15: Filter by SessionID (NEW in v1.0.7)
# ============================================================================
<#
Write-Host "SCENARIO 15: Filter Specific Session by SessionID" -ForegroundColor Green
Write-Host "Use the new -SessionID parameter to analyze a specific TerminalServices session"
Write-Host ""

# First, get all sessions to find SessionIDs
Write-Host "Step 1: Get all sessions and list SessionIDs" -ForegroundColor Cyan
$sessions = Get-RDPForensics -StartDate (Get-Date).AddHours(-4) -GroupBySession
$sessions | Select-Object CorrelationKey, User, SessionID, @{N='Events';E={$_.Events.Count}}, Duration | 
    Format-Table -AutoSize

# Pick a specific SessionID to investigate
Write-Host "`nStep 2: Investigate specific SessionID session" -ForegroundColor Cyan
$targetSessionID = '5'  # TerminalServices session ID
Write-Host "Filtering for SessionID: $targetSessionID" -ForegroundColor Yellow
Write-Host ""

# Get detailed view of this specific session
Get-RDPForensics -StartDate (Get-Date).AddHours(-4) -GroupBySession -SessionID $targetSessionID

Write-Host "`nUse Case: Troubleshoot specific RDP session number" -ForegroundColor Green
Write-Host "  ✓ Match terminal session ID from user complaints" -ForegroundColor Gray
Write-Host "  ✓ Correlate with task manager session ID" -ForegroundColor Gray
Write-Host "  ✓ Quick session lookup for support scenarios" -ForegroundColor Gray
#>

# ============================================================================
# SCENARIO 16: Domain Controller Correlation Testing (NEW in v1.0.7)
# ============================================================================
<#
Write-Host "SCENARIO 16: Test Domain Controller Session Correlation" -ForegroundColor Green
Write-Host "Verify v1.0.7 fixes for 4624 event parsing on Domain Controllers"
Write-Host ""

Write-Host "Testing improved DC correlation:" -ForegroundColor Cyan
Write-Host "  • 4624 events now extract from 'New Logon:' section (not 'Subject:')" -ForegroundColor Yellow
Write-Host "  • Username format: DOMAIN\User (consistent with TerminalServices)" -ForegroundColor Yellow
Write-Host "  • LogonID extracted correctly (not '0x0' SYSTEM account)" -ForegroundColor Yellow
Write-Host ""

# Run on Domain Controller
$sessions = Get-RDPForensics -StartDate (Get-Date).AddHours(-5) `
    -Username "contoso\administrator" `
    -GroupBySession

Write-Host "Expected Results:" -ForegroundColor Green
Write-Host "  ✓ Sessions show as 'LogonID:0x...' (not 'SessionID:...')" -ForegroundColor Gray
Write-Host "  ✓ Complete duration tracking (not 00:00:00)" -ForegroundColor Gray
Write-Host "  ✓ Multiple events per session (merged correlation)" -ForegroundColor Gray
Write-Host "  ✓ User format: 'CONTOSO\administrator' (not '-' or bare username)" -ForegroundColor Gray
Write-Host ""

# Validate session properties
$sessions | ForEach-Object {
    Write-Host "Session: $($_.CorrelationKey)" -ForegroundColor White
    Write-Host "  User: $($_.User) $(if($_.User -notmatch '\\'){Write-Host '❌ Missing domain prefix' -ForegroundColor Red}else{Write-Host '✓' -ForegroundColor Green})"
    Write-Host "  LogonID: $($_.LogonID) $(if($_.LogonID -eq '0x0'){Write-Host '❌ Wrong LogonID (SYSTEM)' -ForegroundColor Red}else{Write-Host '✓' -ForegroundColor Green})"
    Write-Host "  Events: $($_.Events.Count) $(if($_.Events.Count -lt 3){Write-Host '⚠️ Low event count' -ForegroundColor Yellow}else{Write-Host '✓' -ForegroundColor Green})"
    Write-Host "  Duration: $($_.Duration) $(if($_.Duration.TotalSeconds -eq 0 -and $_.Events.Count -gt 1){Write-Host '❌ No duration calc' -ForegroundColor Red}else{Write-Host '✓' -ForegroundColor Green})"
    Write-Host ""
}

Write-Host "✓ Domain Controller correlation test complete" -ForegroundColor Green
#>

# ============================================================================
# SCENARIO 17: Workgroup Server Correlation Testing (NEW in v1.0.7)
# ============================================================================
<#
Write-Host "SCENARIO 17: Test Workgroup Server Session Correlation" -ForegroundColor Green
Write-Host "Verify v1.0.7 synchronized event detection on workgroup servers"
Write-Host ""

Write-Host "Testing workgroup correlation:" -ForegroundColor Cyan
Write-Host "  • Synchronized event detection (2+ events within 3 seconds)" -ForegroundColor Yellow
Write-Host "  • Username format: COMPUTERNAME\User" -ForegroundColor Yellow
Write-Host "  • SessionID + LogonID session merging" -ForegroundColor Yellow
Write-Host ""

# Run on Workgroup Server
$beforeCount = (Get-RDPForensics -StartDate (Get-Date).AddHours(-5) -GroupBySession | 
    Measure-Object).Count

Write-Host "Session count: $beforeCount" -ForegroundColor White

# Filter for administrator
$sessions = Get-RDPForensics -StartDate (Get-Date).AddHours(-5) `
    -Username "administrator" `
    -GroupBySession

Write-Host "Administrator sessions: $($sessions.Count)" -ForegroundColor White
Write-Host ""

Write-Host "Expected Results:" -ForegroundColor Green
Write-Host "  ✓ Fewer sessions than v1.0.6 (merge reduces count)" -ForegroundColor Gray
Write-Host "  ✓ Merged session has 10+ events (SessionID + LogonID combined)" -ForegroundColor Gray
Write-Host "  ✓ User format: 'COMPUTERNAME\Administrator'" -ForegroundColor Gray
Write-Host "  ✓ Complete duration tracking despite event gaps" -ForegroundColor Gray
Write-Host ""

# Validate merged sessions
$sessions | ForEach-Object {
    Write-Host "Session: $($_.CorrelationKey)" -ForegroundColor White
    Write-Host "  User: $($_.User)"
    Write-Host "  SessionID: $($_.SessionID) $(if($_.SessionID -and $_.SessionID -ne 'N/A'){Write-Host '✓ Has SessionID' -ForegroundColor Green})"
    Write-Host "  LogonID: $($_.LogonID) $(if($_.LogonID -and $_.LogonID -ne 'N/A'){Write-Host '✓ Has LogonID' -ForegroundColor Green})"
    Write-Host "  Events: $($_.Events.Count) $(if($_.Events.Count -ge 10){Write-Host '✓ Merged session' -ForegroundColor Green}else{Write-Host '⚠️ May not be merged' -ForegroundColor Yellow})"
    Write-Host "  Duration: $($_.Duration)"
    
    # Check for synchronized events
    $terminalServices = ($_.Events | Where-Object { $_.EventID -in 21,22,23,24,25,39,40 }).Count
    $security = ($_.Events | Where-Object { $_.EventID -in 4624,4778,4779,4634,4647 }).Count
    
    Write-Host "  TerminalServices events: $terminalServices"
    Write-Host "  Security events: $security"
    if ($terminalServices -gt 0 -and $security -gt 0) {
        Write-Host "  ✓ Successfully merged SessionID + LogonID" -ForegroundColor Green
    }
    Write-Host ""
}

Write-Host "✓ Workgroup server correlation test complete" -ForegroundColor Green
#>

# ============================================================================
# SCENARIO 18: Combine New Filters (NEW in v1.0.7)
# ============================================================================
<#
Write-Host "SCENARIO 18: Combine Multiple Filters" -ForegroundColor Green
Write-Host "Demonstrate combining new LogonID/SessionID filters with existing filters"
Write-Host ""

# Example 1: Username + LogonID
Write-Host "Example 1: Filter by Username AND LogonID" -ForegroundColor Cyan
Get-RDPForensics -StartDate (Get-Date).AddHours(-4) `
    -Username "administrator" `
    -LogonID "0x6950A4" `
    -GroupBySession

# Example 2: Source IP + SessionID
Write-Host "`nExample 2: Filter by Source IP AND SessionID" -ForegroundColor Cyan
Get-RDPForensics -StartDate (Get-Date).AddHours(-4) `
    -SourceIP "172.16.0.2" `
    -SessionID "5" `
    -GroupBySession

# Example 3: Export specific session
Write-Host "`nExample 3: Export Specific Session by LogonID" -ForegroundColor Cyan
$reportPath = "C:\RDP_Reports\SpecificSession"
Get-RDPForensics -StartDate (Get-Date).AddDays(-1) `
    -LogonID "0x6950A4" `
    -GroupBySession `
    -ExportPath $reportPath

Write-Host "`nUse Cases:" -ForegroundColor Green
Write-Host "  ✓ Forensic analysis: Narrow down to exact session" -ForegroundColor Gray
Write-Host "  ✓ Incident response: Quick session export for evidence" -ForegroundColor Gray
Write-Host "  ✓ Troubleshooting: Isolate specific user's session" -ForegroundColor Gray
#>

Write-Host "`nTo run an example, uncomment the desired scenario in this file and run again." -ForegroundColor Cyan
Write-Host "Example scenarios available:" -ForegroundColor Yellow
Write-Host "  1. Daily Security Review" -ForegroundColor Gray
Write-Host "  2. Weekly Compliance Report" -ForegroundColor Gray
Write-Host "  3. Investigate Specific User" -ForegroundColor Gray
Write-Host "  4. Brute Force Attack Detection" -ForegroundColor Gray
Write-Host "  5. After-Hours Access Monitoring" -ForegroundColor Gray
Write-Host "  6. Unauthorized Source IP Detection" -ForegroundColor Gray
Write-Host "  7. Session Duration Analysis" -ForegroundColor Gray
Write-Host "  8. Monitor Current Sessions" -ForegroundColor Gray
Write-Host "  9. Monthly Executive Report" -ForegroundColor Gray
Write-Host " 10. Incident Response - Full Investigation" -ForegroundColor Gray
Write-Host " 11. Real-Time Session Monitoring (Auto-Refresh)" -ForegroundColor Gray
Write-Host " 12. Session Correlation & Lifecycle Analysis" -ForegroundColor Gray
Write-Host " 13. Test v1.0.7 Enhanced Correlation" -ForegroundColor Gray
Write-Host " 14. Filter by LogonID (NEW in v1.0.7)" -ForegroundColor Green
Write-Host " 15. Filter by SessionID (NEW in v1.0.7)" -ForegroundColor Green
Write-Host " 16. Domain Controller Correlation Testing (NEW in v1.0.7)" -ForegroundColor Green
Write-Host " 17. Workgroup Server Correlation Testing (NEW in v1.0.7)" -ForegroundColor Green
Write-Host " 18. Combine New Filters (NEW in v1.0.7)" -ForegroundColor Green
Write-Host ""

