<#
.SYNOPSIS
    Example usage scenarios for RDP forensics tools.

.DESCRIPTION
    This script demonstrates various usage scenarios for the RDP forensics toolkit.
    Run the examples that match your needs.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.6
    Uncomment the scenarios you want to run.
#>

# Ensure we're in the script directory
Set-Location $PSScriptRoot

Write-Host "`n=== RDP Forensics Toolkit - Usage Examples ===" -ForegroundColor Cyan
Write-Host "Uncomment and run the scenarios that match your needs.`n" -ForegroundColor Yellow

# ============================================================================
# SCENARIO 1: Daily Security Review
# ============================================================================
<#
Write-Host "SCENARIO 1: Daily Security Review" -ForegroundColor Green
Write-Host "Get all RDP activity for today and display summary"

.\Get-RDPForensics.ps1
#>

# ============================================================================
# SCENARIO 2: Weekly Compliance Report
# ============================================================================
<#
Write-Host "SCENARIO 2: Weekly Compliance Report" -ForegroundColor Green
Write-Host "Export last 7 days of RDP activity to CSV for compliance review"

$reportPath = "C:\RDP_Reports\Weekly"
$startDate = (Get-Date).AddDays(-7)

.\Get-RDPForensics.ps1 -StartDate $startDate -ExportPath $reportPath

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

.\Get-RDPForensics.ps1 -Username $targetUser -StartDate (Get-Date).AddMonths(-1) -ExportPath $investigationPath

Write-Host "`nInvestigation results saved to: $investigationPath" -ForegroundColor Cyan
#>

# ============================================================================
# SCENARIO 4: Brute Force Attack Detection
# ============================================================================
<#
Write-Host "SCENARIO 4: Brute Force Attack Detection" -ForegroundColor Green
Write-Host "Identify IPs with multiple failed logon attempts"

$events = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-1)

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

$events = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-7)

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

$events = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-30)

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

$events = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-7)

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

.\Get-CurrentRDPSessions.ps1 -ShowProcesses
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

$events = .\Get-RDPForensics.ps1 -StartDate $startDate -EndDate $endDate -ExportPath $reportPath

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
.\Get-CurrentRDPSessions.ps1 -Watch

# Option 2: Fast monitoring during incident response (3-second refresh)
# .\Get-CurrentRDPSessions.ps1 -Watch -RefreshInterval 3

# Option 3: Detailed monitoring with processes shown (10-second refresh)
# .\Get-CurrentRDPSessions.ps1 -Watch -ShowProcesses -RefreshInterval 10

# Option 4: Slower monitoring for long-term observation (30-second refresh)
# .\Get-CurrentRDPSessions.ps1 -Watch -RefreshInterval 30

# Option 5: Monitor with change logging for forensic analysis
# .\Get-CurrentRDPSessions.ps1 -Watch -LogPath "C:\Logs\RDP_Monitor"

# Option 6: Full monitoring - Watch, logging, and process tracking
# .\Get-CurrentRDPSessions.ps1 -Watch -RefreshInterval 5 -LogPath "C:\SecurityLogs\RDP" -ShowProcesses

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
$events = .\Get-RDPForensics.ps1 -StartDate $startDate -EndDate $endDate -ExportPath $investigationPath -IncludeOutbound

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
.\Get-CurrentRDPSessions.ps1 -ShowProcesses

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
$sessions = .\Get-RDPForensics.ps1 -StartDate (Get-Date).AddDays(-7) -GroupBySession -ExportPath $reportPath

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
Write-Host ""
