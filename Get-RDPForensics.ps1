#Requires -RunAsAdministrator

function Get-RDPForensics {
    <#
.SYNOPSIS
    Comprehensive RDP forensics analysis tool for Windows systems.

.DESCRIPTION
    This script collects and analyzes RDP connection logs from various Windows Event Logs
    following forensic best practices. It tracks all stages of RDP connections:
    1. Network Connection (EventID 1149)
    2. Authentication (EventID 4624, 4625)
    3. Logon (EventID 21, 22)
    4. Session Disconnect/Reconnect (EventID 24, 25, 39, 40, 4778, 4779)
    5. Logoff (EventID 23, 4634, 4647, 9009)

.PARAMETER StartDate
    The start date for log collection. Defaults to beginning of current day.

.PARAMETER EndDate
    The end date for log collection. Defaults to current time.

.PARAMETER ExportPath
    Optional path to export results to CSV files.

.PARAMETER Username
    Filter results for a specific username.

.PARAMETER SourceIP
    Filter results for a specific source IP address.

.PARAMETER IncludeOutbound
    Include outbound RDP connection logs from the client side.

.EXAMPLE
    Get-RDPForensics
    Get all RDP events for today.

.EXAMPLE
    Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -ExportPath "C:\RDP_Reports"
    Get last 7 days of RDP events and export to CSV files.

.EXAMPLE
    Get-RDPForensics -Username "john.doe" -StartDate (Get-Date).AddMonths(-1)
    Get RDP events for specific user in the last month.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.1
    Based on: https://woshub.com/rdp-connection-logs-forensics-windows/
    Requires: Administrator privileges to read Security event logs
#>

    [CmdletBinding()]
    param(
        [Parameter()]
        [DateTime]$StartDate = (Get-Date -Hour 0 -Minute 0 -Second 0),
    
        [Parameter()]
        [DateTime]$EndDate = (Get-Date),
    
        [Parameter()]
        [string]$ExportPath,
    
        [Parameter()]
        [string]$Username,
    
        [Parameter()]
        [string]$SourceIP,
    
        [Parameter()]
        [switch]$IncludeOutbound
    )

    # Error handling preference
    $ErrorActionPreference = 'Continue'

    # Emoji support for both PowerShell 5.1 and 7.x
    function Get-Emoji {
        param([string]$Name)
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $emojis = @{
                'shield'   = [char]::ConvertFromUtf32(0x1F6E1) + [char]::ConvertFromUtf32(0xFE0F)
                'magnify'  = [char]::ConvertFromUtf32(0x1F50D)
                'check'    = [char]::ConvertFromUtf32(0x2705)
                'cross'    = [char]::ConvertFromUtf32(0x274C)
                'warning'  = [char]::ConvertFromUtf32(0x26A0) + [char]::ConvertFromUtf32(0xFE0F)
                'clock'    = [char]::ConvertFromUtf32(0x23F1) + [char]::ConvertFromUtf32(0xFE0F)
                'computer' = [char]::ConvertFromUtf32(0x1F4BB)
                'lock'     = [char]::ConvertFromUtf32(0x1F512)
                'key'      = [char]::ConvertFromUtf32(0x1F511)
                'chart'    = [char]::ConvertFromUtf32(0x1F4CA)
                'folder'   = [char]::ConvertFromUtf32(0x1F4C1)
                'rocket'   = [char]::ConvertFromUtf32(0x1F680)
            }
        }
        else {
            # PowerShell 5.1 - Use Unicode symbols that work in Windows Console
            $emojis = @{
                'shield'   = "$([char]0x25A0)"  # Black square
                'magnify'  = "$([char]0x25CE)"  # Bullseye
                'check'    = "$([char]0x221A)"  # Square root (checkmark-like)
                'cross'    = "$([char]0x00D7)"  # Multiplication sign
                'warning'  = "$([char]0x203C)"  # Double exclamation
                'clock'    = "$([char]0x25D4)"  # Circle with upper right quadrant
                'computer' = "$([char]0x25A3)"  # White square with rounded corners
                'lock'     = "$([char]0x25A6)"  # Square with vertical fill
                'key'      = "$([char]0x2020)"  # Dagger
                'chart'    = "$([char]0x25A0)"  # Black square
                'folder'   = "$([char]0x25B6)"  # Right-pointing triangle
                'rocket'   = "$([char]0x25BA)"  # Right-pointing pointer
            }
        }
        return $emojis[$Name]
    }

    # ASCII Art Header
    Write-Host "`n" -NoNewline
    $topLeft = [char]0x2554; $topRight = [char]0x2557; $bottomLeft = [char]0x255A; $bottomRight = [char]0x255D
    $horizontal = [string][char]0x2550; $vertical = [char]0x2551
    Write-Host "$topLeft$($horizontal * 67)$topRight" -ForegroundColor Cyan
    Write-Host "$vertical" -ForegroundColor Cyan -NoNewline
    Write-Host "          RDP FORENSICS ANALYSIS TOOL v1.0.2                       " -ForegroundColor White -NoNewline
    Write-Host "$vertical" -ForegroundColor Cyan
    Write-Host "$vertical" -ForegroundColor Cyan -NoNewline
    Write-Host "        Security Investigation & Audit Toolkit                     " -ForegroundColor Yellow -NoNewline
    Write-Host "$vertical" -ForegroundColor Cyan
    Write-Host "$bottomLeft$($horizontal * 67)$bottomRight" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$(Get-Emoji 'clock') Analysis Period: " -ForegroundColor Cyan -NoNewline
    Write-Host "$($StartDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White -NoNewline
    Write-Host " to " -ForegroundColor Gray -NoNewline
    Write-Host "$($EndDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-Host ""

    # Function to parse EventID 1149 - RDP Connection Attempts
    function Get-RDPConnectionAttempts {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'rocket') [1/6] Collecting RDP Connection Attempts (EventID 1149)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
                Id        = 1149
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            if ($events) {
                [xml[]]$xml = $events | ForEach-Object { $_.ToXml() }
            
                $results = foreach ($event in $xml.Event) {
                    [PSCustomObject]@{
                        TimeCreated = [DateTime]::Parse($event.System.TimeCreated.SystemTime)
                        EventID     = 1149
                        EventType   = 'Connection Attempt'
                        User        = $event.UserData.EventXML.Param1
                        Domain      = $event.UserData.EventXML.Param2
                        SourceIP    = $event.UserData.EventXML.Param3
                        SessionID   = $null
                        LogonID     = $null
                        Details     = "User authentication succeeded"
                    }
                }
            
                Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
                Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
                Write-Host " connection attempts" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No connection attempts found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting connection attempts: $_"
            return @()
        }
    }

    # Function to parse EventID 4624, 4625 - Authentication Events
    function Get-RDPAuthenticationEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'key') [2/6] Collecting RDP Authentication Events (EventID 4624, 4625)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4624, 4625
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue | Where-Object {
                # Filter for RDP LogonTypes: 10 (RemoteInteractive), 7 (Unlock/Reconnect), 3 (Network-can be RDP), 5 (Service/Console)
                $_.Message -match 'Logon Type:\s+(10|7|3|5)\s'
            }
        
            if ($events) {
                $results = foreach ($event in $events) {
                    $message = $event.Message
                
                    # Parse message using regex
                    $userName = if ($message -match '\s\sAccount Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match '\s\sAccount Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $sourceIP = if ($message -match 'Source Network Address:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $logonType = if ($message -match 'Logon Type:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $logonID = if ($message -match 'Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $workstation = if ($message -match 'Workstation Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                
                    $logonTypeDesc = switch ($logonType) {
                        '2' { 'Interactive (Local)' }
                        '3' { 'Network' }
                        '4' { 'Batch' }
                        '5' { 'Service/Console' }
                        '7' { 'Unlock/Reconnect' }
                        '8' { 'NetworkCleartext' }
                        '9' { 'NewCredentials' }
                        '10' { 'RemoteInteractive (RDP)' }
                        '11' { 'CachedInteractive' }
                        default { "Unknown ($logonType)" }
                    }
                
                    $eventType = if ($event.Id -eq 4624) { 'Successful Logon' } else { 'Failed Logon' }
                
                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = $eventType
                        User        = $userName
                        Domain      = $userDomain
                        SourceIP    = $sourceIP
                        SessionID   = $null
                        LogonID     = $logonID
                        Details     = "$logonTypeDesc | Workstation: $workstation"
                    }
                }
            
                Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
                Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
                Write-Host " authentication events" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No authentication events found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting authentication events: $_"
            return @()
        }
    }

    # Function to parse Session Logon/Logoff Events
    function Get-RDPSessionEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'computer') [3/6] Collecting RDP Session Events (EventID 21-25, 39, 40)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                Id        = 21, 22, 23, 24, 25, 39, 40
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            if ($events) {
                [xml[]]$xml = $events | ForEach-Object { $_.ToXml() }
            
                $results = foreach ($event in $xml.Event) {
                    $eventID = $event.System.EventID
                    $timeCreated = [DateTime]::Parse($event.System.TimeCreated.SystemTime)
                
                    # Parse UserData
                    $user = if ($event.UserData.EventXML.User) { $event.UserData.EventXML.User } else { 'N/A' }
                    $sessionID = if ($event.UserData.EventXML.SessionID) { $event.UserData.EventXML.SessionID } else { 'N/A' }
                    $address = if ($event.UserData.EventXML.Address) { $event.UserData.EventXML.Address } else { 'N/A' }
                
                    $eventType = switch ($eventID) {
                        21 { 'Session Logon Succeeded' }
                        22 { 'Shell Start Notification' }
                        23 { 'Session Logoff Succeeded' }
                        24 { 'Session Disconnected' }
                        25 { 'Session Reconnected' }
                        39 { 'Session Disconnected by Another Session' }
                        40 { 'Session Disconnected (With Reason Code)' }
                        default { "Event $eventID" }
                    }
                
                    $details = if ($eventID -eq 40) {
                        $reasonCode = $event.UserData.EventXML.Reason
                        $reasonText = switch ($reasonCode) {
                            0 { 'No additional information' }
                            5 { 'Client connection replaced by another' }
                            11 { 'User activity initiated disconnect' }
                            default { "Reason code: $reasonCode" }
                        }
                        $reasonText
                    }
                    elseif ($eventID -eq 39) {
                        $sessionA = $event.UserData.EventXML.SessionID
                        $sessionB = $event.UserData.EventXML.Param2
                        "Session $sessionA disconnected by session $sessionB"
                    }
                    else {
                        "Session ID: $sessionID"
                    }
                
                    [PSCustomObject]@{
                        TimeCreated = $timeCreated
                        EventID     = [int]$eventID
                        EventType   = $eventType
                        User        = $user
                        Domain      = 'N/A'
                        SourceIP    = $address
                        SessionID   = $sessionID
                        LogonID     = $null
                        Details     = $details
                    }
                }
            
                Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
                Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
                Write-Host " session events" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No session events found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting session events: $_"
            return @()
        }
    }

    # Function to parse Session Reconnect/Disconnect from Security Log
    function Get-RDPSessionReconnectEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'lock') [4/6] Collecting RDP Reconnect/Disconnect Events (EventID 4778, 4779)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4778, 4779
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            if ($events) {
                $results = foreach ($event in $events) {
                    $message = $event.Message
                
                    $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $logonID = if ($message -match 'Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $sessionName = if ($message -match 'Session Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $sourceIP = if ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                
                    $eventType = if ($event.Id -eq 4778) { 'Session Reconnected' } else { 'Session Disconnected' }
                
                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = $eventType
                        User        = $userName
                        Domain      = $userDomain
                        SourceIP    = $sourceIP
                        SessionID   = $sessionName
                        LogonID     = $logonID
                        Details     = "LogonID: $logonID"
                    }
                }
            
                Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
                Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
                Write-Host " reconnect/disconnect events" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No reconnect/disconnect events found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting reconnect/disconnect events: $_"
            return @()
        }
    }

    # Function to parse Logoff Events
    function Get-RDPLogoffEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'warning') [5/6] Collecting RDP Logoff Events (EventID 4634, 4647, 9009)..." -ForegroundColor Yellow
    
        try {
            # Security log logoff events
            $securityEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4634, 4647
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -match 'Logon Type:\s+(10|7|3|5)\s'
            }
        
            # System log DWM exit events
            $systemEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = 9009
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            $results = @()
        
            if ($securityEvents) {
                foreach ($event in $securityEvents) {
                    $message = $event.Message
                
                    $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $logonID = if ($message -match 'Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $logonType = if ($message -match 'Logon Type:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                
                    $eventType = if ($event.Id -eq 4647) { 'User-Initiated Logoff' } else { 'Account Logged Off' }
                
                    $results += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = $eventType
                        User        = $userName
                        Domain      = $userDomain
                        SourceIP    = 'N/A'
                        SessionID   = $null
                        LogonID     = $logonID
                        Details     = "LogonType: $logonType"
                    }
                }
            }
        
            if ($systemEvents) {
                foreach ($event in $systemEvents) {
                    $results += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = 'Desktop Window Manager Exit'
                        User        = 'N/A'
                        Domain      = 'N/A'
                        SourceIP    = 'N/A'
                        SessionID   = $null
                        LogonID     = $null
                        Details     = "DWM exited (RDP session ended)"
                    }
                }
            }
        
            Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
            Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
            Write-Host " logoff events" -ForegroundColor Green
            return $results
        }
        catch {
            Write-Warning "Error collecting logoff events: $_"
            return @()
        }
    }

    # Function to get outbound RDP connections
    function Get-OutboundRDPConnections {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'magnify') [6/6] Collecting Outbound RDP Connections (EventID 1102)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
                Id        = 1102
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            if ($events) {
                $results = foreach ($event in $events) {
                    $targetHost = $event.Properties[1].Value
                    $localUser = if ($event.UserId) { 
                        try {
                            (New-Object System.Security.Principal.SecurityIdentifier($event.UserId)).Translate([System.Security.Principal.NTAccount]).Value
                        }
                        catch {
                            $event.UserId.Value
                        }
                    }
                    else { 'N/A' }
                
                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = 'Outbound RDP Connection'
                        User        = $localUser
                        Domain      = 'N/A'
                        SourceIP    = 'Local Machine'
                        SessionID   = $null
                        LogonID     = $null
                        Details     = "Target: $targetHost"
                    }
                }
            
                Write-Host "  Found $($results.Count) outbound connections" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No outbound connections found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting outbound connections: $_"
            return @()
        }
    }

    # Collect all events
    $allEvents = @()
    $allEvents += Get-RDPConnectionAttempts -Start $StartDate -End $EndDate
    $allEvents += Get-RDPAuthenticationEvents -Start $StartDate -End $EndDate
    $allEvents += Get-RDPSessionEvents -Start $StartDate -End $EndDate
    $allEvents += Get-RDPSessionReconnectEvents -Start $StartDate -End $EndDate
    $allEvents += Get-RDPLogoffEvents -Start $StartDate -End $EndDate

    if ($IncludeOutbound) {
        $allEvents += Get-OutboundRDPConnections -Start $StartDate -End $EndDate
    }

    # Apply filters
    if ($Username) {
        Write-Host "`nFiltering for username: $Username" -ForegroundColor Cyan
        $allEvents = $allEvents | Where-Object { $_.User -like "*$Username*" }
    }

    if ($SourceIP) {
        Write-Host "Filtering for source IP: $SourceIP" -ForegroundColor Cyan
        $allEvents = $allEvents | Where-Object { $_.SourceIP -like "*$SourceIP*" }
    }

    # Sort by time
    $allEvents = $allEvents | Sort-Object TimeCreated -Descending

    # Display results
    Write-Host "`n" -NoNewline
    $separator = [string][char]0x2500
    Write-Host ($separator * 58) -ForegroundColor DarkCyan
    Write-Host "$(Get-Emoji 'chart') ANALYSIS SUMMARY" -ForegroundColor Cyan
    Write-Host ($separator * 58) -ForegroundColor DarkCyan
    Write-Host "Total Events: " -ForegroundColor Yellow -NoNewline
    Write-Host "$($allEvents.Count)" -ForegroundColor White

    if ($allEvents.Count -gt 0) {
        # Group by event type
        $groupedEvents = $allEvents | Group-Object EventType | Sort-Object Count -Descending
        Write-Host "`nEvents by Type:" -ForegroundColor Yellow
        $groupedEvents | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
        }
    
        # Display recent events
        Write-Host "`n" -NoNewline
        Write-Host ($separator * 58) -ForegroundColor DarkCyan
        Write-Host "$(Get-Emoji 'magnify') RECENT RDP EVENTS (Top 50)" -ForegroundColor Cyan
        Write-Host ($separator * 58) -ForegroundColor DarkCyan
        $allEvents | Select-Object -First 50 | Format-Table TimeCreated, EventID, EventType, User, SourceIP, Details -AutoSize
    
        # Export if requested
        if ($ExportPath) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            }
        
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $exportFile = Join-Path $ExportPath "RDP_Forensics_$timestamp.csv"
        
            Write-Host "`n" -NoNewline
            Write-Host "──────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
            Write-Host "$(Get-Emoji 'folder') EXPORTING RESULTS" -ForegroundColor Cyan
            Write-Host "──────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
            $allEvents | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8
            Write-Host "$(Get-Emoji 'check') Results exported to: " -ForegroundColor Green -NoNewline
            Write-Host "$exportFile" -ForegroundColor White
        
            # Export summary
            $summaryFile = Join-Path $ExportPath "RDP_Summary_$timestamp.txt"
            $summary = @"
RDP Forensics Analysis Summary
================================
Analysis Period: $($StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndDate.ToString('yyyy-MM-dd HH:mm:ss'))
Total Events: $($allEvents.Count)

Events by Type:
$($groupedEvents | ForEach-Object { "  $($_.Name): $($_.Count)" } | Out-String)

Unique Users:
$($allEvents | Where-Object { $_.User -ne 'N/A' } | Select-Object -ExpandProperty User -Unique | ForEach-Object { "  $_" } | Out-String)

Unique Source IPs:
$($allEvents | Where-Object { $_.SourceIP -ne 'N/A' -and $_.SourceIP -ne 'Local Machine' } | Select-Object -ExpandProperty SourceIP -Unique | ForEach-Object { "  $_" } | Out-String)
"@
            $summary | Out-File -FilePath $summaryFile -Encoding UTF8
            Write-Host "$(Get-Emoji 'check') Summary exported to: " -ForegroundColor Green -NoNewline
            Write-Host "$summaryFile" -ForegroundColor White
        }
    }
    else {
        Write-Host "`n$(Get-Emoji 'warning') No RDP events found matching the criteria." -ForegroundColor Yellow
    }

    # Return the events for pipeline usage
    return $allEvents
}

