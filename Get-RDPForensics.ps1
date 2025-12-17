#Requires -RunAsAdministrator

function Get-RDPForensics {
    <#
.SYNOPSIS
    Comprehensive RDP forensics analysis tool for Windows systems.

.DESCRIPTION
    This script collects and analyzes RDP connection logs from various Windows Event Logs
    following forensic best practices. It tracks all stages of RDP connections:
    1. Network Connection (EventID 1149)
    2. Credential Validation (EventID 4776)
    3. Authentication (EventID 4624, 4625, 4648)
    4. Logon (EventID 21, 22)
    5. Lock/Unlock (EventID 4800, 4801)
    6. Session Disconnect/Reconnect (EventID 24, 25, 39, 40, 4778, 4779)
    7. Logoff (EventID 23, 4634, 4647, 9009)

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

.PARAMETER LogonID
    Filter results for a specific LogonID (e.g., '0x6950A4').
    Only applicable when using -GroupBySession.
    RECOMMENDED: LogonID provides the most reliable correlation as it persists across disconnect/reconnect cycles.
    Cannot be used together with -SessionID (mutually exclusive).

.PARAMETER SessionID
    Filter results for a specific Terminal Services SessionID (e.g., '5').
    Only applicable when using -GroupBySession.
    NOTE: SessionID changes on disconnect/reconnect. Use -LogonID for tracking full session lifecycle.
    Cannot be used together with -LogonID (mutually exclusive).

.PARAMETER IncludeOutbound
    Include outbound RDP connection logs from the client side.

.PARAMETER GroupBySession
    Group events by ActivityID/LogonID/SessionID to show correlated session lifecycles.
    Uses Windows Event Correlation ActivityID for precise cross-log correlation, with fallback to LogonID and SessionID.
    Displays session summary with duration, lifecycle stages, and completeness indicators.
    Exports to separate CSV file (RDP_Sessions_<timestamp>.csv) when used with -ExportPath.

.PARAMETER IncludeCredentialValidation
    Include pre-authentication events in the analysis:
    - EventID 4768-4772 (Kerberos authentication: TGT, service tickets, failures)
    - EventID 4776 (NTLM Credential Validation - used when Kerberos fails/unavailable)
    
    ⚠️ IMPORTANT: These events are logged on the DOMAIN CONTROLLER, not the Terminal Server.
    When running this tool on a Terminal Server, these events will be EMPTY (count: 0).
    Only use this parameter when:
    - Running on a Domain Controller to analyze authentication patterns
    - Analyzing logs exported from a Domain Controller
    
    Shows complete authentication story:
    - Kerberos attempts (4768 TGT request, 4769 service ticket)
    - Kerberos failures (4771 pre-auth failed) that trigger NTLM fallback
    - NTLM authentication (4776) when Kerberos unavailable or fails
    
    Correlation Strategy:
    - Pre-authentication events (4768-4772, 4776) use username + timestamp matching
    - Terminal Server events (4624, 4778, etc.) use ActivityID correlation
    - ActivityID cannot correlate across machines (DC vs Terminal Server)
    - All pre-auth events matched within 0-10 second window before RDP session start
    - Automatically filters out non-RDP authentications (SMB, SQL, Exchange, etc.)
    - Only shows pre-auth events that correlate to RDP Logon Type 10/7/3/5

.EXAMPLE
    Get-RDPForensics
    Get all RDP events for today.

.EXAMPLE
    Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -ExportPath "C:\RDP_Reports"
    Get last 7 days of RDP events and export to CSV files.

.EXAMPLE
    Get-RDPForensics -Username "john.doe" -StartDate (Get-Date).AddMonths(-1)
    Get RDP events for specific user in the last month.

.EXAMPLE
    Get-RDPForensics -GroupBySession
    Display events grouped by session with complete lifecycle tracking.

.EXAMPLE
    Get-RDPForensics -StartDate (Get-Date).AddDays(-7) -GroupBySession -ExportPath "C:\Reports"
    Analyze last 7 days of sessions and export both events and session summaries.

.EXAMPLE
    Get-RDPForensics -IncludeCredentialValidation -GroupBySession
    Include Kerberos (4768-4772) and NTLM (4776) authentication events with time-based correlation.
    ⚠️ NOTE: Only works when running on Domain Controller. Will return 0 events on Terminal Server.

.EXAMPLE
    Get-RDPForensics -GroupBySession -LogonID "0x6950A4"
    Display all events for a specific LogonID-based session.

.EXAMPLE
    Get-RDPForensics -GroupBySession -SessionID "5"
    Display all events for a specific SessionID-based session.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.8
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
    
        [Parameter(ParameterSetName = 'ByLogonID')]
        [string]$LogonID,
    
        [Parameter(ParameterSetName = 'BySessionID')]
        [string]$SessionID,
    
        [Parameter()]
        [switch]$IncludeOutbound,

        [Parameter()]
        [switch]$GroupBySession,

        [Parameter()]
        [switch]$IncludeCredentialValidation
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

    # Function to correlate events across log sources using LogonID and SessionID
    function Get-CorrelatedSessions {
        param([array]$Events)

        # Group events by LogonID (priority 1) or SessionID (priority 2)
        # Secondary correlation then merges SessionID sessions into LogonID sessions (same user + time proximity)
        $sessionMap = @{}
        
        foreach ($event in $Events) {
            # Determine correlation key with priority: LogonID > SessionID (ActivityID kept for reference only)
            $correlationKey = $null
            
            # Priority 1: Use LogonID from Security log events (best cross-log correlation)
            # Exception: Event 4648 uses SubjectLogonID (not the session LogonID) - skip direct correlation
            if ($event.EventID -ne 4648 -and $event.LogonID -and $event.LogonID -ne 'N/A' -and $event.LogonID -ne $null) {
                $correlationKey = "LogonID:$($event.LogonID)"
            }
            # Priority 2: Use SessionID from TerminalServices events
            elseif ($event.SessionID -and $event.SessionID -ne 'N/A' -and $event.SessionID -ne $null) {
                $correlationKey = "SessionID:$($event.SessionID)"
            }
            # Note: ActivityID is preserved in events for forensic analysis but not used for correlation
            # as it's provider-specific and doesn't reliably match across Security/TerminalServices logs
            # Note: Event 4648 uses time-based correlation instead (SubjectLogonID ≠ session LogonID)
            
            if ($correlationKey) {
                if (-not $sessionMap.ContainsKey($correlationKey)) {
                    $sessionMap[$correlationKey] = @{
                        CorrelationKey = $correlationKey
                        Events         = @()
                        User           = $null
                        SourceIP       = $null
                        StartTime      = $null
                        EndTime        = $null
                        Duration       = $null
                        ActivityID     = $event.ActivityID
                        LogonID        = $event.LogonID
                        SessionID      = $event.SessionID
                        Lifecycle      = @{
                            ConnectionAttempt = $false
                            Authentication    = $false
                            Logon             = $false
                            Active            = $false
                            Disconnect        = $false
                            Logoff            = $false
                        }
                    }
                }
                
                # Add event to session
                $sessionMap[$correlationKey].Events += $event
                
                # Update correlation IDs if not yet set (for sessions grouped by different keys)
                if (-not $sessionMap[$correlationKey].ActivityID -and $event.ActivityID) {
                    $sessionMap[$correlationKey].ActivityID = $event.ActivityID
                }
                if (-not $sessionMap[$correlationKey].LogonID -and $event.LogonID -and $event.LogonID -ne 'N/A') {
                    $sessionMap[$correlationKey].LogonID = $event.LogonID
                }
                if (-not $sessionMap[$correlationKey].SessionID -and $event.SessionID -and $event.SessionID -ne 'N/A') {
                    $sessionMap[$correlationKey].SessionID = $event.SessionID
                }
                
                # Track lifecycle stages
                # Note: Event 4648 excluded from direct correlation - uses time-based correlation instead
                switch ($event.EventID) {
                    1149 { $sessionMap[$correlationKey].Lifecycle.ConnectionAttempt = $true }
                    { $_ -in 4624, 4776 } { $sessionMap[$correlationKey].Lifecycle.Authentication = $true }
                    { $_ -in 21, 22 } { $sessionMap[$correlationKey].Lifecycle.Logon = $true }
                    { $_ -in 24, 25, 4778, 4801 } { $sessionMap[$correlationKey].Lifecycle.Active = $true }
                    { $_ -in 39, 40, 4779, 4800 } { $sessionMap[$correlationKey].Lifecycle.Disconnect = $true }
                    { $_ -in 23, 4634, 4647, 9009 } { $sessionMap[$correlationKey].Lifecycle.Logoff = $true }
                }
                
                # Update session metadata
                if ($event.User -and $event.User -ne 'N/A') {
                    $sessionMap[$correlationKey].User = $event.User
                }
                if ($event.SourceIP -and $event.SourceIP -ne 'N/A' -and $event.SourceIP -ne '-' -and $event.SourceIP -ne 'LOCAL') {
                    $sessionMap[$correlationKey].SourceIP = $event.SourceIP
                }
            }
        }
        
        # Time-based correlation for pre-authentication and credential events
        # These events have different LogonIDs/ActivityIDs than the actual session:
        # - 4768-4772, 4776: Pre-auth events logged on DC
        # - 4648: Credential submission with SubjectLogonID (not the new session LogonID)
        # Match these events to sessions within 10 seconds before session start with matching username/IP
        # IMPORTANT: Only include pre-auth events that correlate to RDP sessions (Logon Type 10/7/3/5)
        $preAuthEvents = $Events | Where-Object { 
            $_.EventID -in 4648, 4768, 4769, 4770, 4771, 4772, 4776 -and 
            -not $_.CorrelationKey 
        }
        
        $correlatedPreAuthEventIDs = @()  # Track which pre-auth events matched RDP sessions
        
        foreach ($preAuthEvent in $preAuthEvents) {
            $matchedSession = $null
            $closestTimeDiff = [TimeSpan]::MaxValue
            
            # Find the closest RDP session that starts within 10 seconds after this pre-auth event
            foreach ($sessionKey in $sessionMap.Keys) {
                $session = $sessionMap[$sessionKey]
                $matchUser = $session.User -eq $preAuthEvent.User
                $matchIP = (-not $preAuthEvent.SourceIP -or $preAuthEvent.SourceIP -eq 'N/A' -or 
                    $session.SourceIP -eq $preAuthEvent.SourceIP)
                
                if ($matchUser -and $matchIP) {
                    $sessionStart = ($session.Events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                    $timeDiff = $sessionStart - $preAuthEvent.TimeCreated
                    
                    # Pre-auth/credential events should be 0-10 seconds BEFORE session start
                    if ($timeDiff.TotalSeconds -ge 0 -and $timeDiff.TotalSeconds -le 10) {
                        if ($timeDiff -lt $closestTimeDiff) {
                            $closestTimeDiff = $timeDiff
                            $matchedSession = $sessionKey
                        }
                    }
                }
            }
            
            # Add pre-auth event to matched RDP session
            if ($matchedSession) {
                $sessionMap[$matchedSession].Events += $preAuthEvent
                $sessionMap[$matchedSession].Lifecycle.Authentication = $true
                $correlatedPreAuthEventIDs += $preAuthEvent.GetHashCode()  # Track this event as matched
                
                # Mark event as correlated (for filtering in non-grouped output)
                $preAuthEvent | Add-Member -NotePropertyName 'CorrelatedToRDP' -NotePropertyValue $true -Force
            }
        }
        
        # Filter out uncorrelated pre-auth events from the Events array
        # Only keep pre-auth events that matched to RDP sessions (Logon Type 10/7/3/5)
        $Events = $Events | Where-Object {
            # Keep all non-pre-auth events
            ($_.EventID -notin 4648, 4768, 4769, 4770, 4771, 4772, 4776) -or
            # OR keep pre-auth events that were correlated to RDP sessions
            ($_.CorrelatedToRDP -eq $true)
        }
        
        # Secondary Correlation: Merge SessionID-based sessions into LogonID-based sessions
        # This handles the case where TerminalServices events (21-25) have SessionID but no LogonID
        # while Security events (4624, 4778, 4779, 4634) have LogonID
        # Match sessions based on: Username + Time Proximity (within 10 seconds) + RDP LogonType
        $sessionIDSessions = @($sessionMap.Keys | Where-Object { $_ -like "SessionID:*" })
        $logonIDSessions = @($sessionMap.Keys | Where-Object { $_ -like "LogonID:*" })
        
        foreach ($sessionIDKey in $sessionIDSessions) {
            $sessionIDSession = $sessionMap[$sessionIDKey]
            
            # Find matching LogonID session
            $matchedLogonIDKey = $null
            $bestMatchScore = 0  # Track number of synchronized event pairs
            
            foreach ($logonIDKey in $logonIDSessions) {
                $logonIDSession = $sessionMap[$logonIDKey]
                
                # Match criteria: Same user + synchronized events
                if ($logonIDSession.User -eq $sessionIDSession.User) {
                    # Check if this LogonID session has RDP events (4624/4778/4779)
                    $hasRDPLogonType = $logonIDSession.Events | Where-Object { 
                        ($_.EventID -eq 4624 -and $_.Details -match 'RemoteInteractive|Unlock/Reconnect|Network') -or
                        ($_.EventID -in @(4778, 4779))
                    }
                    
                    if ($hasRDPLogonType) {
                        # Count synchronized events (events within 3 seconds of each other)
                        $synchronizedCount = 0
                        foreach ($sessionIDEvent in $sessionIDSession.Events) {
                            foreach ($logonIDEvent in $logonIDSession.Events) {
                                $timeDiff = [Math]::Abs(($logonIDEvent.TimeCreated - $sessionIDEvent.TimeCreated).TotalSeconds)
                                if ($timeDiff -le 3) {
                                    $synchronizedCount++
                                    break  # Only count each SessionID event once
                                }
                            }
                        }
                        
                        # If we found multiple synchronized events, this is a strong match
                        if ($synchronizedCount -ge 2 -and $synchronizedCount -gt $bestMatchScore) {
                            $bestMatchScore = $synchronizedCount
                            $matchedLogonIDKey = $logonIDKey
                        }
                    }
                }
            }
            
            # Merge SessionID events into LogonID session
            if ($matchedLogonIDKey) {
                $sessionMap[$matchedLogonIDKey].Events += $sessionIDSession.Events
                # Update SessionID in LogonID session
                if (-not $sessionMap[$matchedLogonIDKey].SessionID -or $sessionMap[$matchedLogonIDKey].SessionID -eq 'N/A') {
                    $sessionMap[$matchedLogonIDKey].SessionID = $sessionIDSession.SessionID
                }
                # Merge lifecycle flags
                foreach ($key in $sessionIDSession.Lifecycle.Keys) {
                    if ($sessionIDSession.Lifecycle[$key]) {
                        $sessionMap[$matchedLogonIDKey].Lifecycle[$key] = $true
                    }
                }
                # Remove the SessionID session (merged into LogonID session)
                $sessionMap.Remove($sessionIDKey)
            }
        }
        
        # Calculate session durations and create session objects
        $sessions = foreach ($key in $sessionMap.Keys) {
            $session = $sessionMap[$key]
            $sortedEvents = $session.Events | Sort-Object TimeCreated
            
            if ($sortedEvents.Count -gt 0) {
                $session.StartTime = $sortedEvents[0].TimeCreated
                $session.EndTime = $sortedEvents[-1].TimeCreated
                
                if ($session.StartTime -and $session.EndTime) {
                    $session.Duration = $session.EndTime - $session.StartTime
                }
            }
            
            # Create session object
            [PSCustomObject]@{
                CorrelationKey    = $session.CorrelationKey
                ActivityID        = $session.ActivityID
                User              = $session.User
                SourceIP          = $session.SourceIP
                LogonID           = $session.LogonID
                SessionID         = $session.SessionID
                StartTime         = $session.StartTime
                EndTime           = $session.EndTime
                Duration          = if ($session.Duration) { 
                    "{0:hh\:mm\:ss}" -f $session.Duration 
                }
                else { 
                    'N/A' 
                }
                EventCount        = $session.Events.Count
                ConnectionAttempt = $session.Lifecycle.ConnectionAttempt
                Authentication    = $session.Lifecycle.Authentication
                Logon             = $session.Lifecycle.Logon
                Active            = $session.Lifecycle.Active
                Disconnect        = $session.Lifecycle.Disconnect
                Logoff            = $session.Lifecycle.Logoff
                # Lifecycle is complete if session has minimum viable stages (Auth + Logon/Active)
                # OR if session was terminated (has Logoff)
                # This avoids false warnings for active sessions or time-window limitations
                LifecycleComplete = ($session.Lifecycle.Authentication -and ($session.Lifecycle.Logon -or $session.Lifecycle.Active)) -or 
                $session.Lifecycle.Logoff
                Events            = $session.Events
            }
        }
        
        # Return sessions and the filtered events array
        return @{
            Sessions       = ($sessions | Sort-Object StartTime -Descending)
            FilteredEvents = $Events
        }
    }

    # ASCII Art Header
    Write-Host "`n" -NoNewline
    $topLeft = [char]0x2554; $topRight = [char]0x2557; $bottomLeft = [char]0x255A; $bottomRight = [char]0x255D
    $horizontal = [string][char]0x2550; $vertical = [char]0x2551
    Write-Host "$topLeft$($horizontal * 67)$topRight" -ForegroundColor Cyan
    Write-Host "$vertical" -ForegroundColor Cyan -NoNewline
    Write-Host "          RDP FORENSICS ANALYSIS TOOL v1.0.8                       " -ForegroundColor White -NoNewline
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
                    # Extract ActivityID from Correlation element
                    $activityID = if ($event.System.Correlation.ActivityID) { 
                        $event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                    
                    [PSCustomObject]@{
                        TimeCreated = [DateTime]::Parse($event.System.TimeCreated.SystemTime)
                        EventID     = 1149
                        EventType   = 'Connection Attempt'
                        User        = $event.UserData.EventXML.Param1
                        Domain      = $event.UserData.EventXML.Param2
                        SourceIP    = $event.UserData.EventXML.Param3
                        SessionID   = $null
                        LogonID     = $null
                        ActivityID  = $activityID
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

    # Function to parse EventID 4624, 4625, 4648, 4776, 4768-4772 - Authentication Events
    function Get-RDPAuthenticationEvents {
        param(
            [DateTime]$Start, 
            [DateTime]$End,
            [bool]$IncludeKerberosAndNTLM = $false
        )
    
        $eventList = if ($IncludeKerberosAndNTLM) { "4624, 4625, 4648, 4768-4772, 4776" } else { "4624, 4625, 4648" }
        Write-Host "$(Get-Emoji 'key') [2/7] Collecting RDP Authentication Events (EventID $eventList)..." -ForegroundColor Yellow
    
        try {
            # Collect logon events (4624/4625) and explicit credential usage (4648)
            $logonEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4624, 4625, 4648
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue | Where-Object {
                # Filter for RDP LogonTypes: 10 (RemoteInteractive), 7 (Unlock/Reconnect), 3 (Network-can be RDP), 5 (Service/Console)
                # For Event 4648, include all (no logon type)
                $_.Id -eq 4648 -or $_.Message -match 'Logon Type:\s+(10|7|3|5)'
            }
            
            # Optionally collect Kerberos and NTLM pre-authentication events
            $kerberosEvents = @()
            $credentialEvents = @()
            
            if ($IncludeKerberosAndNTLM) {
                # Kerberos authentication events (4768-4772)
                $kerberosEvents = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 4768, 4769, 4770, 4771, 4772
                    StartTime = $Start
                    EndTime   = $End
                } -ErrorAction SilentlyContinue
                
                # NTLM credential validation events (4776)
                $credentialEvents = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 4776
                    StartTime = $Start
                    EndTime   = $End
                } -ErrorAction SilentlyContinue | Where-Object {
                    # Include events where Source Workstation is not empty and not local machine
                    # (4776 fires for all NTLM auth, we want remote/RDP-related ones)
                    $_.Message -match 'Source Workstation:\s+\S+' -and 
                    $_.Message -notmatch 'Source Workstation:\s+(LOCAL|LOCALHOST|127\.0\.0\.1|-)'
                }
            }
            
            # Combine all event types
            $events = @($logonEvents) + @($kerberosEvents) + @($credentialEvents)
        
            if ($events -and $events.Count -gt 0) {
                $results = foreach ($event in $events) {
                    $message = $event.Message
                
                    # Extract ActivityID from XML
                    [xml]$eventXml = $event.ToXml()
                    $activityID = if ($eventXml.Event.System.Correlation.ActivityID) { 
                        $eventXml.Event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
                    # Handle different event types
                    switch ($event.Id) {
                        4768 {
                            # Kerberos TGT Request
                            $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $sourceIP = if ($message -match 'Client Address:\s+::ffff:([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            $statusCode = if ($message -match 'Result Code:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $ticketOptions = if ($message -match 'Ticket Options:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            $eventType = if ($statusCode -eq '0x0') { 'Kerberos TGT Success' } else { 'Kerberos TGT Failed' }
                            $details = "Result: $statusCode | Options: $ticketOptions"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4769 {
                            # Kerberos Service Ticket Request
                            $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $serviceName = if ($message -match 'Service Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $sourceIP = if ($message -match 'Client Address:\s+::ffff:([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            $statusCode = if ($message -match 'Failure Code:\s+([^\r\n]+)') { $matches[1].Trim() } else { '0x0' }
                            
                            $eventType = if ($statusCode -eq '0x0') { 'Kerberos Service Ticket Success' } else { 'Kerberos Service Ticket Failed' }
                            $details = "Service: $serviceName | Result: $statusCode"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4770 {
                            # Kerberos Service Ticket Renewal
                            $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $serviceName = if ($message -match 'Service Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $sourceIP = if ($message -match 'Client Address:\s+::ffff:([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            
                            $eventType = 'Kerberos Ticket Renewed'
                            $details = "Service: $serviceName"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4771 {
                            # Kerberos Pre-authentication Failed (KEY EVENT - shows why Kerberos failed)
                            $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'Service Name:\s+krbtgt/([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            $sourceIP = if ($message -match 'Client Address:\s+::ffff:([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            $errorCode = if ($message -match 'Failure Code:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            # Common Kerberos error codes
                            $errorDesc = switch ($errorCode) {
                                '0x6' { 'Client not found' }
                                '0x7' { 'Server not found' }
                                '0xC' { 'Workstation restriction' }
                                '0x12' { 'Client revoked/disabled' }
                                '0x17' { 'Password expired' }
                                '0x18' { 'Wrong password' }
                                '0x25' { 'Clock skew too large' }
                                default { "Code $errorCode" }
                            }
                            
                            $eventType = 'Kerberos Pre-auth Failed'
                            $details = "Error: $errorDesc | Source: $sourceIP"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4772 {
                            # Kerberos Authentication Ticket Request Failed
                            $userName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $sourceIP = if ($message -match 'Client Address:\s+::ffff:([^\r\n]+)') { $matches[1].Trim() } 
                            elseif ($message -match 'Client Address:\s+([^\r\n]+)') { $matches[1].Trim() } 
                            else { 'N/A' }
                            $errorCode = if ($message -match 'Failure Code:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            $eventType = 'Kerberos Ticket Request Failed'
                            $details = "Error Code: $errorCode"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4776 {
                            # NTLM Credential Validation
                            # 4776 has format "Logon Account: DOMAIN\Username"
                            $logonAccount = if ($message -match 'Logon Account:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            # Extract just the username if domain\username format
                            $userName = if ($logonAccount -match '\\(.+)$') { $matches[1] } 
                            elseif ($logonAccount -ne 'N/A') { $logonAccount } 
                            else { 'N/A' }
                            $userDomain = if ($message -match 'Source Workstation:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $errorCode = if ($message -match 'Error Code:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $authPackage = if ($message -match 'Authentication Package:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'NTLM' }
                            
                            $eventType = if ($errorCode -eq '0x0') { 'NTLM Validation Success' } else { 'NTLM Validation Failed' }
                            $details = "$authPackage | Error Code: $errorCode | Source: $userDomain"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = 'N/A'
                                SourceIP    = 'N/A'
                                SessionID   = $null
                                LogonID     = $null
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        4648 {
                            # Explicit Credential Usage (credential submission before logon)
                            # Shows WHO submitted credentials, FOR WHICH account, FROM WHERE
                            $subjectUserName = if ($message -match 'Subject:[\s\S]*?Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $subjectDomain = if ($message -match 'Subject:[\s\S]*?Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $subjectLogonID = if ($message -match 'Subject:[\s\S]*?Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            $targetUserName = if ($message -match 'Account Whose Credentials Were Used:[\s\S]*?Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $targetDomain = if ($message -match 'Account Whose Credentials Were Used:[\s\S]*?Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            $targetServerName = if ($message -match 'Target Server:[\s\S]*?Target Server Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $sourceIP = if ($message -match 'Network Information:[\s\S]*?Network Address:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $processName = if ($message -match 'Process Information:[\s\S]*?Process Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            # Construct usernames
                            if ($subjectDomain -ne 'N/A' -and $subjectDomain -ne '-' -and $subjectUserName -ne 'N/A') {
                                $subjectFullName = "$subjectDomain\$subjectUserName"
                            }
                            else {
                                $subjectFullName = $subjectUserName
                            }
                            
                            if ($targetDomain -ne 'N/A' -and $targetDomain -ne '-' -and $targetUserName -ne 'N/A') {
                                $targetFullName = "$targetDomain\$targetUserName"
                            }
                            else {
                                $targetFullName = $targetUserName
                            }
                            
                            # Use target user as primary User field (the account being authenticated)
                            $userName = $targetFullName
                            $userDomain = $targetDomain
                            
                            $eventType = 'Credential Submission'
                            $details = "Subject: $subjectFullName → Target: $targetFullName | Server: $targetServerName | Process: $(Split-Path $processName -Leaf)"
                            
                            [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventID     = $event.Id
                                EventType   = $eventType
                                User        = $userName
                                Domain      = $userDomain
                                SourceIP    = $sourceIP
                                SessionID   = $null
                                LogonID     = $subjectLogonID
                                ActivityID  = $activityID
                                Details     = $details
                            }
                        }
                        default {
                            # Logon/Failed Logon (4624/4625)
                            # Match fields from "New Logon" section (not "Subject" section)
                            $accountName = if ($message -match 'New Logon:[\s\S]*?Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $userDomain = if ($message -match 'New Logon:[\s\S]*?Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            
                            # Construct full username as DOMAIN\User to match TerminalServices event format
                            if ($userDomain -ne 'N/A' -and $userDomain -ne '-' -and $accountName -ne 'N/A') {
                                $userName = "$userDomain\$accountName"
                            }
                            else {
                                $userName = $accountName
                            }
                            
                            $sourceIP = if ($message -match 'Source Network Address:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $logonType = if ($message -match 'Logon Type:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                            $logonID = if ($message -match 'New Logon:[\s\S]*?Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
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
                                ActivityID  = $activityID
                                Details     = "$logonTypeDesc | Workstation: $workstation"
                            }
                        }
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
                
                    # Extract ActivityID from Correlation element
                    $activityID = if ($event.System.Correlation.ActivityID) { 
                        $event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
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
                        ActivityID  = $activityID
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

    # Function to parse Session Lock/Unlock Events
    function Get-RDPLockUnlockEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'lock') [4/7] Collecting Session Lock/Unlock Events (EventID 4800, 4801)..." -ForegroundColor Yellow
    
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4800, 4801
                StartTime = $Start
                EndTime   = $End
            } -ErrorAction SilentlyContinue
        
            if ($events) {
                $results = foreach ($event in $events) {
                    $message = $event.Message
                
                    # Extract ActivityID from XML
                    [xml]$eventXml = $event.ToXml()
                    $activityID = if ($eventXml.Event.System.Correlation.ActivityID) { 
                        $eventXml.Event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
                    $accountName = if ($message -match 'Subject:.*?Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match 'Subject:.*?Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    
                    # Construct DOMAIN\User format to match TerminalServices events
                    if ($userDomain -ne 'N/A' -and $userDomain -ne '-' -and $accountName -ne 'N/A') {
                        $userName = "$userDomain\$accountName"
                    }
                    else {
                        $userName = $accountName
                    }
                    
                    $logonID = if ($message -match 'Subject:.*?Logon ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $sessionID = if ($message -match 'Session ID:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                
                    $eventType = if ($event.Id -eq 4800) { 'Workstation Locked' } else { 'Workstation Unlocked' }
                
                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = $eventType
                        User        = $userName
                        Domain      = $userDomain
                        SourceIP    = 'Local Machine'
                        SessionID   = $sessionID
                        LogonID     = $logonID
                        ActivityID  = $activityID
                        Details     = "Session ID: $sessionID | LogonID: $logonID"
                    }
                }
            
                Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
                Write-Host "$($results.Count)" -ForegroundColor White -NoNewline
                Write-Host " lock/unlock events" -ForegroundColor Green
                return $results
            }
            else {
                Write-Host "  $(Get-Emoji 'cross') No lock/unlock events found" -ForegroundColor DarkGray
                return @()
            }
        }
        catch {
            Write-Warning "Error collecting lock/unlock events: $_"
            return @()
        }
    }

    # Function to parse Session Reconnect/Disconnect from Security Log
    function Get-RDPSessionReconnectEvents {
        param([DateTime]$Start, [DateTime]$End)
    
        Write-Host "$(Get-Emoji 'lock') [5/7] Collecting RDP Reconnect/Disconnect Events (EventID 4778, 4779)..." -ForegroundColor Yellow
    
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
                
                    # Extract ActivityID from XML
                    [xml]$eventXml = $event.ToXml()
                    $activityID = if ($eventXml.Event.System.Correlation.ActivityID) { 
                        $eventXml.Event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
                    $accountName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    
                    # Construct DOMAIN\User format to match TerminalServices events
                    if ($userDomain -ne 'N/A' -and $userDomain -ne '-' -and $accountName -ne 'N/A') {
                        $userName = "$userDomain\$accountName"
                    }
                    else {
                        $userName = $accountName
                    }
                    
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
                        ActivityID  = $activityID
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
    
        Write-Host "$(Get-Emoji 'warning') [6/7] Collecting RDP Logoff Events (EventID 4634, 4647, 9009)..." -ForegroundColor Yellow
    
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
                
                    # Extract ActivityID from XML
                    [xml]$eventXml = $event.ToXml()
                    $activityID = if ($eventXml.Event.System.Correlation.ActivityID) { 
                        $eventXml.Event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
                    $accountName = if ($message -match 'Account Name:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    $userDomain = if ($message -match 'Account Domain:\s+([^\r\n]+)') { $matches[1].Trim() } else { 'N/A' }
                    
                    # Construct DOMAIN\User format to match TerminalServices events
                    if ($userDomain -ne 'N/A' -and $userDomain -ne '-' -and $accountName -ne 'N/A') {
                        $userName = "$userDomain\$accountName"
                    }
                    else {
                        $userName = $accountName
                    }
                    
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
                        ActivityID  = $activityID
                        Details     = "LogonType: $logonType"
                    }
                }
            }
        
            if ($systemEvents) {
                foreach ($event in $systemEvents) {
                    # Extract ActivityID from XML
                    [xml]$eventXml = $event.ToXml()
                    $activityID = if ($eventXml.Event.System.Correlation.ActivityID) { 
                        $eventXml.Event.System.Correlation.ActivityID 
                    }
                    else { 
                        $null 
                    }
                
                    $results += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventID     = $event.Id
                        EventType   = 'Desktop Window Manager Exit'
                        User        = 'N/A'
                        Domain      = 'N/A'
                        SourceIP    = 'N/A'
                        SessionID   = $null
                        LogonID     = $null
                        ActivityID  = $activityID
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
    
        Write-Host "$(Get-Emoji 'magnify') [7/7] Collecting Outbound RDP Connections (EventID 1102)..." -ForegroundColor Yellow
    
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
    $allEvents += Get-RDPAuthenticationEvents -Start $StartDate -End $EndDate -IncludeKerberosAndNTLM $IncludeCredentialValidation.IsPresent
    $allEvents += Get-RDPSessionEvents -Start $StartDate -End $EndDate
    $allEvents += Get-RDPLockUnlockEvents -Start $StartDate -End $EndDate
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
    
    if ($SessionID) {
        Write-Host "Filtering for SessionID: $SessionID" -ForegroundColor Cyan
        # Filter events to only those matching SessionID OR Security events without SessionID
        $allEvents = $allEvents | Where-Object {
            ($_.SessionID -eq $SessionID -or $_.SessionID -eq [string]$SessionID) -or
            ((-not $_.SessionID -or $_.SessionID -eq 'N/A') -and $_.EventID -in @(1149, 4624, 4625, 4648, 4768, 4769, 4770, 4771, 4772, 4776, 4778, 4779, 4800, 4801, 4634, 4647, 9009))
        }
    }

    # Sort by time
    $allEvents = $allEvents | Sort-Object TimeCreated -Descending

    # Correlate events by LogonID and SessionID if GroupBySession is specified
    if ($GroupBySession) {
        Write-Host "`n" -NoNewline
        Write-Host "$(Get-Emoji 'key') Correlating events by LogonID/SessionID..." -ForegroundColor Cyan
        $correlationResult = Get-CorrelatedSessions -Events $allEvents
        $sessions = $correlationResult.Sessions
        $allEvents = $correlationResult.FilteredEvents  # Use filtered events (pre-auth events matched to RDP only)
        Write-Host "  $(Get-Emoji 'check') Found " -ForegroundColor Green -NoNewline
        Write-Host "$($sessions.Count)" -ForegroundColor White -NoNewline
        Write-Host " unique sessions (using LogonID-based correlation)" -ForegroundColor Green
        
        if ($IncludeCredentialValidation) {
            $preAuthCount = ($allEvents | Where-Object { $_.EventID -in 4768, 4769, 4770, 4771, 4772, 4776 }).Count
            Write-Host "  $(Get-Emoji 'check') Filtered to " -ForegroundColor Green -NoNewline
            Write-Host "$preAuthCount" -ForegroundColor White -NoNewline
            Write-Host " pre-auth events correlated to RDP sessions (non-RDP auth filtered out)" -ForegroundColor Green
        }
        
        # Apply LogonID/SessionID filters if specified
        if ($LogonID) {
            Write-Host "  $(Get-Emoji 'magnify') Filtering for LogonID: $LogonID" -ForegroundColor Cyan
            $sessions = $sessions | Where-Object { $_.LogonID -eq $LogonID }
            if ($sessions.Count -eq 0) {
                Write-Host "  $(Get-Emoji 'warning') No sessions found with LogonID: $LogonID" -ForegroundColor Yellow
            }
        }
        
        # Update event list to show only events from filtered sessions
        if ($LogonID) {
            $allEvents = @($sessions | ForEach-Object { $_.Events }) | Sort-Object TimeCreated -Descending
        }
    }

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

        # Display session-grouped results if requested
        if ($GroupBySession -and $sessions) {
            Write-Host "`n" -NoNewline
            Write-Host ($separator * 58) -ForegroundColor DarkCyan
            Write-Host "$(Get-Emoji 'key') CORRELATED RDP SESSIONS" -ForegroundColor Cyan
            Write-Host ($separator * 58) -ForegroundColor DarkCyan
            
            # Box-drawing characters for PS 5.1 compatibility
            $sessionSep = [string][char]0x2500  # Horizontal line
            $arrow = [string][char]0x2192  # Right arrow
            
            foreach ($session in $sessions | Select-Object -First 20) {
                Write-Host "`n" -NoNewline
                Write-Host "$($sessionSep * 3) Session: " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($session.CorrelationKey)" -ForegroundColor White -NoNewline
                Write-Host " $($sessionSep * 3)" -ForegroundColor DarkGray
                
                Write-Host "  $(Get-Emoji 'user') User: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.User)" -ForegroundColor White -NoNewline
                Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
                Write-Host "$(Get-Emoji 'computer') Source IP: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.SourceIP)" -ForegroundColor White
                
                Write-Host "  $(Get-Emoji 'clock') Start: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.StartTime)" -ForegroundColor White -NoNewline
                Write-Host "  |  End: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.EndTime)" -ForegroundColor White -NoNewline
                Write-Host "  |  Duration: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.Duration)" -ForegroundColor Yellow
                
                Write-Host "  $(Get-Emoji 'chart') Lifecycle: " -ForegroundColor Cyan -NoNewline
                if ($session.ConnectionAttempt) { Write-Host "Connect " -ForegroundColor Green -NoNewline } else { Write-Host "- " -ForegroundColor DarkGray -NoNewline }
                Write-Host "$arrow " -ForegroundColor DarkGray -NoNewline
                if ($session.Authentication) { Write-Host "Auth " -ForegroundColor Green -NoNewline } else { Write-Host "- " -ForegroundColor DarkGray -NoNewline }
                Write-Host "$arrow " -ForegroundColor DarkGray -NoNewline
                if ($session.Logon) { Write-Host "Logon " -ForegroundColor Green -NoNewline } else { Write-Host "- " -ForegroundColor DarkGray -NoNewline }
                Write-Host "$arrow " -ForegroundColor DarkGray -NoNewline
                if ($session.Active) { Write-Host "Active " -ForegroundColor Green -NoNewline } else { Write-Host "- " -ForegroundColor DarkGray -NoNewline }
                Write-Host "$arrow " -ForegroundColor DarkGray -NoNewline
                if ($session.Disconnect) { Write-Host "Disconnect " -ForegroundColor Yellow -NoNewline } else { Write-Host "- " -ForegroundColor DarkGray -NoNewline }
                Write-Host "$arrow " -ForegroundColor DarkGray -NoNewline
                if ($session.Logoff) { Write-Host "Logoff" -ForegroundColor Green } else { Write-Host "-" -ForegroundColor DarkGray }
                
                Write-Host "  $(Get-Emoji 'folder') Events: " -ForegroundColor Cyan -NoNewline
                Write-Host "$($session.EventCount)" -ForegroundColor White -NoNewline
                if (-not $session.LifecycleComplete) {
                    # Provide specific warning based on what's missing
                    if (-not $session.Authentication -and -not $session.Logon) {
                        Write-Host "  $(Get-Emoji 'warning') Missing authentication/logon events" -ForegroundColor Yellow
                    }
                    elseif ($session.Logoff -and -not $session.Logon) {
                        Write-Host "  $(Get-Emoji 'warning') Suspicious: Logoff without Logon" -ForegroundColor Red
                    }
                    else {
                        Write-Host "  $(Get-Emoji 'warning') Partial session data (may be active or outside time window)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host ""
                }
                
                # Display event table for this session
                Write-Host ""
                $session.Events | Sort-Object TimeCreated | Format-Table TimeCreated, EventID, EventType, User, SourceIP, SessionID, LogonID, Details -AutoSize
            }
            
            if ($sessions.Count -gt 20) {
                Write-Host "`n... and $($sessions.Count - 20) more sessions" -ForegroundColor DarkGray
            }
        }
        else {
            # Display recent events (default view)
            Write-Host "`n" -NoNewline
            Write-Host ($separator * 58) -ForegroundColor DarkCyan
            Write-Host "$(Get-Emoji 'magnify') RECENT RDP EVENTS (Top 50)" -ForegroundColor Cyan
            Write-Host ($separator * 58) -ForegroundColor DarkCyan
            $allEvents | Select-Object -First 50 | Format-Table TimeCreated, EventID, EventType, User, SourceIP, Details -AutoSize
        }
    
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
            
            # Export sessions if correlation was used
            if ($GroupBySession -and $sessions) {
                $sessionFile = Join-Path $ExportPath "RDP_Sessions_$timestamp.csv"
                $sessions | Select-Object CorrelationKey, User, SourceIP, StartTime, EndTime, Duration, EventCount, 
                ConnectionAttempt, Authentication, Logon, Active, Disconnect, Logoff, LifecycleComplete | 
                Export-Csv -Path $sessionFile -NoTypeInformation -Encoding UTF8
                Write-Host "$(Get-Emoji 'check') Sessions exported to: " -ForegroundColor Green -NoNewline
                Write-Host "$sessionFile" -ForegroundColor White
            }
        }
    }
    else {
        Write-Host "`n$(Get-Emoji 'warning') No RDP events found matching the criteria." -ForegroundColor Yellow
    }

    # Note: Function displays results directly to host, no pipeline output
    # To capture events for pipeline use, export to CSV and reimport
}

