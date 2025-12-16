#Requires -RunAsAdministrator

function Get-CurrentRDPSessions {
    <#
.SYNOPSIS
    Display current active RDP sessions on the system.

.DESCRIPTION
    Shows currently logged-on RDP users, their session IDs, states, and processes.
    Useful for real-time monitoring and quick session overview.

.PARAMETER SessionID
    Optional session ID to get detailed information about a specific session.

.PARAMETER ShowProcesses
    Show running processes for each session.

.PARAMETER Watch
    Enable continuous monitoring mode with auto-refresh. Press Ctrl+C to exit.

.PARAMETER RefreshInterval
    Refresh interval in seconds when using -Watch mode. Default is 5 seconds.

.PARAMETER LogPath
    Path to write session change log file. Logs new connections, disconnections, and state changes.
    Creates a timestamped CSV file for later analysis. Works in both single-check and Watch mode.

.EXAMPLE
    Get-CurrentRDPSessions
    Display all current RDP sessions.

.EXAMPLE
    Get-CurrentRDPSessions -SessionID 3 -ShowProcesses
    Show detailed information and processes for session 3.

.EXAMPLE
    Get-CurrentRDPSessions -Watch
    Continuously monitor RDP sessions with 5-second refresh.

.EXAMPLE
    Get-CurrentRDPSessions -Watch -RefreshInterval 10
    Monitor sessions with 10-second refresh interval.

.EXAMPLE
    Get-CurrentRDPSessions -Watch -LogPath "C:\Logs\RDP_Monitor"
    Monitor sessions with logging enabled. Changes are written to CSV for later analysis.

.EXAMPLE
    Get-CurrentRDPSessions -Watch -RefreshInterval 5 -LogPath "C:\SecurityLogs\RDP" -ShowProcesses
    Full monitoring with process tracking and change logging for incident response.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.4
    Requires: Administrator privileges
#>

    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$SessionID,
    
        [Parameter()]
        [switch]$ShowProcesses,

        [Parameter()]
        [switch]$Watch,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$RefreshInterval = 5,

        [Parameter()]
        [string]$LogPath
    )

    # Emoji support for both PowerShell 5.1 and 7.x
    function Get-Emoji {
        param([string]$Name)
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $emojis = @{
                'computer' = [char]::ConvertFromUtf32(0x1F4BB)
                'clock'    = [char]::ConvertFromUtf32(0x23F1) + [char]::ConvertFromUtf32(0xFE0F)
                'user'     = [char]::ConvertFromUtf32(0x1F464)
                'check'    = [char]::ConvertFromUtf32(0x2705)
                'warning'  = [char]::ConvertFromUtf32(0x26A0) + [char]::ConvertFromUtf32(0xFE0F)
                'chart'    = [char]::ConvertFromUtf32(0x1F4CA)
            }
        }
        else {
            # PowerShell 5.1 - Use Unicode symbols that work in Windows Console
            $emojis = @{
                'computer' = "$([char]0x25A3)"  # White square with rounded corners
                'clock'    = "$([char]0x25D4)"  # Circle with upper right quadrant
                'user'     = "$([char]0x263A)"  # White smiling face
                'check'    = "$([char]0x221A)"  # Square root (checkmark-like)
                'warning'  = "$([char]0x203C)"  # Double exclamation
                'chart'    = "$([char]0x25A0)"  # Black square
            }
        }
        return $emojis[$Name]
    }

    # Initialize logging if LogPath is specified
    $logFile = $null
    $previousSessions = @{}
    
    if ($LogPath) {
        # Create log directory if it doesn't exist
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }
        
        # Create timestamped log file
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $logFile = Join-Path $LogPath "RDP_SessionMonitor_$timestamp.csv"
        
        # Write CSV header
        "Timestamp,EventType,SessionName,Username,SessionID,State,SourceIP,Details" | Out-File -FilePath $logFile -Encoding UTF8
        
        Write-Host "$(Get-Emoji 'chart') Logging enabled: " -ForegroundColor Cyan -NoNewline
        Write-Host "$logFile" -ForegroundColor Green
        Write-Host ""
    }

    # Main monitoring logic wrapped in a loop for Watch mode
    $continueMonitoring = $true
    $iterationCount = 0

    while ($continueMonitoring) {
        # Clear screen only in Watch mode (after first iteration)
        if ($Watch -and $iterationCount -gt 0) {
            Clear-Host
        }

        # ASCII Art Header
        Write-Host "`n" -NoNewline
        $topLeft = [char]0x2554; $topRight = [char]0x2557; $bottomLeft = [char]0x255A; $bottomRight = [char]0x255D
        $horizontal = [string][char]0x2550; $vertical = [char]0x2551
        Write-Host "$topLeft$($horizontal * 51)$topRight" -ForegroundColor Green
        Write-Host "$vertical" -ForegroundColor Green -NoNewline
        Write-Host "     ACTIVE RDP SESSIONS MONITOR v1.0.4            " -ForegroundColor White -NoNewline
        Write-Host "$vertical" -ForegroundColor Green
        Write-Host "$bottomLeft$($horizontal * 51)$bottomRight" -ForegroundColor Green
        Write-Host ""
        Write-Host "$(Get-Emoji 'computer') Computer: " -ForegroundColor Cyan -NoNewline
        Write-Host "$env:COMPUTERNAME" -ForegroundColor White
        Write-Host "$(Get-Emoji 'clock') Time: " -ForegroundColor Cyan -NoNewline
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        
        if ($Watch) {
            Write-Host "$(Get-Emoji 'check') Mode: " -ForegroundColor Cyan -NoNewline
            Write-Host "Auto-Refresh (${RefreshInterval}s) - Press Ctrl+C to exit" -ForegroundColor Yellow
        }
        Write-Host ""

        # Get current sessions using qwinsta
        try {
            $sessions = qwinsta 2>$null
    
            if ($sessions) {
                # Parse qwinsta output
                $sessionObjects = @()
        
                foreach ($line in $sessions | Select-Object -Skip 1) {
                    if ($line -match '^\s*>?\s*(\S+)\s+(\S+|\s+)\s+(\d+)\s+(\S+)') {
                        $sessionName = $matches[1].Trim()
                        $username = $matches[2].Trim()
                        $id = $matches[3].Trim()
                        $state = $matches[4].Trim()
                
                        # Only include active/disconnected RDP sessions
                        # Exclude: console (local), services (system), Listen states (RDP listeners)
                        # Include: rdp-tcp#X sessions with Active/Disc/Conn states
                        if ($sessionName -match 'rdp-tcp#\d+' -and $state -notmatch 'Listen') {
                            $sessionObjects += [PSCustomObject]@{
                                SessionName = $sessionName
                                Username    = if ($username -and $username -ne '') { $username } else { 'N/A' }
                                ID          = [int]$id
                                State       = $state
                                Type        = 'RDP'
                            }
                        }
                    }
                }
        
                # Log changes if logging is enabled
                if ($logFile -and $iterationCount -gt 0) {
                    $currentSessionKeys = @{}
                
                    foreach ($session in $sessionObjects) {
                        $key = "$($session.SessionName)-$($session.ID)"
                        $currentSessionKeys[$key] = $session
                    
                        # Check for new sessions or state changes
                        if (-not $previousSessions.ContainsKey($key)) {
                            # New session detected
                            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),NEW_SESSION,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),,New RDP session detected"
                            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                            Write-Host "  [LOG] New session: $($session.Username) (ID: $($session.ID))" -ForegroundColor Green
                        }
                        elseif ($previousSessions[$key].State -ne $session.State) {
                            # State change detected
                            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),STATE_CHANGE,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),,State changed from $($previousSessions[$key].State) to $($session.State)"
                            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                            Write-Host "  [LOG] State change: $($session.Username) - $($previousSessions[$key].State) -> $($session.State)" -ForegroundColor Yellow
                        }
                    }
                
                    # Check for disconnected/removed sessions
                    foreach ($key in $previousSessions.Keys) {
                        if (-not $currentSessionKeys.ContainsKey($key)) {
                            $oldSession = $previousSessions[$key]
                            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),SESSION_ENDED,$($oldSession.SessionName),$($oldSession.Username),$($oldSession.ID),$($oldSession.State),,Session ended or disconnected"
                            $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                            Write-Host "  [LOG] Session ended: $($oldSession.Username) (ID: $($oldSession.ID))" -ForegroundColor Red
                        }
                    }
                
                    # Update previous sessions tracking
                    $previousSessions = $currentSessionKeys
                }
                elseif ($logFile -and $iterationCount -eq 0) {
                    # First iteration - just record initial state
                    foreach ($session in $sessionObjects) {
                        $key = "$($session.SessionName)-$($session.ID)"
                        $previousSessions[$key] = $session
                        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),INITIAL_STATE,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),,Monitoring started - session already active"
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                    }
                }
        
                if ($sessionObjects.Count -gt 0) {
                    Write-Host "`n" -NoNewline
                    Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGreen
                    Write-Host "$(Get-Emoji 'user') ACTIVE SESSIONS (" -ForegroundColor Yellow -NoNewline
                    Write-Host "$($sessionObjects.Count)" -ForegroundColor White -NoNewline
                    Write-Host ")" -ForegroundColor Yellow
                    $separator = [string][char]0x2500
                    Write-Host ($separator * 42) -ForegroundColor DarkGreen
                    $sessionObjects | Format-Table -AutoSize
            
                    # Show processes for specific session or all if requested
                    if ($ShowProcesses) {
                        if ($SessionID) {
                            $targetSessions = $sessionObjects | Where-Object { $_.ID -eq $SessionID }
                        }
                        else {
                            $targetSessions = $sessionObjects
                        }
                
                        foreach ($session in $targetSessions) {
                            Write-Host "`n$(Get-Emoji 'computer') Processes for Session " -ForegroundColor Yellow -NoNewline
                            Write-Host "$($session.ID)" -ForegroundColor White -NoNewline
                            Write-Host " - User: " -ForegroundColor Yellow -NoNewline
                            Write-Host "$($session.Username)" -ForegroundColor Cyan
                    
                            try {
                                $processes = qprocess /id:$($session.ID) 2>$null
                                if ($processes) {
                                    $processes | Select-Object -Skip 1 | ForEach-Object {
                                        Write-Host "  $_" -ForegroundColor Gray
                                    }
                                }
                                else {
                                    Write-Host "  No processes found or unable to query" -ForegroundColor Gray
                                }
                            }
                            catch {
                                Write-Host "  Error querying processes: $_" -ForegroundColor Red
                            }
                        }
                    }
            
                    # Get recent logon events for active users
                    Write-Host "`n" -NoNewline
                    Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGreen
                    Write-Host "$(Get-Emoji 'chart') RECENT LOGON INFORMATION" -ForegroundColor Yellow
                    Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGreen
                    foreach ($session in $sessionObjects | Where-Object { $_.Username -ne 'N/A' }) {
                        $recentLogon = Get-WinEvent -FilterHashtable @{
                            LogName = 'Security'
                            Id      = 4624
                        } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
                            $_.Message -match $session.Username -and $_.Message -match 'Logon Type:\s+(10|7)\s'
                        } | Select-Object -First 1
                
                        if ($recentLogon) {
                            $sourceIP = if ($recentLogon.Message -match 'Source Network Address:\s+([^\r\n]+)') { 
                                $matches[1].Trim() 
                            }
                            else { 
                                'N/A' 
                            }
                    
                            Write-Host "  $(Get-Emoji 'check') " -ForegroundColor Green -NoNewline
                            Write-Host "$($session.Username)" -ForegroundColor Cyan -NoNewline
                            Write-Host " - Last logon: " -ForegroundColor Gray -NoNewline
                            Write-Host "$($recentLogon.TimeCreated)" -ForegroundColor White -NoNewline
                            Write-Host " from " -ForegroundColor Gray -NoNewline
                            Write-Host "$sourceIP" -ForegroundColor Yellow
                        }
                    }
                }
                else {
                    Write-Host "$(Get-Emoji 'warning') No active RDP sessions found." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "$(Get-Emoji 'cross') Unable to query sessions." -ForegroundColor Red
            }
        }
        catch {
            Write-Error "Error getting session information: $_"
        }

        Write-Host ""

        # Handle Watch mode loop
        if ($Watch) {
            $iterationCount++
            Write-Host "Next refresh in $RefreshInterval seconds..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $RefreshInterval
        }
        else {
            $continueMonitoring = $false
        }
    }
}

