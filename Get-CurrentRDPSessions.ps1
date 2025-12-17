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
    Version: 1.0.8
    Requires: Administrator privileges
    
    Changelog v1.0.8:
    - Added Win32 API (WTS) integration for extended session properties
    - New properties: IdleTime, ClientIPAddress, ClientName, EncryptionLevel
    - New properties: ConnectTime, ClientBuildNumber, ClientDisplay, ColorDepth
    - Improved accuracy without Event Log dependency for basic info
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

    # Win32 API Definitions for Windows Terminal Services (WTS)
    # Only add type if not already loaded
    if (-not ([System.Management.Automation.PSTypeName]'WTSApi').Type) {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
    
    public enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }
    
    public enum WTS_INFO_CLASS
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSClientBuildNumber,
        WTSClientName,
        WTSClientDirectory,
        WTSClientProductId,
        WTSClientHardwareId,
        WTSClientAddress,
        WTSClientDisplay,
        WTSClientProtocolType,
        WTSIdleTime,
        WTSLogonTime,
        WTSIncomingBytes,
        WTSOutgoingBytes,
        WTSIncomingFrames,
        WTSOutgoingFrames,
        WTSClientInfo,
        WTSSessionInfo,
        WTSSessionInfoEx,
        WTSConfigInfo,
        WTSValidationInfo,
        WTSSessionAddressV4,
        WTSIsRemoteSession
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_CLIENT_ADDRESS
    {
        public int AddressFamily;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Address;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_CLIENT_DISPLAY
    {
        public int HorizontalResolution;
        public int VerticalResolution;
        public int ColorDepth;
    }
    
    public class WTSApi
    {
        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            out IntPtr ppSessionInfo,
            out int pCount);
        
        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out int pBytesReturned);
        
        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);
        
        public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
    }
"@
    }

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

    # Helper function to query WTS session information
    function Get-WTSSessionInfo {
        param(
            [int]$SessionId,
            [WTS_INFO_CLASS]$InfoClass
        )
        
        $buffer = [IntPtr]::Zero
        $bytesReturned = 0
        
        try {
            $result = [WTSApi]::WTSQuerySessionInformation(
                [WTSApi]::WTS_CURRENT_SERVER_HANDLE,
                $SessionId,
                $InfoClass,
                [ref]$buffer,
                [ref]$bytesReturned
            )
            
            if ($result -and $buffer -ne [IntPtr]::Zero) {
                switch ($InfoClass) {
                    ([WTS_INFO_CLASS]::WTSClientAddress) {
                        $clientAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [Type][WTS_CLIENT_ADDRESS])
                        if ($clientAddr.AddressFamily -eq 2) {
                            # AF_INET (IPv4)
                            return "$($clientAddr.Address[2]).$($clientAddr.Address[3]).$($clientAddr.Address[4]).$($clientAddr.Address[5])"
                        }
                        return "Unknown"
                    }
                    ([WTS_INFO_CLASS]::WTSClientDisplay) {
                        $display = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [Type][WTS_CLIENT_DISPLAY])
                        return [PSCustomObject]@{
                            Width      = $display.HorizontalResolution
                            Height     = $display.VerticalResolution
                            ColorDepth = $display.ColorDepth
                        }
                    }
                    ([WTS_INFO_CLASS]::WTSIdleTime) {
                        $idleTime = [System.Runtime.InteropServices.Marshal]::ReadInt64($buffer)
                        return $idleTime
                    }
                    ([WTS_INFO_CLASS]::WTSLogonTime) {
                        $logonTime = [System.Runtime.InteropServices.Marshal]::ReadInt64($buffer)
                        if ($logonTime -gt 0) {
                            return [DateTime]::FromFileTime($logonTime)
                        }
                        return $null
                    }
                    ([WTS_INFO_CLASS]::WTSClientBuildNumber) {
                        return [System.Runtime.InteropServices.Marshal]::ReadInt32($buffer)
                    }
                    default {
                        # String properties - use Unicode marshaling
                        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($buffer)
                    }
                }
            }
            return $null
        }
        finally {
            if ($buffer -ne [IntPtr]::Zero) {
                [WTSApi]::WTSFreeMemory($buffer)
            }
        }
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
        
        # Write CSV header with extended properties
        "Timestamp,EventType,SessionName,Username,SessionID,State,ClientIP,ClientName,ConnectTime,ClientBuild,IdleTime,Details" | Out-File -FilePath $logFile -Encoding UTF8
        
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

        # ASCII Art Header - Use basic ASCII for PowerShell 5.1 compatibility
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 53) -ForegroundColor Green
        Write-Host "     ACTIVE RDP SESSIONS MONITOR v1.0.8            " -ForegroundColor White
        Write-Host ("=" * 53) -ForegroundColor Green
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

        # Get current sessions using qwinsta (reliable) + WTS API for extended properties
        try {
            $sessions = qwinsta 2>$null
    
            if ($sessions) {
                # Parse qwinsta output
                $sessionObjects = @()
        
                foreach ($line in $sessions | Select-Object -Skip 1) {
                    if ($line -match '^\s*>?\s*(\S+)\s+(\S+|\s+)\s+(\d+)\s+(\S+)') {
                        $sessionName = $matches[1].Trim()
                        $username = $matches[2].Trim()
                        $id = [int]$matches[3].Trim()
                        $state = $matches[4].Trim()
                
                        # Only include active/disconnected RDP sessions
                        # Exclude: console (local), services (system), Listen states (RDP listeners)
                        # Include: rdp-tcp#X sessions with Active/Disc/Conn states
                        if ($sessionName -match 'rdp-tcp#\d+' -and $state -notmatch 'Listen') {
                            # Use WTS API to get extended session properties
                            $clientName = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSClientName)
                            # Filter out invalid client names (empty, whitespace, or non-ASCII junk)
                            if ($clientName -and $clientName.Trim() -ne '' -and $clientName -match '^[\x20-\x7E]+$') {
                                $clientName = $clientName.Trim()
                            }
                            else {
                                $clientName = $null
                            }
                            $clientIP = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSClientAddress)
                            $clientBuild = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSClientBuildNumber)
                            $clientDisplay = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSClientDisplay)
                            $idleTime = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSIdleTime)
                            $wtsConnectTime = Get-WTSSessionInfo -SessionId $id -InfoClass ([WTS_INFO_CLASS]::WTSLogonTime)
                            
                            # Always check Event Log for most accurate connection time
                            # WTS API may return stale data for new sessions after logoff/logon
                            $eventLogConnectTime = $null
                            
                            if ($username -and $username -ne '') {
                                # Priority 1: Check Security Event 4778 (reconnection)
                                $reconnectEvent = Get-WinEvent -FilterHashtable @{
                                    LogName = 'Security'
                                    Id      = 4778
                                } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {
                                    $_.Message -match [regex]::Escape($username)
                                } | Select-Object -First 1
                                
                                if ($reconnectEvent) {
                                    $eventLogConnectTime = $reconnectEvent.TimeCreated
                                }
                                
                                # Priority 2: Check Terminal Services Event 25 (reconnection)
                                if (-not $eventLogConnectTime) {
                                    $tsReconnect = Get-WinEvent -FilterHashtable @{
                                        LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                                        Id      = 25
                                    } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {
                                        $_.Message -match [regex]::Escape($username) -and
                                        $_.Properties[0].Value -eq $id  # Session ID
                                    } | Select-Object -First 1
                                    
                                    if ($tsReconnect) {
                                        $eventLogConnectTime = $tsReconnect.TimeCreated
                                    }
                                }
                                
                                # Priority 3: Check Security Event 4624 (initial logon)
                                if (-not $eventLogConnectTime) {
                                    $logonEvent = Get-WinEvent -FilterHashtable @{
                                        LogName = 'Security'
                                        Id      = 4624
                                    } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
                                        $_.Message -match [regex]::Escape($username) -and 
                                        $_.Message -match 'Logon Type:\s+(10|7)\s' -and
                                        ($clientIP -and $_.Message -match [regex]::Escape($clientIP))
                                    } | Select-Object -First 1
                                    
                                    if ($logonEvent) {
                                        $eventLogConnectTime = $logonEvent.TimeCreated
                                    }
                                }
                                
                                # Priority 4: Check Terminal Services Event 21 (session logon) or 22 (shell start)
                                if (-not $eventLogConnectTime) {
                                    $tsLogon = Get-WinEvent -FilterHashtable @{
                                        LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                                        Id      = 21, 22
                                    } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
                                        $_.Message -match [regex]::Escape($username) -and
                                        $_.Properties[0].Value -eq $id  # Session ID
                                    } | Select-Object -First 1
                                    
                                    if ($tsLogon) {
                                        $eventLogConnectTime = $tsLogon.TimeCreated
                                    }
                                }
                            }
                            
                            # Use the most recent time between WTS API and Event Log
                            # This handles cases where WTS returns stale data
                            $connectTime = if ($eventLogConnectTime -and $wtsConnectTime) {
                                # Both available - use most recent
                                if ($eventLogConnectTime -gt $wtsConnectTime) { $eventLogConnectTime } else { $wtsConnectTime }
                            }
                            elseif ($eventLogConnectTime) {
                                # Only Event Log available
                                $eventLogConnectTime
                            }
                            elseif ($wtsConnectTime) {
                                # Only WTS available
                                $wtsConnectTime
                            }
                            else {
                                # No time available
                                $null
                            }
                            
                            # Calculate idle time in readable format
                            $idleTimeDisplay = if ($idleTime -ne $null -and $idleTime -ge 0) {
                                $idleMinutes = [Math]::Floor($idleTime / 60000)
                                if ($idleMinutes -lt 1) { "<1 min" }
                                elseif ($idleMinutes -lt 60) { "$idleMinutes min" }
                                else { "$([Math]::Floor($idleMinutes / 60))h $($idleMinutes % 60)m" }
                            }
                            else { "N/A" }
                            
                            $sessionObjects += [PSCustomObject]@{
                                SessionName   = $sessionName
                                Username      = if ($username -and $username -ne '') { $username } else { 'N/A' }
                                ID            = $id
                                State         = $state
                                Type          = 'RDP'
                                ClientName    = if ($clientName) { $clientName } else { 'N/A' }
                                ClientIP      = if ($clientIP) { $clientIP } else { 'Unknown' }
                                ClientBuild   = if ($clientBuild) { $clientBuild } else { 'N/A' }
                                ClientDisplay = if ($clientDisplay) { "$($clientDisplay.Width)x$($clientDisplay.Height) ($($clientDisplay.ColorDepth)bit)" } else { 'N/A' }
                                IdleTime      = $idleTimeDisplay
                                ConnectTime   = if ($connectTime) { $connectTime } else { $null }
                            }
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
                        $connectTimeStr = if ($session.ConnectTime) { $session.ConnectTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),NEW_SESSION,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),$($session.ClientIP),$($session.ClientName),$connectTimeStr,$($session.ClientBuild),$($session.IdleTime),New RDP session detected"
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                        Write-Host "  [LOG] New session: $($session.Username) from $($session.ClientIP) (ID: $($session.ID))" -ForegroundColor Green
                    }
                    elseif ($previousSessions[$key].State -ne $session.State) {
                        # State change detected
                        $connectTimeStr = if ($session.ConnectTime) { $session.ConnectTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),STATE_CHANGE,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),$($session.ClientIP),$($session.ClientName),$connectTimeStr,$($session.ClientBuild),$($session.IdleTime),State changed from $($previousSessions[$key].State) to $($session.State)"
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                        Write-Host "  [LOG] State change: $($session.Username) - $($previousSessions[$key].State) -> $($session.State)" -ForegroundColor Yellow
                    }
                }
                
                # Check for disconnected/removed sessions
                foreach ($key in $previousSessions.Keys) {
                    if (-not $currentSessionKeys.ContainsKey($key)) {
                        $oldSession = $previousSessions[$key]
                        $connectTimeStr = if ($oldSession.ConnectTime) { $oldSession.ConnectTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),SESSION_ENDED,$($oldSession.SessionName),$($oldSession.Username),$($oldSession.ID),$($oldSession.State),$($oldSession.ClientIP),$($oldSession.ClientName),$connectTimeStr,$($oldSession.ClientBuild),$($oldSession.IdleTime),Session ended or disconnected"
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                        Write-Host "  [LOG] Session ended: $($oldSession.Username) from $($oldSession.ClientIP) (ID: $($oldSession.ID))" -ForegroundColor Red
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
                    $connectTimeStr = if ($session.ConnectTime) { $session.ConnectTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),INITIAL_STATE,$($session.SessionName),$($session.Username),$($session.ID),$($session.State),$($session.ClientIP),$($session.ClientName),$connectTimeStr,$($session.ClientBuild),$($session.IdleTime),Monitoring started - session already active"
                    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                }
            }
        
            if ($sessionObjects.Count -gt 0) {
                Write-Host "`n" -NoNewline
                Write-Host ("-" * 80) -ForegroundColor DarkGreen
                Write-Host "$(Get-Emoji 'user') ACTIVE SESSIONS (" -ForegroundColor Yellow -NoNewline
                Write-Host "$($sessionObjects.Count)" -ForegroundColor White -NoNewline
                Write-Host ")" -ForegroundColor Yellow
                Write-Host ("-" * 80) -ForegroundColor DarkGreen
                    
                # Display sessions with extended properties
                $sessionObjects | Select-Object SessionName, Username, ID, State, ClientIP, ClientName, ConnectTime, IdleTime, ClientBuild, ClientDisplay | Format-Table -AutoSize
            
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
                Write-Host ("-" * 80) -ForegroundColor DarkGreen
                Write-Host "$(Get-Emoji 'chart') RECENT LOGON INFORMATION" -ForegroundColor Yellow
                Write-Host ("-" * 80) -ForegroundColor DarkGreen
                foreach ($session in $sessionObjects | Where-Object { $_.Username -ne 'N/A' }) {
                    # Check for reconnection first (4778), then initial logon (4624)
                    $recentActivity = Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        Id      = 4778
                    } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {
                        $_.Message -match [regex]::Escape($session.Username)
                    } | Select-Object -First 1
                    
                    if (-not $recentActivity) {
                        $recentActivity = Get-WinEvent -FilterHashtable @{
                            LogName = 'Security'
                            Id      = 4624
                        } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
                            $_.Message -match [regex]::Escape($session.Username) -and $_.Message -match 'Logon Type:\s+(10|7)\s'
                        } | Select-Object -First 1
                    }
                
                    if ($recentActivity) {
                        $sourceIP = if ($recentActivity.Message -match '(Source Network Address|Client Address):\s+([^\r\n]+)') { 
                            $matches[2].Trim() 
                        }
                        else { 
                            'N/A' 
                        }
                        
                        $activityType = if ($recentActivity.Id -eq 4778) { "Last activity" } else { "Last logon" }
                    
                        Write-Host "  $(Get-Emoji 'check') " -ForegroundColor Green -NoNewline
                        Write-Host "$($session.Username)" -ForegroundColor Cyan -NoNewline
                        Write-Host " - $activityType" -ForegroundColor Gray -NoNewline
                        Write-Host ": $($recentActivity.TimeCreated)" -ForegroundColor White -NoNewline
                        Write-Host " from " -ForegroundColor Gray -NoNewline
                        Write-Host "$sourceIP" -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Host "$(Get-Emoji 'warning') No active RDP sessions found." -ForegroundColor Yellow
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

