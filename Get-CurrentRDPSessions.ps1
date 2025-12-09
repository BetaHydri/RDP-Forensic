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

.EXAMPLE
    Get-CurrentRDPSessions
    Display all current RDP sessions.

.EXAMPLE
    Get-CurrentRDPSessions -SessionID 3 -ShowProcesses
    Show detailed information and processes for session 3.

.NOTES
    Author: Jan Tiedemann
    Version: 1.0.0
    Requires: Administrator privileges
#>

    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$SessionID,
    
        [Parameter()]
        [switch]$ShowProcesses
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
        } else {
            $emojis = @{
                'computer' = '[PC]'
                'clock'    = '[TIME]'
                'user'     = '[USER]'
                'check'    = '[OK]'
                'warning'  = '[!]'
                'chart'    = '[INFO]'
            }
        }
        return $emojis[$Name]
    }

    # ASCII Art Header
    Write-Host "`n" -NoNewline
    $topLeft = [char]0x2554; $topRight = [char]0x2557; $bottomLeft = [char]0x255A; $bottomRight = [char]0x255D
    $horizontal = [string][char]0x2550; $vertical = [char]0x2551
    Write-Host "$topLeft$($horizontal * 51)$topRight" -ForegroundColor Green
    Write-Host "$vertical" -ForegroundColor Green -NoNewline
    Write-Host "     ACTIVE RDP SESSIONS MONITOR v1.0.0         " -ForegroundColor White -NoNewline
    Write-Host "$vertical" -ForegroundColor Green
    Write-Host "$bottomLeft$($horizontal * 51)$bottomRight" -ForegroundColor Green
    Write-Host ""
    Write-Host "$(Get-Emoji 'computer') Computer: " -ForegroundColor Cyan -NoNewline
    Write-Host "$env:COMPUTERNAME" -ForegroundColor White
    Write-Host "$(Get-Emoji 'clock') Time: " -ForegroundColor Cyan -NoNewline
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host ""

    # Get current sessions using qwinsta
    try {
        $sessions = qwinsta 2>$null
    
        if ($sessions) {
            # Parse qwinsta output
            $sessionObjects = @()
        
            foreach ($line in $sessions | Select-Object -Skip 1) {
                if ($line -match '^\s*(\S+|\s+)\s+(\S+|\s+)\s+(\d+)\s+(\S+)\s+(\S+)') {
                    $sessionName = $matches[1].Trim()
                    $username = $matches[2].Trim()
                    $id = $matches[3].Trim()
                    $state = $matches[4].Trim()
                    $type = $matches[5].Trim()
                
                    # Only include RDP sessions (not console or services)
                    if ($sessionName -match 'rdp-tcp' -or $state -match 'Active|Disc') {
                        $sessionObjects += [PSCustomObject]@{
                            SessionName = $sessionName
                            Username    = if ($username -and $username -ne '') { $username } else { 'N/A' }
                            ID          = [int]$id
                            State       = $state
                            Type        = $type
                        }
                    }
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
}

