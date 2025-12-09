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

    Write-Host "`n=== Current RDP Sessions ===" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
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
                Write-Host "Active RDP Sessions:" -ForegroundColor Yellow
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
                        Write-Host "`nProcesses for Session $($session.ID) - User: $($session.Username)" -ForegroundColor Yellow
                    
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
                Write-Host "`nRecent Logon Information:" -ForegroundColor Yellow
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
                    
                        Write-Host "  $($session.Username) - Last logon: $($recentLogon.TimeCreated) from $sourceIP" -ForegroundColor Gray
                    }
                }
            }
            else {
                Write-Host "No active RDP sessions found." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Unable to query sessions." -ForegroundColor Red
        }
    }
    catch {
        Write-Error "Error getting session information: $_"
    }

    Write-Host ""
}

