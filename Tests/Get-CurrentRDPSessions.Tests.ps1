<#
.SYNOPSIS
    Pester tests for Get-CurrentRDPSessions.ps1

.DESCRIPTION
    Test suite for the current RDP sessions monitoring script.

.NOTES
    Requires Pester 5.0+
    Run as Administrator
#>

#Requires -Modules Pester
#Requires -RunAsAdministrator

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot ".." "Get-CurrentRDPSessions.ps1"
}

Describe "Get-CurrentRDPSessions.ps1 - Script Validation" {
    
    Context "Script File Existence and Syntax" {
        It "Script file should exist" {
            $script:ScriptPath | Should -Exist
        }
        
        It "Script should have valid PowerShell syntax" {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $script:ScriptPath -Raw), 
                [ref]$errors
            )
            $errors.Count | Should -Be 0
        }
        
        It "Script should contain help documentation" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
        }
    }
    
    Context "Parameter Validation" {
        It "Should accept SessionID parameter" {
            { & $script:ScriptPath -SessionID 1 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should accept ShowProcesses switch" {
            { & $script:ScriptPath -ShowProcesses -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe "Get-CurrentRDPSessions.ps1 - Functionality" {
    
    Context "Session Query" {
        It "Should execute qwinsta command successfully" {
            { qwinsta 2>$null } | Should -Not -Throw
        }
        
        It "Should query sessions without error" {
            { & $script:ScriptPath -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "Process Query" {
        It "Should query processes with ShowProcesses switch" {
            { & $script:ScriptPath -ShowProcesses -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe "Get-CurrentRDPSessions.ps1 - Error Handling" {
    
    Context "Invalid Session ID" {
        It "Should handle non-existent session ID gracefully" {
            { & $script:ScriptPath -SessionID 99999 -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }
}
