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
    # Dot source the function
    . $script:ScriptPath
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
            { Get-CurrentRDPSessions -SessionID 1 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should accept ShowProcesses switch" {
            { Get-CurrentRDPSessions -ShowProcesses -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should accept Watch switch" {
            # Note: Can't actually test Watch mode as it runs indefinitely
            # Testing parameter validation only
            $params = (Get-Command Get-CurrentRDPSessions).Parameters
            $params.ContainsKey('Watch') | Should -Be $true
            $params['Watch'].SwitchParameter | Should -Be $true
        }

        It "Should accept RefreshInterval parameter" {
            $params = (Get-Command Get-CurrentRDPSessions).Parameters
            $params.ContainsKey('RefreshInterval') | Should -Be $true
            $params['RefreshInterval'].ParameterType.Name | Should -Be 'Int32'
        }

        It "Should validate RefreshInterval range (1-300)" {
            $params = (Get-Command Get-CurrentRDPSessions).Parameters
            $validation = $params['RefreshInterval'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $validation | Should -Not -BeNullOrEmpty
            $validation.MinRange | Should -Be 1
            $validation.MaxRange | Should -Be 300
        }

        It "Should have RefreshInterval default value of 5" {
            $params = (Get-Command Get-CurrentRDPSessions).Parameters
            $defaultValue = $params['RefreshInterval'].Attributes | Where-Object { $_.GetType().Name -eq 'PSDefaultValueAttribute' }
            # Alternative: check the actual default by examining the parameter metadata
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $paramBlock = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true) | 
            Where-Object { $_.Name.VariablePath.UserPath -eq 'RefreshInterval' }
            $paramBlock.DefaultValue.Value | Should -Be 5
        }

        It "Should accept LogPath parameter" {
            $params = (Get-Command Get-CurrentRDPSessions).Parameters
            $params.ContainsKey('LogPath') | Should -Be $true
            $params['LogPath'].ParameterType.Name | Should -Be 'String'
        }
    }
}

Describe "Get-CurrentRDPSessions.ps1 - Functionality" {
    
    Context "Session Query" {
        It "Should execute qwinsta command successfully" {
            { qwinsta 2>$null } | Should -Not -Throw
        }
        
        It "Should query sessions without error" {
            { Get-CurrentRDPSessions -ErrorAction Stop } | Should -Not -Throw
        }
    }
    
    Context "Process Query" {
        It "Should query processes with ShowProcesses switch" {
            { Get-CurrentRDPSessions -ShowProcesses -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe "Get-CurrentRDPSessions.ps1 - Logging Feature" {
    
    BeforeAll {
        $script:TestLogPath = Join-Path $PSScriptRoot "TestLogs"
    }

    AfterEach {
        if (Test-Path $script:TestLogPath) {
            Remove-Item -Path $script:TestLogPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context "Log File Creation" {
        It "Should create log directory if it doesn't exist" {
            Get-CurrentRDPSessions -LogPath $script:TestLogPath -ErrorAction Stop
            Test-Path $script:TestLogPath | Should -Be $true
        }

        It "Should create timestamped CSV log file" {
            Get-CurrentRDPSessions -LogPath $script:TestLogPath -ErrorAction Stop
            $logFiles = Get-ChildItem -Path $script:TestLogPath -Filter "RDP_SessionMonitor_*.csv"
            $logFiles.Count | Should -BeGreaterThan 0
        }

        It "Should create CSV with correct header" {
            Get-CurrentRDPSessions -LogPath $script:TestLogPath -ErrorAction Stop
            $logFile = Get-ChildItem -Path $script:TestLogPath -Filter "RDP_SessionMonitor_*.csv" | Select-Object -First 1
            $header = Get-Content $logFile.FullName -First 1
            $header | Should -Match 'Timestamp,EventType,SessionName,Username,SessionID,State,SourceIP,Details'
        }
    }

    Context "Logging Functionality" {
        It "Should accept LogPath parameter without errors" {
            { Get-CurrentRDPSessions -LogPath $script:TestLogPath -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should work with LogPath and ShowProcesses together" {
            { Get-CurrentRDPSessions -LogPath $script:TestLogPath -ShowProcesses -ErrorAction Stop } | Should -Not -Throw
        }

        It "Should create valid CSV content" {
            Get-CurrentRDPSessions -LogPath $script:TestLogPath -ErrorAction Stop
            $logFile = Get-ChildItem -Path $script:TestLogPath -Filter "RDP_SessionMonitor_*.csv" | Select-Object -First 1
            $content = Get-Content $logFile.FullName -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match 'Timestamp.*EventType.*SessionName'
        }
    }
}

Describe "Get-CurrentRDPSessions.ps1 - Error Handling" {
    
    Context "Invalid Session ID" {
        It "Should handle non-existent session ID gracefully" {
            { Get-CurrentRDPSessions -SessionID 99999 -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }
}
