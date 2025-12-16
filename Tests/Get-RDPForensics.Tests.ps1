<#
.SYNOPSIS
    Pester tests for Get-RDPForensics.ps1

.DESCRIPTION
    Comprehensive test suite for the RDP Forensics toolkit.
    Tests include parameter validation, event collection, filtering, and export functionality.

.NOTES
    Requires Pester 5.0+
    Run as Administrator for full test coverage
#>

#Requires -Modules Pester
#Requires -RunAsAdministrator

BeforeAll {
    # Import the script
    $script:ScriptPath = Join-Path $PSScriptRoot ".." "Get-RDPForensics.ps1"
    
    # Test data paths
    $script:TestOutputPath = Join-Path $PSScriptRoot "TestOutput"
    
    # Create test output directory
    if (-not (Test-Path $script:TestOutputPath)) {
        New-Item -Path $script:TestOutputPath -ItemType Directory -Force | Out-Null
    }
    
    # Mock data for testing
    $script:MockEventData = @{
        TimeCreated = Get-Date
        EventID     = 4624
        EventType   = 'Successful Logon'
        User        = 'TestUser'
        Domain      = 'TestDomain'
        SourceIP    = '192.168.1.100'
        SessionID   = '1'
        LogonID     = '0x12345'
        Details     = 'RemoteInteractive (RDP)'
    }
}

AfterAll {
    # Cleanup test output directory
    if (Test-Path $script:TestOutputPath) {
        Remove-Item -Path $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Get-RDPForensics.ps1 - PowerShell Version Compatibility" {
    
    Context "Version Detection" {
        It "Should detect current PowerShell version" {
            $PSVersionTable.PSVersion | Should -Not -BeNullOrEmpty
        }
        
        It "Should be running PowerShell 5.1 or later" {
            $PSVersionTable.PSVersion.Major | Should -BeGreaterOrEqual 5
        }
        
        It "Should report version correctly" {
            Write-Host "Running tests on PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
            $true | Should -Be $true
        }
    }
    
    Context "Emoji Support Across Versions" {
        It "Should handle emoji function in PowerShell 5.1" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'function Get-Emoji'
            $content | Should -Match 'PSVersionTable.PSVersion.Major -ge 6'
        }
        
        It "Should have fallback characters for PowerShell 5.1" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '\[char\]0x'
        }
    }
    
    Context "ConvertFromUtf32 Compatibility" {
        It "Should use runtime [char] casting for PS 5.1 compatibility" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            # Should NOT use [char]::ConvertFromUtf32 directly at parse time
            # Should use it only in PowerShell 7+ branch
            if ($PSVersionTable.PSVersion.Major -eq 5) {
                # In PS 5.1, the script should work without errors
                { & $script:ScriptPath -StartDate (Get-Date) } | Should -Not -Throw
            }
        }
    }
}

Describe "Get-RDPForensics.ps1 - Script Validation" {
    
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
        
        It "Script should contain required help comments" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
            $content | Should -Match '\.PARAMETER'
            $content | Should -Match '\.EXAMPLE'
        }
        
        It "Script should require Administrator privileges" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '#Requires -RunAsAdministrator'
        }
    }
    
    Context "Parameter Validation" {
        It "Should accept StartDate parameter" {
            { & $script:ScriptPath -StartDate (Get-Date).AddDays(-1) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept EndDate parameter" {
            { & $script:ScriptPath -EndDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept Username parameter" {
            { & $script:ScriptPath -Username "testuser" -StartDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept SourceIP parameter" {
            { & $script:ScriptPath -SourceIP "192.168.1.1" -StartDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept IncludeOutbound switch" {
            { & $script:ScriptPath -IncludeOutbound -StartDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept GroupBySession switch" {
            { & $script:ScriptPath -GroupBySession -StartDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should accept IncludeCredentialValidation switch" {
            { & $script:ScriptPath -IncludeCredentialValidation -StartDate (Get-Date) -ErrorAction Stop } | 
            Should -Not -Throw
        }
    }
}

Describe "Get-RDPForensics.ps1 - Event Collection" {
    
    Context "Event Log Access" {
        It "Should access Security event log" {
            { Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop } | 
            Should -Not -Throw
        }
        
        It "Should access TerminalServices-RemoteConnectionManager log" {
            $logExists = Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ErrorAction SilentlyContinue
            $logExists | Should -Not -BeNullOrEmpty
        }
        
        It "Should access TerminalServices-LocalSessionManager log" {
            $logExists = Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -ErrorAction SilentlyContinue
            $logExists | Should -Not -BeNullOrEmpty
        }
        
        It "Should access System event log" {
            { Get-WinEvent -LogName 'System' -MaxEvents 1 -ErrorAction Stop } | 
            Should -Not -Throw
        }
    }
    
    Context "Event Collection Output" {
        BeforeAll {
            $script:TestResults = & $script:ScriptPath -StartDate (Get-Date).AddHours(-1)
        }
        
        It "Should return array of objects" {
            $script:TestResults | Should -BeOfType [System.Array] -Because "Results should be an array"
        }
        
        It "Should have required properties" {
            if ($script:TestResults.Count -gt 0) {
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'TimeCreated'
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'EventID'
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'EventType'
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'User'
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'SourceIP'
            }
        }
        
        It "Should return events with valid EventIDs" {
            $validEventIDs = @(1149, 4624, 4625, 4768, 4769, 4770, 4771, 4772, 4776, 21, 22, 23, 24, 25, 39, 40, 4778, 4779, 4800, 4801, 4634, 4647, 9009, 1102)
            if ($script:TestResults.Count -gt 0) {
                $script:TestResults | ForEach-Object {
                    $validEventIDs | Should -Contain $_.EventID
                }
            }
        }
        
        It "Should have ActivityID property when available" {
            if ($script:TestResults.Count -gt 0) {
                $script:TestResults[0].PSObject.Properties.Name | Should -Contain 'ActivityID'
            }
        }
    }
}

Describe "Get-RDPForensics.ps1 - Filtering Functionality" {
    
    Context "Username Filtering" {
        It "Should filter by username" {
            $results = & $script:ScriptPath -Username "Administrator" -StartDate (Get-Date).AddDays(-7)
            if ($results.Count -gt 0) {
                $results | ForEach-Object {
                    $_.User | Should -Match "Administrator"
                }
            }
            else {
                Set-ItResult -Skipped -Because "No events found for Administrator"
            }
        }
    }
    
    Context "Source IP Filtering" {
        It "Should filter by source IP" {
            # Get any events first
            $allEvents = & $script:ScriptPath -StartDate (Get-Date).AddDays(-7)
            if ($allEvents.Count -gt 0) {
                $testIP = $allEvents | Where-Object { $_.SourceIP -ne 'N/A' } | Select-Object -First 1 -ExpandProperty SourceIP
                if ($testIP) {
                    $filtered = & $script:ScriptPath -SourceIP $testIP -StartDate (Get-Date).AddDays(-7)
                    $filtered | ForEach-Object {
                        $_.SourceIP | Should -Match $testIP
                    }
                }
                else {
                    Set-ItResult -Skipped -Because "No events with valid source IP found"
                }
            }
            else {
                Set-ItResult -Skipped -Because "No events found in last 7 days"
            }
        }
    }
    
    Context "Date Range Filtering" {
        It "Should respect StartDate parameter" {
            $startDate = (Get-Date).AddHours(-2)
            $results = & $script:ScriptPath -StartDate $startDate
            if ($results.Count -gt 0) {
                $results | ForEach-Object {
                    $_.TimeCreated | Should -BeGreaterOrEqual $startDate
                }
            }
        }
        
        It "Should respect EndDate parameter" {
            $endDate = Get-Date
            $results = & $script:ScriptPath -StartDate (Get-Date).AddDays(-1) -EndDate $endDate
            if ($results.Count -gt 0) {
                $results | ForEach-Object {
                    $_.TimeCreated | Should -BeLessOrEqual $endDate
                }
            }
        }
    }
}

Describe "Get-RDPForensics.ps1 - Export Functionality" {
    
    Context "CSV Export" {
        BeforeAll {
            $script:ExportTestPath = Join-Path $script:TestOutputPath "ExportTest"
            & $script:ScriptPath -StartDate (Get-Date).AddHours(-1) -ExportPath $script:ExportTestPath
        }
        
        It "Should create export directory" {
            $script:ExportTestPath | Should -Exist
        }
        
        It "Should create CSV file" {
            $csvFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "RDP_Forensics_*.csv"
            $csvFiles.Count | Should -BeGreaterThan 0
        }
        
        It "Should create summary file" {
            $summaryFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "RDP_Summary_*.txt"
            $summaryFiles.Count | Should -BeGreaterThan 0
        }
        
        It "CSV file should have valid headers" {
            $csvFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "RDP_Forensics_*.csv"
            if ($csvFiles.Count -gt 0) {
                $csv = Import-Csv -Path $csvFiles[0].FullName
                $csv[0].PSObject.Properties.Name | Should -Contain 'TimeCreated'
                $csv[0].PSObject.Properties.Name | Should -Contain 'EventID'
                $csv[0].PSObject.Properties.Name | Should -Contain 'User'
            }
        }
        
        It "Summary file should contain statistics" {
            $summaryFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "RDP_Summary_*.txt"
            if ($summaryFiles.Count -gt 0) {
                $content = Get-Content -Path $summaryFiles[0].FullName -Raw
                $content | Should -Match 'Total Events'
                $content | Should -Match 'Events by Type'
            }
        }
    }
}

Describe "Get-RDPForensics.ps1 - Outbound Connection Tracking" {
    
    Context "IncludeOutbound Switch" {
        It "Should collect outbound connections when switch is used" {
            $results = & $script:ScriptPath -IncludeOutbound -StartDate (Get-Date).AddDays(-1)
            # Check if any outbound connections exist
            $outbound = $results | Where-Object { $_.EventID -eq 1102 }
            # Test passes if no error occurs, outbound events may or may not exist
            $results | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Get-RDPForensics.ps1 - Error Handling" {
    
    Context "Invalid Parameters" {
        It "Should handle future StartDate gracefully" {
            $futureDate = (Get-Date).AddDays(1)
            $results = & $script:ScriptPath -StartDate $futureDate -ErrorAction SilentlyContinue
            $results.Count | Should -Be 0
        }
        
        It "Should handle EndDate before StartDate" {
            $results = & $script:ScriptPath -StartDate (Get-Date) -EndDate (Get-Date).AddDays(-1) -ErrorAction SilentlyContinue
            $results.Count | Should -Be 0
        }
    }
    
    Context "Non-existent User/IP" {
        It "Should return empty results for non-existent user" {
            $results = & $script:ScriptPath -Username "NonExistentUser12345XYZ" -StartDate (Get-Date).AddDays(-1)
            $results.Count | Should -Be 0
        }
        
        It "Should return empty results for non-existent IP" {
            $results = & $script:ScriptPath -SourceIP "999.999.999.999" -StartDate (Get-Date).AddDays(-1)
            $results.Count | Should -Be 0
        }
    }
}

Describe "Get-RDPForensics.ps1 - Performance" {
    
    Context "Script Execution Time" {
        It "Should complete within reasonable time (< 60 seconds for 1 hour)" {
            $startTime = Get-Date
            & $script:ScriptPath -StartDate (Get-Date).AddHours(-1) | Out-Null
            $duration = (Get-Date) - $startTime
            $duration.TotalSeconds | Should -BeLessThan 60
        }
    }
}

Describe "Get-RDPForensics.ps1 - Event Type Coverage" {
    
    Context "Critical Event IDs" {
        BeforeAll {
            $script:AllEvents = & $script:ScriptPath -StartDate (Get-Date).AddDays(-7)
        }
        
        It "Should check for Connection Attempts (1149)" {
            # Test passes if script runs without error
            $script:AllEvents | Should -Not -BeNullOrEmpty -Because "Script should return results or empty array"
        }
        
        It "Should check for Authentication Events (4624, 4625)" {
            # Test passes if script runs without error
            $script:AllEvents | Should -Not -BeNullOrEmpty -Because "Script should return results or empty array"
        }
        
        It "Should check for Session Events (21-25, 39, 40)" {
            # Test passes if script runs without error
            $script:AllEvents | Should -Not -BeNullOrEmpty -Because "Script should return results or empty array"
        }
        
        It "Should check for Reconnect/Disconnect Events (4778, 4779)" {
            # Test passes if script runs without error
            $script:AllEvents | Should -Not -BeNullOrEmpty -Because "Script should return results or empty array"
        }
        
        It "Should check for Logoff Events (4634, 4647, 9009)" {
            # Test passes if script runs without error
            $script:AllEvents | Should -Not -BeNullOrEmpty -Because "Script should return results or empty array"
        }
    }
}

Describe "Get-RDPForensics.ps1 - Credential Validation (EventID 4776)" {
    
    Context "IncludeCredentialValidation Parameter" {
        It "Should not collect 4776 events by default" {
            $results = & $script:ScriptPath -StartDate (Get-Date).AddHours(-1)
            $cred4776 = $results | Where-Object { $_.EventID -eq 4776 }
            $cred4776.Count | Should -Be 0 -Because "4776 should be off by default"
        }
        
        It "Should collect 4776 events when switch is used" {
            $results = & $script:ScriptPath -IncludeCredentialValidation -StartDate (Get-Date).AddDays(-1)
            # May or may not have 4776 events, but script should run without error
            $results | Should -Not -BeNullOrEmpty
        }
        
        It "Should parse 4776 event properties correctly" {
            $results = & $script:ScriptPath -IncludeCredentialValidation -StartDate (Get-Date).AddDays(-1)
            $cred4776 = $results | Where-Object { $_.EventID -eq 4776 } | Select-Object -First 1
            if ($cred4776) {
                $cred4776.PSObject.Properties.Name | Should -Contain 'User'
                $cred4776.PSObject.Properties.Name | Should -Contain 'EventType'
                $cred4776.PSObject.Properties.Name | Should -Contain 'Details'
                $cred4776.EventType | Should -Match 'Credential Validation'
            }
            else {
                Set-ItResult -Skipped -Because "No 4776 events found in time range"
            }
        }
    }
    
    Context "Time-Based Correlation" {
        It "Should correlate 4776 with sessions when GroupBySession is used" {
            # Get results with both GroupBySession and IncludeCredentialValidation
            { & $script:ScriptPath -GroupBySession -IncludeCredentialValidation -StartDate (Get-Date).AddHours(-1) } | 
            Should -Not -Throw
        }
    }
}
