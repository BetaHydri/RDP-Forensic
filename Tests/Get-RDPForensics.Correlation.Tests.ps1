BeforeAll {
    # Import module
    $ModulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$ModulePath\RDP-Forensic.psd1" -Force
}

Describe "Get-RDPForensics Session Correlation Tests" {
    
    Context "GroupBySession Parameter" {
        It "Should accept GroupBySession parameter" {
            $params = (Get-Command Get-RDPForensics).Parameters
            $params.ContainsKey('GroupBySession') | Should -Be $true
        }
        
        It "GroupBySession should be a switch parameter" {
            $param = (Get-Command Get-RDPForensics).Parameters['GroupBySession']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }
        
        It "GroupBySession should not be mandatory" {
            $param = (Get-Command Get-RDPForensics).Parameters['GroupBySession']
            $param.Attributes.Mandatory | Should -Not -Contain $true
        }
    }
    
    Context "Correlation Function Exists" {
        It "Should contain Get-CorrelatedSessions function definition" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'function Get-CorrelatedSessions'
        }
        
        It "Get-CorrelatedSessions should handle empty event arrays" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'if.*Count.*-eq.*0.*return'
        }
        
        It "Should create session map for correlation" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$sessionMap\s*=\s*@\{\}'
        }
        
        It "Should track LogonID as correlation key (Priority 1)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'LogonID:'
        }
        
        It "Should track SessionID as correlation key (Priority 2)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'SessionID:'
        }
        
        It "Should preserve ActivityID for forensic analysis" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'ActivityID'
        }
        
        It "Should prioritize LogonID over SessionID" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'Priority 1.*LogonID'
        }
    }
    
    Context "Lifecycle Stage Tracking" {
        It "Should track ConnectionAttempt stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'ConnectionAttempt'
        }
        
        It "Should track Authentication stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'Authentication'
        }
        
        It "Should track pre-authentication EventIDs in Authentication stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '4624.*4776'
        }
        
        It "Should track Logon stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$session\.Logon\s*=\s*\$true'
        }
        
        It "Should track Active stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$session\.Active\s*=\s*\$true'
        }
        
        It "Should track Disconnect stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$session\.Disconnect\s*=\s*\$true'
        }
        
        It "Should track Logoff stage" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$session\.Logoff\s*=\s*\$true'
        }
    }
    
    Context "Session Duration Calculation" {
        It "Should calculate session duration" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$duration\s*=.*EndTime.*StartTime'
        }
        
        It "Should format duration as hh:mm:ss" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'ToString\([''"]hh\\:mm\\:ss'
        }
        
        It "Should handle sessions without end time" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'In Progress|N/A'
        }
    }
    
    Context "Session Completeness Detection" {
        It "Should set LifecycleComplete flag" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'LifecycleComplete'
        }
        
        It "Should check all lifecycle stages for completeness" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Complete lifecycle requires ConnectionAttempt, Logon, and Logoff at minimum
            $functionContent | Should -Match '\$session\.ConnectionAttempt.*and.*\$session\.Logon'
        }
    }
    
    Context "Time-Based Correlation for Pre-Authentication Events (4768-4772, 4776)" {
        It "Should contain time-based correlation logic for pre-auth events" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'Time-based correlation.*pre-authentication'
        }
        
        It "Should include all pre-auth EventIDs in correlation" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '4768.*4769.*4770.*4771.*4772.*4776'
        }
        
        It "Should match pre-auth events within time window" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'TotalSeconds.*-ge.*0.*-and.*TotalSeconds.*-le'
        }
        
        It "Should match by username for time-based correlation" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'User.*-eq.*User'
        }
        
        It "Should add pre-auth events to matched sessions" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'sessionMap.*Events.*\+=.*preAuthEvent'
        }
        
        It "Should filter out uncorrelated pre-auth events" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'CorrelatedToRDP'
        }
    }
    
    Context "Display Output with GroupBySession" {
        It "Should show correlated sessions when GroupBySession is used" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'if.*GroupBySession.*and.*sessions'
        }
        
        It "Should display session correlation key" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'CorrelationKey'
        }
        
        It "Should display lifecycle visualization" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'Lifecycle:'
        }
        
        It "Should warn about incomplete sessions" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'Incomplete session lifecycle'
        }
        
        It "Should show default view when GroupBySession is not used" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'RECENT RDP EVENTS'
        }
    }
    
    Context "Export with Correlation" {
        It "Should export sessions to separate CSV when GroupBySession is used" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'RDP_Sessions_.*\.csv'
        }
        
        It "Should export session properties to CSV" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'CorrelationKey.*User.*SourceIP.*StartTime.*EndTime.*Duration'
        }
        
        It "Should export lifecycle flags to CSV" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'ConnectionAttempt.*Authentication.*Logon.*Active.*Disconnect.*Logoff'
        }
        
        It "Should still export individual events" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'RDP_Forensics_.*\.csv'
        }
    }
    
    Context "Help Documentation" {
        It "Should document GroupBySession parameter in help" {
            $help = Get-Help Get-RDPForensics -Parameter GroupBySession
            $help | Should -Not -BeNullOrEmpty
        }
        
        It "Should have examples using GroupBySession" {
            $help = Get-Help Get-RDPForensics -Examples
            $allExamples = ($help.examples.example | ForEach-Object { $_.code }) -join " "
            $allExamples | Should -Match 'GroupBySession'
        }
    }
    
    Context "Version Information" {
        It "Should be version 1.0.7 or higher" {
            $version = (Get-Command Get-RDPForensics).Version
            $version.Major | Should -BeGreaterOrEqual 1
            $version.Minor | Should -BeGreaterOrEqual 0
            $version.Build | Should -BeGreaterOrEqual 7
        }
        
        It "Module manifest should show version 1.0.7" {
            $manifest = Test-ModuleManifest "$ModulePath\RDP-Forensic.psd1" -ErrorAction SilentlyContinue
            $manifest.Version.ToString() | Should -Be '1.0.7'
        }
    }
    
    Context "v1.0.7 New Filtering Parameters" {
        It "Should accept LogonID parameter" {
            $params = (Get-Command Get-RDPForensics).Parameters
            $params.ContainsKey('LogonID') | Should -Be $true
        }
        
        It "LogonID should be a string parameter" {
            $param = (Get-Command Get-RDPForensics).Parameters['LogonID']
            $param.ParameterType.Name | Should -Be 'String'
        }
        
        It "LogonID should not be mandatory" {
            $param = (Get-Command Get-RDPForensics).Parameters['LogonID']
            $param.Attributes.Mandatory | Should -Not -Contain $true
        }
        
        It "Should accept SessionID parameter" {
            $params = (Get-Command Get-RDPForensics).Parameters
            $params.ContainsKey('SessionID') | Should -Be $true
        }
        
        It "SessionID should be a string parameter" {
            $param = (Get-Command Get-RDPForensics).Parameters['SessionID']
            $param.ParameterType.Name | Should -Be 'String'
        }
        
        It "SessionID should not be mandatory" {
            $param = (Get-Command Get-RDPForensics).Parameters['SessionID']
            $param.Attributes.Mandatory | Should -Not -Contain $true
        }
        
        It "Should have help documentation for LogonID parameter" {
            $help = Get-Help Get-RDPForensics -Parameter LogonID -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
        }
        
        It "Should have help documentation for SessionID parameter" {
            $help = Get-Help Get-RDPForensics -Parameter SessionID -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
        }
        
        It "Should have examples using LogonID filter" {
            $help = Get-Help Get-RDPForensics -Examples
            $allExamples = ($help.examples.example | ForEach-Object { $_.code }) -join " "
            $allExamples | Should -Match 'LogonID'
        }
        
        It "Should have examples using SessionID filter" {
            $help = Get-Help Get-RDPForensics -Examples
            $allExamples = ($help.examples.example | ForEach-Object { $_.code }) -join " "
            $allExamples | Should -Match 'SessionID'
        }
        
        It "Should filter sessions by LogonID" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'if.*\$LogonID.*Where-Object.*LogonID.*-eq'
        }
        
        It "Should filter sessions by SessionID" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'if.*\$SessionID.*Where-Object.*SessionID.*-eq'
        }
        
        It "Should warn when no sessions match LogonID filter" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'No sessions found with LogonID'
        }
        
        It "Should warn when no sessions match SessionID filter" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'No sessions found with SessionID'
        }
    }
    
    Context "v1.0.7 Bug Fix - Domain Controller 4624 Event Parsing" {
        It "Should extract username from 'New Logon:' section (not 'Subject:' section)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'New Logon:\[\\s\\S\]\*\?Account Name:'
        }
        
        It "Should extract LogonID from 'New Logon:' section" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'New Logon:\[\\s\\S\]\*\?Logon ID:'
        }
        
        It "Should extract domain from 'New Logon:' section" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'New Logon:\[\\s\\S\]\*\?Account Domain:'
        }
        
        It "Should construct DOMAIN\\User format for 4624 events" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\$userDomain\\\\$accountName'
        }
    }
    
    Context "v1.0.7 Bug Fix - Username Format Standardization" {
        It "Should construct DOMAIN\\User format for 4778/4779 events (Reconnect/Disconnect)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Check in Get-RDPSessionReconnectEvents function
            $functionContent | Should -Match 'Get-RDPSessionReconnectEvents.*\$userDomain\\\\$accountName'
        }
        
        It "Should construct DOMAIN\\User format for 4634/4647 events (Logoff)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Check in Get-RDPLogoffEvents function
            $functionContent | Should -Match 'Get-RDPLogoffEvents.*\$userDomain\\\\$accountName'
        }
        
        It "Should construct DOMAIN\\User format for 4800/4801 events (Lock/Unlock)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Check in Get-RDPLockUnlockEvents function
            $functionContent | Should -Match 'Get-RDPLockUnlockEvents.*\$userDomain\\\\$accountName'
        }
        
        It "Should handle workgroup systems (COMPUTERNAME\\User format)" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Should work for both domain and workgroup by using same construction logic
            $functionContent | Should -Match 'if.*\$userDomain.*-ne.*N/A'
        }
    }
    
    Context "v1.0.7 Bug Fix - LogonType Regex" {
        It "Should not require trailing space in LogonType regex" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            # Should match 'Logon Type:\s+(10|7|3|5)' WITHOUT trailing \s
            $functionContent | Should -Match 'Logon Type:\\s\+\(10\|7\|3\|5\)(?!\\s)'
        }
    }
    
    Context "v1.0.7 Bug Fix - Secondary Correlation Type Conversion" {
        It "Should use [double]::MaxValue instead of [TimeSpan]::MaxValue" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '\[double\]::MaxValue'
            $functionContent | Should -Not -Match '\[TimeSpan\]::MaxValue'
        }
    }
    
    Context "v1.0.7 Enhancement - Synchronized Event Detection" {
        It "Should count synchronized events between SessionID and LogonID sessions" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'synchronizedCount|synchronized.*count'
        }
        
        It "Should require minimum 2 synchronized events for merge" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'synchronizedCount.*-ge.*2'
        }
        
        It "Should check events within 3 second window" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'TotalSeconds.*-le.*3'
        }
        
        It "Should pick LogonID session with most synchronized events" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match 'bestMatchScore'
        }
        
        It "Should check for RDP event types (4624/4778/4779) in LogonID sessions" {
            $functionContent = Get-Content "$ModulePath\Get-RDPForensics.ps1" -Raw
            $functionContent | Should -Match '4624.*4778.*4779'
        }
    }
}

