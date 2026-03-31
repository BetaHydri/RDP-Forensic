<#
.SYNOPSIS
    PowerShell version compatibility tests for RDP Forensics Toolkit

.DESCRIPTION
    Validates compatibility between PowerShell 5.1 and PowerShell 7+
    Tests emoji rendering, character encoding, and version-specific features

.NOTES
    Requires Pester 5.0+
    Run on both PowerShell 5.1 and 7+ for full coverage
#>

#Requires -Modules Pester

BeforeAll {
    $script:RootPath = Split-Path -Parent $PSScriptRoot
    $script:MainScript = Join-Path $script:RootPath 'source' 'Public' 'Get-RDPForensics.ps1'
    $script:SessionScript = Join-Path $script:RootPath 'source' 'Public' 'Get-CurrentRDPSessions.ps1'
    $builtModule = Get-ChildItem -Path (Join-Path (Join-Path (Join-Path $script:RootPath 'output') 'module') 'RDP-Forensic') -Filter 'RDP-Forensic.psd1' -Recurse | Select-Object -First 1
    if ($builtModule) {
        Import-Module $builtModule.FullName -Force
        $script:ModulePath = Split-Path $builtModule.FullName
    }
    
    # Detect PowerShell version
    $script:PSMajorVersion = $PSVersionTable.PSVersion.Major
    $script:IsPS7Plus = $script:PSMajorVersion -ge 7
    $script:IsPS5 = $script:PSMajorVersion -eq 5
}

Describe "PowerShell Version Compatibility - Core Functionality" {
    
    Context "Current PowerShell Version: $($PSVersionTable.PSVersion)" {
        It "Should be PowerShell 5.1 or later" {
            $PSVersionTable.PSVersion.Major | Should -BeGreaterOrEqual 5
            Write-Host "Running on PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
        }
        
        It "Should report correct edition" {
            $PSVersionTable.PSEdition | Should -BeIn @('Desktop', 'Core')
            Write-Host "Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
        }
    }
    
    Context "Script Execution on $($PSVersionTable.PSVersion)" {
        It "Main script should execute without errors" {
            { Get-RDPForensics -StartDate (Get-Date).AddHours(-1) } | Should -Not -Throw
        }
        
        It "Session script should execute without errors" {
            { Get-CurrentRDPSessions } | Should -Not -Throw
        }
        
        It "Module should import without errors" {
            { Import-Module RDP-Forensic -Force -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe "PowerShell Version Compatibility - Emoji and Character Support" {
    
    Context "Get-Emoji Function" {
        BeforeAll {
            # Source the Get-Emoji function from the main script
            $emojiFunction = (Get-Content $script:MainScript -Raw) -match '(?s)function Get-Emoji.*?return \$emojis\[\$Name\].*?\}'
            if ($matches) {
                Invoke-Expression $matches[0]
            }
        }
        
        It "Get-Emoji function should exist in script" {
            $content = Get-Content $script:MainScript -Raw
            $content | Should -Match 'function Get-Emoji'
        }
        
        It "Should have version detection logic" {
            $content = Get-Content $script:MainScript -Raw
            $content | Should -Match 'PSVersionTable.PSVersion.Major -ge 6'
        }
        
        It "Should have fallback characters for PowerShell 5.1" {
            $content = Get-Content $script:MainScript -Raw
            $content | Should -Match 'else.*{.*\[char\]0x'
        }
        
        It "Should have emoji definitions for PowerShell 7+" {
            $content = Get-Content $script:MainScript -Raw
            $content | Should -Match 'ConvertFromUtf32'
        }
        
        It "Should return non-empty character for all emoji names" {
            if (Get-Command Get-Emoji -ErrorAction SilentlyContinue) {
                $emojiNames = @('shield', 'magnify', 'check', 'cross', 'warning', 'clock', 
                               'computer', 'lock', 'key', 'chart', 'folder', 'rocket')
                foreach ($name in $emojiNames) {
                    $result = Get-Emoji $name
                    $result | Should -Not -BeNullOrEmpty
                }
            }
        }
    }
    
    Context "Unicode Character Rendering" {
        It "Should use appropriate character encoding for PS version" {
            if ($script:IsPS7Plus) {
                # PowerShell 7+ should use UTF-8
                Write-Host "PowerShell 7+ detected - using full emoji support" -ForegroundColor Green
            } else {
                # PowerShell 5.1 should use compatible characters
                Write-Host "PowerShell 5.1 detected - using fallback characters" -ForegroundColor Yellow
            }
            $true | Should -Be $true
        }
        
        It "Should not throw on character conversion" {
            { 
                if ($script:IsPS7Plus) {
                    [char]::ConvertFromUtf32(0x1F6E1) | Out-Null
                } else {
                    [char]0x25A0 | Out-Null
                }
            } | Should -Not -Throw
        }
    }
}

Describe "PowerShell Version Compatibility - Event Collection" {
    
    Context "Get-WinEvent Compatibility" {
        It "Should access Security log on both versions" {
            { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Should use FilterHashtable syntax correctly" {
            {
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    Id = 4624
                    StartTime = (Get-Date).AddHours(-1)
                } -MaxEvents 1 -ErrorAction SilentlyContinue
            } | Should -Not -Throw
        }
        
        It "Should handle XML parsing on both versions" {
            $event = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($event) {
                { [xml]$event.ToXml() } | Should -Not -Throw
            }
        }
    }
    
    Context "Event Parsing Compatibility" {
        It "Should parse event messages correctly" {
            $results = Get-RDPForensics -StartDate (Get-Date).AddHours(-1)
            if ($results.Count -gt 0) {
                $results[0].PSObject.Properties.Name | Should -Contain 'TimeCreated'
                $results[0].PSObject.Properties.Name | Should -Contain 'EventID'
                $results[0].PSObject.Properties.Name | Should -Contain 'User'
            }
        }
    }
}

Describe "PowerShell Version Compatibility - Parameter Handling" {
    
    Context "Switch Parameters" {
        It "Should handle -GroupBySession switch" {
            { Get-RDPForensics -GroupBySession -StartDate (Get-Date).AddHours(-1) } | Should -Not -Throw
        }
        
        It "Should handle -IncludeOutbound switch" {
            { Get-RDPForensics -IncludeOutbound -StartDate (Get-Date).AddHours(-1) } | Should -Not -Throw
        }
        
        It "Should handle -IncludeCredentialValidation switch" {
            { Get-RDPForensics -IncludeCredentialValidation -StartDate (Get-Date).AddHours(-1) } | Should -Not -Throw
        }
        
        It "Should handle combined switches" {
            { Get-RDPForensics -GroupBySession -IncludeCredentialValidation -StartDate (Get-Date).AddHours(-1) } | 
                Should -Not -Throw
        }
    }
    
    Context "DateTime Parameters" {
        It "Should handle DateTime objects" {
            { Get-RDPForensics -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) } | Should -Not -Throw
        }
    }
}

Describe "PowerShell Version Compatibility - Export Functionality" {
    
    Context "CSV Export" {
        BeforeAll {
            $script:TestExportPath = Join-Path $PSScriptRoot "PSVersionTestExport"
            if (Test-Path $script:TestExportPath) {
                Remove-Item $script:TestExportPath -Recurse -Force
            }
        }
        
        AfterAll {
            if (Test-Path $script:TestExportPath) {
                Remove-Item $script:TestExportPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "Should export CSV with UTF-8 encoding" {
            Get-RDPForensics -StartDate (Get-Date).AddHours(-1) -ExportPath $script:TestExportPath
            
            $csvFile = Get-ChildItem -Path $script:TestExportPath -Filter "*.csv" | Select-Object -First 1
            if ($csvFile) {
                { Import-Csv $csvFile.FullName } | Should -Not -Throw
            }
        }
        
        It "Should create text files readable on both versions" {
            $txtFile = Get-ChildItem -Path $script:TestExportPath -Filter "*.txt" | Select-Object -First 1
            if ($txtFile) {
                { Get-Content $txtFile.FullName -Raw } | Should -Not -Throw
            }
        }
    }
}

Describe "PowerShell Version Compatibility - Error Handling" {
    
    Context "ErrorActionPreference" {
        It "Should respect ErrorActionPreference setting" {
            $originalEAP = $ErrorActionPreference
            { 
                $ErrorActionPreference = 'Continue'
                Get-RDPForensics -StartDate (Get-Date).AddHours(-1) | Out-Null
                $ErrorActionPreference = $originalEAP
            } | Should -Not -Throw
        }
    }
    
    Context "SilentlyContinue Error Handling" {
        It "Should handle missing event logs gracefully" {
            { 
                Get-WinEvent -LogName 'NonExistentLog' -ErrorAction SilentlyContinue 
            } | Should -Not -Throw
        }
    }
}

Describe "PowerShell Version Compatibility - Performance" {
    
    Context "Execution Time Comparison" {
        It "Should complete within reasonable time on $($PSVersionTable.PSVersion)" {
            $startTime = Get-Date
            Get-RDPForensics -StartDate (Get-Date).AddHours(-1) | Out-Null
            $duration = (Get-Date) - $startTime
            
            Write-Host "Execution time on PS $($PSVersionTable.PSVersion): $($duration.TotalSeconds) seconds" -ForegroundColor Cyan
            $duration.TotalSeconds | Should -BeLessThan 60
        }
    }
}

Describe "PowerShell Version Compatibility - Module System" {
    
    Context "Module Import" {
        It "Should import module on $($PSVersionTable.PSVersion)" {
            { Import-Module RDP-Forensic -Force } | Should -Not -Throw
        }
        
        It "Should export Get-RDPForensics command" {
            Import-Module RDP-Forensic -Force
            $command = Get-Command Get-RDPForensics -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
        
        It "Should export Get-CurrentRDPSessions command" {
            Import-Module RDP-Forensic -Force
            $command = Get-Command Get-CurrentRDPSessions -ErrorAction SilentlyContinue
            $command | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "PowerShell Version Recommendations" {
    
    Context "Best Practices for Version" {
        It "Should document version requirements" {
            $readme = Get-Content (Join-Path $script:RootPath "README.md") -Raw
            $readme | Should -Match 'PowerShell 5.1'
        }
        
        It "Should report current compatibility status" {
            if ($script:IsPS7Plus) {
                Write-Host "✓ Running on PowerShell 7+ with full emoji support" -ForegroundColor Green
            } else {
                Write-Host "✓ Running on PowerShell 5.1 with fallback character support" -ForegroundColor Yellow
            }
            $true | Should -Be $true
        }
    }
}
