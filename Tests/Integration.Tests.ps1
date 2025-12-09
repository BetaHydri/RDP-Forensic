<#
.SYNOPSIS
    Integration tests for RDP Forensics Toolkit

.DESCRIPTION
    End-to-end integration tests that validate complete workflows and scenarios.

.NOTES
    Requires Pester 5.0+
    Run as Administrator
#>

#Requires -Modules Pester
#Requires -RunAsAdministrator

BeforeAll {
    $script:RootPath = Split-Path -Parent $PSScriptRoot
    $script:MainScript = Join-Path $script:RootPath "Get-RDPForensics.ps1"
    $script:SessionScript = Join-Path $script:RootPath "Get-CurrentRDPSessions.ps1"
    $script:TestOutputPath = Join-Path $PSScriptRoot "IntegrationTestOutput"
    
    if (-not (Test-Path $script:TestOutputPath)) {
        New-Item -Path $script:TestOutputPath -ItemType Directory -Force | Out-Null
    }
}

AfterAll {
    if (Test-Path $script:TestOutputPath) {
        Remove-Item -Path $script:TestOutputPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Integration - Complete Forensic Workflow" {
    
    Context "Daily Security Review Scenario" {
        It "Should collect today's RDP activity" {
            $results = & $script:MainScript
            $results | Should -Not -BeNullOrEmpty -Because "Should return array (even if empty)"
        }
    }
    
    Context "Incident Investigation Scenario" {
        BeforeAll {
            $script:IncidentDate = (Get-Date).AddDays(-1)
            $script:InvestigationPath = Join-Path $script:TestOutputPath "Investigation"
        }
        
        It "Should collect events around incident time" {
            $results = & $script:MainScript -StartDate $script:IncidentDate -ExportPath $script:InvestigationPath
            $script:InvestigationPath | Should -Exist
        }
        
        It "Should generate investigation reports" {
            $csvFiles = Get-ChildItem -Path $script:InvestigationPath -Filter "*.csv" -ErrorAction SilentlyContinue
            $txtFiles = Get-ChildItem -Path $script:InvestigationPath -Filter "*.txt" -ErrorAction SilentlyContinue
            ($csvFiles.Count + $txtFiles.Count) | Should -BeGreaterThan 0
        }
    }
    
    Context "Compliance Audit Scenario" {
        BeforeAll {
            $script:CompliancePath = Join-Path $script:TestOutputPath "Compliance"
        }
        
        It "Should generate weekly compliance report" {
            $startDate = (Get-Date).AddDays(-7)
            & $script:MainScript -StartDate $startDate -ExportPath $script:CompliancePath
            $script:CompliancePath | Should -Exist
        }
        
        It "Should include summary statistics" {
            $summaryFiles = Get-ChildItem -Path $script:CompliancePath -Filter "RDP_Summary_*.txt" -ErrorAction SilentlyContinue
            if ($summaryFiles.Count -gt 0) {
                $content = Get-Content -Path $summaryFiles[0].FullName -Raw
                $content | Should -Match 'Total Events'
            }
        }
    }
    
    Context "Real-time Monitoring Scenario" {
        It "Should display current sessions" {
            { & $script:SessionScript } | Should -Not -Throw
        }
        
        It "Should show session details with processes" {
            { & $script:SessionScript -ShowProcesses } | Should -Not -Throw
        }
    }
}

Describe "Integration - Combined Script Usage" {
    
    Context "Historical Analysis + Current State" {
        It "Should analyze past events and current sessions together" {
            $historical = & $script:MainScript -StartDate (Get-Date).AddHours(-24)
            { & $script:SessionScript } | Should -Not -Throw
            
            # Both should complete without error
            $historical | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Integration - Export Format Compatibility" {
    
    Context "CSV Import Validation" {
        BeforeAll {
            $script:ExportTestPath = Join-Path $script:TestOutputPath "CSVTest"
            & $script:MainScript -StartDate (Get-Date).AddHours(-1) -ExportPath $script:ExportTestPath
        }
        
        It "Exported CSV should be importable" {
            $csvFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "*.csv" -ErrorAction SilentlyContinue
            if ($csvFiles.Count -gt 0) {
                { Import-Csv -Path $csvFiles[0].FullName -ErrorAction Stop } | Should -Not -Throw
            }
        }
        
        It "Imported data should have correct structure" {
            $csvFiles = Get-ChildItem -Path $script:ExportTestPath -Filter "*.csv" -ErrorAction SilentlyContinue
            if ($csvFiles.Count -gt 0) {
                $data = Import-Csv -Path $csvFiles[0].FullName
                if ($data.Count -gt 0) {
                    $data[0].PSObject.Properties.Name | Should -Contain 'EventID'
                    $data[0].PSObject.Properties.Name | Should -Contain 'TimeCreated'
                }
            }
        }
    }
}

Describe "Integration - Performance Under Load" {
    
    Context "Large Date Range Processing" {
        It "Should handle 30-day analysis within 2 minutes" {
            $startTime = Get-Date
            & $script:MainScript -StartDate (Get-Date).AddDays(-30) | Out-Null
            $duration = (Get-Date) - $startTime
            $duration.TotalMinutes | Should -BeLessThan 2
        }
    }
}

Describe "Integration - Module Loading" {
    
    Context "PSM1 Module File" {
        BeforeAll {
            $script:ModulePath = Join-Path $script:RootPath "RDP-Forensic.psm1"
        }
        
        It "Module file should exist" {
            $script:ModulePath | Should -Exist
        }
        
        It "Module should import without errors" {
            { Import-Module $script:ModulePath -Force -ErrorAction Stop } | Should -Not -Throw
        }
        
        It "Module should export Get-RDPForensics function" {
            Import-Module $script:ModulePath -Force
            Get-Command Get-RDPForensics -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Module should export Get-CurrentRDPSessions function" {
            Import-Module $script:ModulePath -Force
            Get-Command Get-CurrentRDPSessions -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        AfterAll {
            Remove-Module RDP-Forensic -ErrorAction SilentlyContinue
        }
    }
}
