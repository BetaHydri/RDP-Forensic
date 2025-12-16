<#
.SYNOPSIS
    Master test runner for RDP Forensics Toolkit

.DESCRIPTION
    Runs all test suites and generates a consolidated test report.
    Includes unit tests, integration tests, and code coverage analysis.

.PARAMETER GenerateReport
    Generate HTML test report

.PARAMETER CodeCoverage
    Run code coverage analysis

.PARAMETER CI
    Run in CI mode (exits with error code on failure)

.EXAMPLE
    .\RunAllTests.ps1
    Run all tests with standard output

.EXAMPLE
    .\RunAllTests.ps1 -GenerateReport
    Run all tests and generate HTML report

.EXAMPLE
    .\RunAllTests.ps1 -CodeCoverage
    Run all tests with code coverage analysis

.NOTES
    Requires Pester 5.0+
    Run as Administrator for full test coverage
#>

#Requires -Modules Pester
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$GenerateReport,
    [switch]$CodeCoverage,
    [switch]$CI
)

$ErrorActionPreference = 'Stop'

# Configuration
$TestsPath = $PSScriptRoot
$RootPath = Split-Path -Parent $TestsPath
$ReportPath = Join-Path $TestsPath "TestResults"

# Ensure report directory exists
if (-not (Test-Path $ReportPath)) {
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RDP Forensics Toolkit - Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check Pester version
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pesterModule) {
    Write-Error "Pester module not found. Install with: Install-Module -Name Pester -Force"
}

Write-Host "Pester Version: $($pesterModule.Version)" -ForegroundColor Gray
Write-Host "Tests Location: $TestsPath" -ForegroundColor Gray
Write-Host "Report Location: $ReportPath`n" -ForegroundColor Gray

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some tests may be skipped."
}

# Build Pester configuration
$pesterConfig = New-PesterConfiguration

# Test discovery
$pesterConfig.Run.Path = $TestsPath
$pesterConfig.Run.PassThru = $true
if ($CI) {
    $pesterConfig.Run.Exit = $true
}

# Output configuration
$pesterConfig.Output.Verbosity = 'Detailed'

# Code coverage configuration
if ($CodeCoverage) {
    Write-Host "Code Coverage Analysis: Enabled" -ForegroundColor Yellow
    $pesterConfig.CodeCoverage.Enabled = $true
    $pesterConfig.CodeCoverage.Path = @(
        (Join-Path $RootPath "Get-RDPForensics.ps1"),
        (Join-Path $RootPath "Get-CurrentRDPSessions.ps1")
    )
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $ReportPath "CodeCoverage.xml"
}

# Report configuration
if ($GenerateReport) {
    Write-Host "HTML Report Generation: Enabled" -ForegroundColor Yellow
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = Join-Path $ReportPath "TestResults.xml"
}

Write-Host "`nStarting test execution...`n" -ForegroundColor Cyan

# Run tests
$testStartTime = Get-Date
$results = Invoke-Pester -Configuration $pesterConfig
$testDuration = (Get-Date) - $testStartTime

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Execution Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Duration: $($testDuration.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host "Total Tests: $($results.TotalCount)" -ForegroundColor White
Write-Host "Passed: $($results.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($results.FailedCount)" -ForegroundColor $(if ($results.FailedCount -gt 0) { 'Red' } else { 'Gray' })
Write-Host "Skipped: $($results.SkippedCount)" -ForegroundColor Yellow

if ($results.FailedCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    $results.Failed | ForEach-Object {
        Write-Host "  - $($_.ExpandedName)" -ForegroundColor Red
        if ($_.ErrorRecord) {
            Write-Host "    Error: $($_.ErrorRecord.Exception.Message)" -ForegroundColor DarkRed
        }
    }
}

# Code coverage summary
if ($CodeCoverage -and $results.CodeCoverage) {
    Write-Host "`nCode Coverage Summary:" -ForegroundColor Cyan
    $coverage = $results.CodeCoverage
    
    if ($coverage.CommandsExecutedCount -gt 0) {
        $coveragePercent = [math]::Round(($coverage.CommandsExecutedCount / $coverage.CommandsAnalyzedCount) * 100, 2)
        Write-Host "Commands Analyzed: $($coverage.CommandsAnalyzedCount)" -ForegroundColor Gray
        Write-Host "Commands Executed: $($coverage.CommandsExecutedCount)" -ForegroundColor Gray
        Write-Host "Coverage: $coveragePercent%" -ForegroundColor $(if ($coveragePercent -ge 70) { 'Green' } elseif ($coveragePercent -ge 50) { 'Yellow' } else { 'Red' })
        
        if ($coverage.MissedCommands) {
            Write-Host "`nMissed Commands: $($coverage.MissedCommands.Count)" -ForegroundColor Yellow
        }
    }
}

# Generate HTML report if requested
if ($GenerateReport -and (Test-Path (Join-Path $ReportPath "TestResults.xml"))) {
    Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan
    
    $htmlReportPath = Join-Path $ReportPath "TestReport.html"
    
    # Simple HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>RDP Forensics Toolkit - Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #0078D4; border-bottom: 2px solid #0078D4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { flex: 1; padding: 20px; border-radius: 5px; text-align: center; }
        .stat-box h3 { margin: 0; font-size: 36px; }
        .stat-box p { margin: 5px 0 0 0; color: #666; }
        .passed { background-color: #d4edda; color: #155724; }
        .failed { background-color: #f8d7da; color: #721c24; }
        .skipped { background-color: #fff3cd; color: #856404; }
        .total { background-color: #d1ecf1; color: #0c5460; }
        .timestamp { color: #666; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078D4; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .skip { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RDP Forensics Toolkit - Test Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        
        <div class="summary">
            <div class="stat-box total">
                <h3>$($results.TotalCount)</h3>
                <p>Total Tests</p>
            </div>
            <div class="stat-box passed">
                <h3>$($results.PassedCount)</h3>
                <p>Passed</p>
            </div>
            <div class="stat-box failed">
                <h3>$($results.FailedCount)</h3>
                <p>Failed</p>
            </div>
            <div class="stat-box skipped">
                <h3>$($results.SkippedCount)</h3>
                <p>Skipped</p>
            </div>
        </div>
        
        <h2>Test Details</h2>
        <p>Duration: $($testDuration.ToString('mm\:ss'))</p>
        
        <h2>Test Results</h2>
        <table>
            <tr>
                <th>Test Name</th>
                <th>Result</th>
                <th>Duration</th>
            </tr>
"@
    
    # Add test results
    $results.Tests | ForEach-Object {
        $resultClass = switch ($_.Result) {
            'Passed' { 'pass' }
            'Failed' { 'fail' }
            'Skipped' { 'skip' }
            default { '' }
        }
        
        $htmlContent += @"
            <tr>
                <td>$($_.ExpandedName)</td>
                <td class="$resultClass">$($_.Result)</td>
                <td>$($_.Duration.TotalMilliseconds)ms</td>
            </tr>
"@
    }
    
    $htmlContent += @"
        </table>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $htmlReportPath -Encoding UTF8
    Write-Host "HTML report saved to: $htmlReportPath" -ForegroundColor Green
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# Exit with appropriate code for CI
if ($CI) {
    exit $results.FailedCount
}

# Return results
return $results
