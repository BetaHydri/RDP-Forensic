# RDP Forensics Toolkit - Test Suite

Comprehensive automated testing for the RDP Forensics Toolkit using Pester 5.0+.

## Overview

This test suite includes:

- **Unit Tests** - Individual script functionality validation
- **Integration Tests** - End-to-end workflow testing  
- **Performance Tests** - Execution time and resource usage
- **Code Coverage** - Identifies untested code paths

## Prerequisites

### Required

- **PowerShell 5.1** or later
- **Pester 5.0+** testing framework
- **Administrator privileges** (for full test coverage)

### Install Pester

```powershell
Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

Verify installation:

```powershell
Get-Module -Name Pester -ListAvailable
```

## Test Files

| File | Description | Tests |
|------|-------------|-------|
| `Get-RDPForensics.Tests.ps1` | Main script unit tests | 50+ |
| `Get-RDPForensics.Correlation.Tests.ps1` | Session correlation & ActivityID tests | 25+ |
| `Get-CurrentRDPSessions.Tests.ps1` | Session monitoring tests | 10+ |
| `Integration.Tests.ps1` | End-to-end workflow tests | 15+ |
| `PowerShellVersion.Tests.ps1` | **NEW** PS 5.1/7+ compatibility tests | 40+ |
| `RunAllTests.ps1` | Master test runner | - |

## Running Tests

### Quick Start

Run all tests with standard output:

```powershell
cd Tests
.\RunAllTests.ps1
```

### Advanced Options

**With HTML Report:**
```powershell
.\RunAllTests.ps1 -GenerateReport
```

**With Code Coverage:**
```powershell
.\RunAllTests.ps1 -CodeCoverage
```

**CI Mode (exit with error code on failure):**
```powershell
.\RunAllTests.ps1 -CI
```

**All Features:**
```powershell
.\RunAllTests.ps1 -GenerateReport -CodeCoverage
```

### Run Individual Test Files

```powershell
# Main script tests only
Invoke-Pester -Path .\Get-RDPForensics.Tests.ps1 -Output Detailed

# Session monitoring tests only
Invoke-Pester -Path .\Get-CurrentRDPSessions.Tests.ps1 -Output Detailed

# Integration tests only
Invoke-Pester -Path .\Integration.Tests.ps1 -Output Detailed
```

### Run Specific Tests

```powershell
# Run tests matching a tag
Invoke-Pester -Path . -Tag "EventCollection" -Output Detailed

# Run tests matching a name pattern
Invoke-Pester -Path . -FullNameFilter "*Export*" -Output Detailed
```

## Test Categories

### 1. Script Validation Tests
- File existence and syntax checking
- Help documentation validation
- Administrator privilege requirements
- Parameter validation

### 2. Event Collection Tests
- Event log accessibility
- Multi-log source queries
- EventID coverage (15+ critical events)
- Output structure validation

### 3. Filtering Tests
- Username filtering accuracy
- Source IP filtering
- Date range filtering
- Combined filter logic

### 4. Export Functionality Tests
- CSV file generation
- Summary report creation
- File structure validation
- Import compatibility

### 5. Performance Tests
- Execution time benchmarks
- Large dataset handling
- Memory usage monitoring

### 6. Integration Tests
- Complete forensic workflows
- Combined script usage
- Real-world scenarios:
  - Daily security review
  - Incident investigation
  - Compliance auditing
  - Real-time monitoring

### 7. Error Handling Tests
- Invalid parameter handling
- Non-existent user/IP filtering
- Edge case scenarios
- Graceful failure modes

### 8. Session Correlation Tests (v1.0.5+, enhanced v1.0.7)
- LogonID-based correlation (Priority 1)
- SessionID-based correlation (Priority 2)
- Secondary correlation: SessionID → LogonID merge (Username + Time + RDP LogonType)
- Lifecycle stage tracking (6 stages)
- Session duration calculation
- Completeness detection
- GroupBySession display output
- Sessions CSV export

### 9. Credential Validation Tests (NEW v1.0.6+)
- EventID 4776 collection (optional)
- IncludeCredentialValidation parameter
- Time-based correlation (0-10 second window)
- Username matching for correlation
- Remote-only filtering
- Credential validation event parsing
- Error code interpretation

### 10. PowerShell Version Compatibility Tests (NEW v1.0.6+)
- PowerShell 5.1 execution
- PowerShell 7+ execution
- Emoji/character rendering across versions
- ConvertFromUtf32 compatibility
- Get-WinEvent syntax compatibility
- Switch parameter handling
- CSV export UTF-8 encoding
- Module import on both versions

## Test Results

### Output Location

Test results are saved to `Tests/TestResults/`:

```
TestResults/
├── TestResults.xml      # NUnit format test results
├── TestReport.html      # Human-readable HTML report
└── CodeCoverage.xml     # Code coverage data
```

### Understanding Results

**Test Status Indicators:**
- ✅ **Passed** - Test completed successfully
- ❌ **Failed** - Test did not meet expectations
- ⚠️ **Skipped** - Test not applicable (e.g., no RDP events exist)

### Testing on Multiple PowerShell Versions

**Important:** The toolkit supports both PowerShell 5.1 and 7+. Run tests on BOTH versions:

**PowerShell 5.1 (Windows PowerShell):**
```powershell
# Run from Windows PowerShell console
powershell.exe
cd Tests
.\RunAllTests.ps1
```

**PowerShell 7+ (PowerShell Core):**
```powershell
# Run from PowerShell 7+ console
pwsh.exe
cd Tests
.\RunAllTests.ps1
```

**Version-Specific Tests:**
```powershell
# Run only PowerShell compatibility tests
Invoke-Pester -Path .\PowerShellVersion.Tests.ps1 -Output Detailed
```

**Expected Differences:**
- PowerShell 5.1 uses fallback characters (□, ○, ×) instead of emojis
- PowerShell 7+ displays full Unicode emoji support
- Both versions should pass all functional tests

**Code Coverage Targets:**
- 🟢 **70%+** - Excellent coverage
- 🟡 **50-70%** - Good coverage
- 🔴 **<50%** - Needs improvement

### Sample Output

```
========================================
Test Execution Summary
========================================

Duration: 02:34
Total Tests: 67
Passed: 64
Failed: 0
Skipped: 3

Code Coverage Summary:
Commands Analyzed: 245
Commands Executed: 186
Coverage: 75.92%
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test RDP Forensics Toolkit

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -MinimumVersion 5.0 -Force
      
      - name: Run Tests
        shell: pwsh
        run: |
          cd Tests
          .\RunAllTests.ps1 -CI -CodeCoverage
```

## Troubleshooting

### Common Issues

**"Pester module not found"**
```powershell
Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

**"Access Denied" errors**
- Run PowerShell as Administrator
- Security event log requires elevated privileges

**Tests are skipped**
- Some tests require actual RDP events to exist
- Skipped tests are normal if no recent RDP activity

**Performance test failures**
- Adjust timeout values based on system performance
- Large log volumes may exceed default thresholds

### Debug Mode

Run tests with verbose output:

```powershell
$VerbosePreference = 'Continue'
Invoke-Pester -Path . -Output Detailed
```

View detailed test execution:

```powershell
Invoke-Pester -Path . -Output Diagnostic
```

## Writing New Tests

### Test Template

```powershell
Describe "Feature Name" {
    Context "Specific Scenario" {
        BeforeAll {
            # Setup code
        }
        
        It "Should perform expected behavior" {
            # Arrange
            $input = "test data"
            
            # Act
            $result = Test-Function $input
            
            # Assert
            $result | Should -Be "expected output"
        }
        
        AfterAll {
            # Cleanup code
        }
    }
}
```

### Best Practices

1. **Descriptive Names** - Use clear "Should..." assertions
2. **Arrange-Act-Assert** - Structure tests consistently
3. **Isolation** - Each test should be independent
4. **Cleanup** - Use BeforeAll/AfterAll for setup/teardown
5. **Skip Appropriately** - Use `Set-ItResult -Skipped` when conditions not met

### Example Test

```powershell
Describe "Username Filtering" {
    Context "When filtering by existing user" {
        It "Should return only events for specified user" {
            # Arrange
            $targetUser = "TestUser"
            
            # Act
            $results = & $ScriptPath -Username $targetUser -StartDate (Get-Date).AddDays(-1)
            
            # Assert
            $results | ForEach-Object {
                $_.User | Should -Match $targetUser
            }
        }
    }
}
```

## Code Coverage

### Generate Coverage Report

```powershell
.\RunAllTests.ps1 -CodeCoverage
```

### View Coverage Data

```powershell
# Import coverage results
$coverage = Import-Clixml .\TestResults\CodeCoverage.xml

# View missed commands
$coverage.MissedCommands | Format-Table File, Line, Function

# View coverage by file
$coverage.CommandsExecutedCount / $coverage.CommandsAnalyzedCount * 100
```

## Contributing Tests

When adding new features, please include:

1. **Unit tests** for new functions
2. **Integration tests** for new workflows
3. **Update documentation** in this README
4. **Ensure all tests pass** before submitting

### Test Contribution Checklist

- [ ] Tests are descriptive and well-named
- [ ] Tests cover happy path scenarios
- [ ] Tests cover error conditions
- [ ] Tests are isolated and independent
- [ ] Cleanup code is included
- [ ] Tests pass consistently
- [ ] Code coverage maintained or improved

## Support

For issues or questions about tests:

1. Check this README for common solutions
2. Review test output for detailed error messages
3. Run individual tests for focused troubleshooting
4. Open an issue on GitHub with test results

## License

Tests are provided under the same license as the main toolkit.
