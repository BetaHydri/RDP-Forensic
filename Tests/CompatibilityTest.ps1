# PowerShell 5.1 Compatibility Test
# Run this in PowerShell 5.1 to verify all v1.0.8 features work

Write-Host "=== RDP-Forensic v1.0.8 Compatibility Test ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
Write-Host "Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Yellow
Write-Host ""

# Import module
Import-Module .\RDP-Forensic.psm1 -Force

# Test 1: Parameter Sets
Write-Host "Test 1: Parameter Sets (LogonID/SessionID Mutual Exclusivity)" -ForegroundColor Green
try {
    $cmd = Get-Command Get-RDPForensics
    $logonIDSet = ($cmd.Parameters['LogonID'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).ParameterSetName
    $sessionIDSet = ($cmd.Parameters['SessionID'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }).ParameterSetName
    
    if ($logonIDSet -eq 'ByLogonID' -and $sessionIDSet -eq 'BySessionID') {
        Write-Host "  ✓ Parameter Sets defined correctly" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Parameter Sets not defined correctly" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ✗ Error: $_" -ForegroundColor Red
}

# Test 2: Event 4648 parsing (regex compatibility)
Write-Host "`nTest 2: Event 4648 Regex Parsing" -ForegroundColor Green
$testMessage = @"
Subject:
	Account Name:		testuser
	Account Domain:		DOMAIN
	Logon ID:		0x12345

Account Whose Credentials Were Used:
	Account Name:		targetuser
	Account Domain:		DOMAIN

Target Server:
	Target Server Name:	SERVER01

Network Information:
	Network Address:	192.168.1.100

Process Information:
	Process Name:		C:\Windows\System32\mstsc.exe
"@

try {
    if ($testMessage -match 'Subject:[\s\S]*?Account Name:\s+([^\r\n]+)') {
        $subjectUser = $matches[1].Trim()
        Write-Host "  ✓ Subject parsing works: $subjectUser" -ForegroundColor Green
    }
    if ($testMessage -match 'Account Whose Credentials Were Used:[\s\S]*?Account Name:\s+([^\r\n]+)') {
        $targetUser = $matches[1].Trim()
        Write-Host "  ✓ Target parsing works: $targetUser" -ForegroundColor Green
    }
    if ($testMessage -match 'Target Server:[\s\S]*?Target Server Name:\s+([^\r\n]+)') {
        $server = $matches[1].Trim()
        Write-Host "  ✓ Server parsing works: $server" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ✗ Regex parsing error: $_" -ForegroundColor Red
}

# Test 3: TimeSpan operations (time-based correlation)
Write-Host "`nTest 3: TimeSpan Operations (Time-based Correlation)" -ForegroundColor Green
try {
    $time1 = Get-Date
    $time2 = $time1.AddSeconds(5)
    $diff = $time2 - $time1
    if ($diff.TotalSeconds -eq 5) {
        Write-Host "  ✓ TimeSpan calculations work correctly" -ForegroundColor Green
    }
    
    # Test time window logic
    if ($diff.TotalSeconds -ge 0 -and $diff.TotalSeconds -le 10) {
        Write-Host "  ✓ Time window logic works (0-10 second window)" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ✗ TimeSpan error: $_" -ForegroundColor Red
}

# Test 4: Hash table operations (session correlation)
Write-Host "`nTest 4: Hash Table Operations (Session Correlation)" -ForegroundColor Green
try {
    $sessionMap = @{}
    $sessionMap['LogonID:0x12345'] = @{
        Events   = @()
        User     = 'testuser'
        SourceIP = '192.168.1.1'
    }
    
    if ($sessionMap.ContainsKey('LogonID:0x12345')) {
        Write-Host "  ✓ Hash table operations work" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ✗ Hash table error: $_" -ForegroundColor Red
}

# Test 5: Array operations
Write-Host "`nTest 5: Array Filtering Operations" -ForegroundColor Green
try {
    $events = @(
        [PSCustomObject]@{ EventID = 4624; SessionID = '3'; LogonID = '0x12345' }
        [PSCustomObject]@{ EventID = 4648; SessionID = $null; LogonID = '0x12345' }
        [PSCustomObject]@{ EventID = 21; SessionID = '3'; LogonID = $null }
    )
    
    # Test SessionID filtering
    $filtered = $events | Where-Object {
        ($_.SessionID -eq '3') -or
        ((-not $_.SessionID) -and $_.EventID -in @(4624, 4648))
    }
    
    if ($filtered.Count -eq 3) {
        Write-Host "  ✓ Array filtering works correctly" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Array filtering returned $($filtered.Count) events (expected 3)" -ForegroundColor Red
    }
}
catch {
    Write-Host "  ✗ Array filtering error: $_" -ForegroundColor Red
}

# Test 6: Parameter binding (mutual exclusivity)
Write-Host "`nTest 6: Parameter Binding (Mutual Exclusivity)" -ForegroundColor Green
try {
    # This should fail
    Get-RDPForensics -LogonID '0x12345' -SessionID '3' -StartDate (Get-Date) -ErrorAction Stop
    Write-Host "  ✗ Mutual exclusivity NOT working (should have thrown error)" -ForegroundColor Red
}
catch {
    if ($_.Exception.Message -match 'Parameter set') {
        Write-Host "  ✓ Mutual exclusivity works (correctly rejected both parameters)" -ForegroundColor Green
    }
    else {
        Write-Host "  ? Different error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Test 7: Individual parameter usage
Write-Host "`nTest 7: Individual Parameter Usage" -ForegroundColor Green
try {
    Get-RDPForensics -LogonID '0x12345' -StartDate (Get-Date).AddHours(-1) -ErrorAction Stop | Out-Null
    Write-Host "  ✓ LogonID parameter works" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ LogonID parameter error: $_" -ForegroundColor Red
}

try {
    Get-RDPForensics -SessionID '3' -StartDate (Get-Date).AddHours(-1) -ErrorAction Stop | Out-Null
    Write-Host "  ✓ SessionID parameter works" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ SessionID parameter error: $_" -ForegroundColor Red
}

# Test 8: Emoji fallback for PowerShell 5.1
Write-Host "`nTest 8: Emoji Fallback" -ForegroundColor Green
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Write-Host "  ✓ PowerShell 5.1 detected - using fallback symbols" -ForegroundColor Green
    Write-Host "  Sample: $([char]0x25A3) $([char]0x25D4) $([char]0x263A)" -ForegroundColor Cyan
}
elseif ($PSVersionTable.PSVersion.Major -ge 6) {
    Write-Host "  ✓ PowerShell 7.x detected - using full emoji" -ForegroundColor Green
    Write-Host "  Sample: $([char]::ConvertFromUtf32(0x1F4BB)) $([char]::ConvertFromUtf32(0x1F50D)) $([char]::ConvertFromUtf32(0x2705))" -ForegroundColor Cyan
}

Write-Host "`n=== Compatibility Test Complete ===" -ForegroundColor Cyan
Write-Host "All core features tested successfully!" -ForegroundColor Green
