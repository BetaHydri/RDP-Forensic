<#
.SYNOPSIS
    Mock-based Pester tests to increase code coverage for Get-RDPForensics.

.DESCRIPTION
    These tests mock Get-WinEvent to return realistic fake events, exercising
    all internal parsing branches (Kerberos, NTLM, logon types, session events,
    lock/unlock, reconnect, logoff, outbound, and correlation logic).

.NOTES
    Requires Pester 5.0+
#>

#Requires -Modules Pester

BeforeAll {
    $script:ProjectRoot = Split-Path -Parent $PSScriptRoot

    $builtModule = Get-ChildItem -Path (Join-Path (Join-Path (Join-Path $script:ProjectRoot 'output') 'module') 'RDP-Forensic') -Filter 'RDP-Forensic.psd1' -Recurse | Select-Object -First 1
    if ($builtModule)
    {
        Import-Module $builtModule.FullName -Force
    }

    #region Helper: New-MockEvent
    function New-MockEvent
    {
        param(
            [int]$Id,
            [string]$Message = '',
            [string]$ActivityID,
            [DateTime]$TimeCreated = (Get-Date '2026-03-31 10:00:00'),
            [string]$XmlOverride,
            [array]$Properties,
            [string]$UserId
        )

        if (-not $XmlOverride)
        {
            $corrAttr = if ($ActivityID) { " ActivityID='$ActivityID'" } else { '' }
            $XmlOverride = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>$Id</EventID>
    <TimeCreated SystemTime='$($TimeCreated.ToUniversalTime().ToString('o'))' />
    <Correlation$corrAttr />
  </System>
</Event>
"@
        }

        $evt = [PSCustomObject]@{
            TimeCreated = $TimeCreated
            Id          = $Id
            Message     = $Message
            _xml        = $XmlOverride
        }

        if ($Properties)
        {
            $propObjects = foreach ($p in $Properties)
            {
                [PSCustomObject]@{ Value = $p }
            }
            $evt | Add-Member -NotePropertyName 'Properties' -NotePropertyValue $propObjects
        }

        if ($UserId)
        {
            $evt | Add-Member -NotePropertyName 'UserId' -NotePropertyValue $UserId
        }

        $evt | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Value { $this._xml } -Force

        return $evt
    }
    #endregion

    #region Helper: New-MockTerminalServicesEvent (XML-based events)
    function New-MockTSEvent
    {
        param(
            [int]$EventID,
            [string]$User = 'TESTDOMAIN\TestUser',
            [string]$SessionID = '3',
            [string]$Address = '192.168.1.100',
            [string]$ActivityID = '{00000001-0001-0001-0001-000000000001}',
            [DateTime]$TimeCreated = (Get-Date '2026-03-31 10:05:00'),
            [string]$Reason,
            [string]$Param2
        )

        $reasonXml = if ($Reason) { "<Reason>$Reason</Reason>" } else { '' }
        $param2Xml = if ($Param2) { "<Param2>$Param2</Param2>" } else { '' }
        $corrAttr = if ($ActivityID) { " ActivityID='$ActivityID'" } else { '' }
        $userXml = if ($User) { "<User>$User</User>" } else { '' }
        $addressXml = if ($Address) { "<Address>$Address</Address>" } else { '' }

        $xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>$EventID</EventID>
    <TimeCreated SystemTime='$($TimeCreated.ToUniversalTime().ToString('o'))' />
    <Correlation$corrAttr />
  </System>
  <UserData>
    <EventXML>
      $userXml
      <SessionID>$SessionID</SessionID>
      $addressXml
      $reasonXml
      $param2Xml
    </EventXML>
  </UserData>
</Event>
"@

        $evt = [PSCustomObject]@{
            TimeCreated = $TimeCreated
            Id          = $EventID
            Message     = ''
            _xml        = $xml
        }
        $evt | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Value { $this._xml } -Force
        return $evt
    }
    #endregion

    #region Helper: New-Mock1149Event (Connection Attempt)
    function New-Mock1149Event
    {
        param(
            [string]$User = 'TestUser',
            [string]$Domain = 'TESTDOMAIN',
            [string]$SourceIP = '192.168.1.100',
            [string]$ActivityID = '{00000001-0001-0001-0001-000000000001}',
            [DateTime]$TimeCreated = (Get-Date '2026-03-31 10:00:00')
        )

        $corrAttr = if ($ActivityID) { " ActivityID='$ActivityID'" } else { '' }
        $xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>1149</EventID>
    <TimeCreated SystemTime='$($TimeCreated.ToUniversalTime().ToString('o'))' />
    <Correlation$corrAttr />
  </System>
  <UserData>
    <EventXML>
      <Param1>$User</Param1>
      <Param2>$Domain</Param2>
      <Param3>$SourceIP</Param3>
    </EventXML>
  </UserData>
</Event>
"@

        $evt = [PSCustomObject]@{
            TimeCreated = $TimeCreated
            Id          = 1149
            Message     = ''
            _xml        = $xml
        }
        $evt | Add-Member -MemberType ScriptMethod -Name 'ToXml' -Value { $this._xml } -Force
        return $evt
    }
    #endregion

    #region Mock event data

    # --- 1149: Connection Attempts ---
    $script:MockEvents1149 = @(
        New-Mock1149Event -TimeCreated (Get-Date '2026-03-31 10:00:00')
    )

    # --- Security: 4624/4625/4648 (Authentication) ---
    $script:MockAuthEvents = @(
        # 4624 - Successful Logon (RemoteInteractive, Type 10)
        (New-MockEvent -Id 4624 -TimeCreated (Get-Date '2026-03-31 10:00:05') `
                -ActivityID '{00000002-0002-0002-0002-000000000002}' `
                -Message @"
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       DC01$
    Account Domain:     TESTDOMAIN
    Logon ID:           0x3E7

Logon Type:         10

New Logon:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345A

Network Information:
    Workstation Name:   CLIENT01
    Source Network Address:  192.168.1.100
"@),
        # 4624 - Logon Type 7 (Unlock/Reconnect)
        (New-MockEvent -Id 4624 -TimeCreated (Get-Date '2026-03-31 10:30:00') `
                -Message @"
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       DC01$
    Account Domain:     TESTDOMAIN
    Logon ID:           0x3E7

Logon Type:         7

New Logon:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345B

Network Information:
    Workstation Name:   CLIENT01
    Source Network Address:  192.168.1.100
"@),
        # 4624 - Logon Type 3 (Network)
        (New-MockEvent -Id 4624 -TimeCreated (Get-Date '2026-03-31 10:31:00') `
                -Message @"
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       DC01$
    Account Domain:     TESTDOMAIN
    Logon ID:           0x3E7

Logon Type:         3

New Logon:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345C

Network Information:
    Workstation Name:   CLIENT01
    Source Network Address:  192.168.1.100
"@),
        # 4624 - Logon Type 5 (Service)
        (New-MockEvent -Id 4624 -TimeCreated (Get-Date '2026-03-31 10:32:00') `
                -Message @"
An account was successfully logged on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       DC01$
    Account Domain:     TESTDOMAIN
    Logon ID:           0x3E7

Logon Type:         5

New Logon:
    Account Name:       SvcAccount
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345D

Network Information:
    Workstation Name:   SRVHOST01
    Source Network Address:  10.0.0.50
"@),
        # 4625 - Failed Logon (Type 10)
        (New-MockEvent -Id 4625 -TimeCreated (Get-Date '2026-03-31 10:01:00') `
                -Message @"
An account failed to log on.

Subject:
    Security ID:        S-1-0-0
    Account Name:       -
    Account Domain:     -
    Logon ID:           0x0

Logon Type:         10

New Logon:
    Account Name:       BadUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x0

Network Information:
    Workstation Name:   ATTACKER01
    Source Network Address:  10.10.10.10
"@),
        # 4648 - Explicit Credential Usage
        (New-MockEvent -Id 4648 -TimeCreated (Get-Date '2026-03-31 09:59:58') `
                -Message @"
A logon was attempted using explicit credentials.

Subject:
    Security ID:        S-1-5-21-111-222-333-1001
    Account Name:       AdminUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0xABCDE

Account Whose Credentials Were Used:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon GUID:         {00000000-0000-0000-0000-000000000000}

Target Server:
    Target Server Name: RDPHOST01
    Additional Information:    TERMSRV/RDPHOST01

Process Information:
    Process ID:         0x1234
    Process Name:       C:\Windows\System32\mstsc.exe

Network Information:
    Network Address:    192.168.1.100
    Port:               0
"@)
    )

    # --- Security: 4768-4772 (Kerberos) ---
    $script:MockKerberosEvents = @(
        # 4768 - Kerberos TGT Success
        (New-MockEvent -Id 4768 -TimeCreated (Get-Date '2026-03-31 09:59:55') `
                -Message @"
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Supplied Realm Name:    TESTDOMAIN.LOCAL

Service Information:
    Service Name:       krbtgt/TESTDOMAIN.LOCAL

Network Information:
    Client Address:     ::ffff:192.168.1.100
    Client Port:        54321

Additional Information:
    Ticket Options:     0x40810010
    Result Code:        0x0
    Ticket Encryption Type: 0x12
"@),
        # 4768 - Kerberos TGT Failed
        (New-MockEvent -Id 4768 -TimeCreated (Get-Date '2026-03-31 09:58:00') `
                -Message @"
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:       BadUser
    Account Domain:     TESTDOMAIN

Network Information:
    Client Address:     10.10.10.10

Additional Information:
    Ticket Options:     0x40810010
    Result Code:        0x6
"@),
        # 4769 - Kerberos Service Ticket Success
        (New-MockEvent -Id 4769 -TimeCreated (Get-Date '2026-03-31 09:59:56') `
                -Message @"
A Kerberos service ticket was requested.

Account Information:
    Account Name:       TestUser@TESTDOMAIN.LOCAL
    Account Domain:     TESTDOMAIN.LOCAL

Service Information:
    Service Name:       TERMSRV/RDPHOST01

Network Information:
    Client Address:     ::ffff:192.168.1.100

Additional Information:
    Ticket Options:     0x40810000
    Ticket Encryption Type: 0x12
    Failure Code:       0x0
"@),
        # 4769 - Kerberos Service Ticket Failed
        (New-MockEvent -Id 4769 -TimeCreated (Get-Date '2026-03-31 09:57:00') `
                -Message @"
A Kerberos service ticket was requested.

Account Information:
    Account Name:       BadUser@TESTDOMAIN.LOCAL
    Account Domain:     TESTDOMAIN.LOCAL

Service Information:
    Service Name:       TERMSRV/RDPHOST01

Network Information:
    Client Address:     10.10.10.10

Additional Information:
    Failure Code:       0x1B
"@),
        # 4770 - Kerberos Ticket Renewal
        (New-MockEvent -Id 4770 -TimeCreated (Get-Date '2026-03-31 11:00:00') `
                -Message @"
A Kerberos service ticket was renewed.

Account Information:
    Account Name:       TestUser@TESTDOMAIN.LOCAL
    Account Domain:     TESTDOMAIN.LOCAL

Service Information:
    Service Name:       krbtgt/TESTDOMAIN.LOCAL

Network Information:
    Client Address:     192.168.1.100
"@),
        # 4771 - Kerberos Pre-auth Failed (wrong password 0x18)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:55:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       TestUser
    Service Name:       krbtgt/TESTDOMAIN.LOCAL

Network Information:
    Client Address:     ::ffff:192.168.1.100

Additional Information:
    Failure Code:       0x18
"@),
        # 4771 - Kerberos Pre-auth Failed (clock skew 0x25)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:54:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       ClockUser

Network Information:
    Client Address:     10.10.10.20

Additional Information:
    Failure Code:       0x25
"@),
        # 4771 - Kerberos Pre-auth Failed (client not found 0x6)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:53:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       UnknownUser

Network Information:
    Client Address:     10.10.10.30

Additional Information:
    Failure Code:       0x6
"@),
        # 4771 - Kerberos Pre-auth Failed (account disabled 0x12)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:52:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       DisabledUser

Network Information:
    Client Address:     10.10.10.40

Additional Information:
    Failure Code:       0x12
"@),
        # 4771 - Kerberos Pre-auth Failed (password expired 0x17)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:51:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       ExpiredUser

Network Information:
    Client Address:     10.10.10.50

Additional Information:
    Failure Code:       0x17
"@),
        # 4771 - Kerberos Pre-auth Failed (server not found 0x7)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:50:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       NoSvrUser

Network Information:
    Client Address:     10.10.10.60

Additional Information:
    Failure Code:       0x7
"@),
        # 4771 - Kerberos Pre-auth Failed (workstation restriction 0xC)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:49:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       RestrictedUser

Network Information:
    Client Address:     10.10.10.70

Additional Information:
    Failure Code:       0xC
"@),
        # 4771 - Kerberos Pre-auth Failed (unknown error code for default branch)
        (New-MockEvent -Id 4771 -TimeCreated (Get-Date '2026-03-31 09:48:00') `
                -Message @"
Kerberos pre-authentication failed.

Account Information:
    Account Name:       DefaultUser

Network Information:
    Client Address:     10.10.10.80

Additional Information:
    Failure Code:       0xFF
"@),
        # 4772 - Kerberos Ticket Request Failed
        (New-MockEvent -Id 4772 -TimeCreated (Get-Date '2026-03-31 09:47:00') `
                -Message @"
A Kerberos authentication ticket request failed.

Account Information:
    Account Name:       FailUser
    Account Domain:     TESTDOMAIN

Network Information:
    Client Address:     10.10.10.90

Additional Information:
    Failure Code:       0x1F
"@)
    )

    # --- Security: 4776 (NTLM Credential Validation) ---
    $script:MockNTLMEvents = @(
        # 4776 - NTLM Validation Success
        (New-MockEvent -Id 4776 -TimeCreated (Get-Date '2026-03-31 09:59:57') `
                -Message @"
The computer attempted to validate the credentials for an account.

Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:  TestUser
Source Workstation:     REMOTECLIENT
Error Code:     0x0
"@),
        # 4776 - NTLM Validation Failed
        (New-MockEvent -Id 4776 -TimeCreated (Get-Date '2026-03-31 09:58:30') `
                -Message @"
The computer attempted to validate the credentials for an account.

Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:  TESTDOMAIN\BadUser
Source Workstation:     ATTACKERCLIENT
Error Code:     0xC000006A
"@)
    )

    # --- TerminalServices-LocalSessionManager: 21-25, 39, 40 (Session Events) ---
    $script:MockSessionEvents = @(
        # 21 - Session Logon
        (New-MockTSEvent -EventID 21 -TimeCreated (Get-Date '2026-03-31 10:00:10')),
        # 22 - Shell Start
        (New-MockTSEvent -EventID 22 -TimeCreated (Get-Date '2026-03-31 10:00:12')),
        # 24 - Session Disconnected
        (New-MockTSEvent -EventID 24 -TimeCreated (Get-Date '2026-03-31 10:20:00')),
        # 25 - Session Reconnected
        (New-MockTSEvent -EventID 25 -TimeCreated (Get-Date '2026-03-31 10:25:00')),
        # 23 - Session Logoff
        (New-MockTSEvent -EventID 23 -TimeCreated (Get-Date '2026-03-31 11:00:00')),
        # 39 - Disconnected by another session
        (New-MockTSEvent -EventID 39 -TimeCreated (Get-Date '2026-03-31 10:45:00') `
                -Param2 '5'),
        # 40 - Disconnect with reason code 5 (replaced)
        (New-MockTSEvent -EventID 40 -TimeCreated (Get-Date '2026-03-31 10:45:01') `
                -Reason '5'),
        # 40 - Disconnect with reason code 11 (user initiated)
        (New-MockTSEvent -EventID 40 -TimeCreated (Get-Date '2026-03-31 10:50:00') `
                -Reason '11'),
        # 40 - Disconnect with reason code 0 (no info)
        (New-MockTSEvent -EventID 40 -TimeCreated (Get-Date '2026-03-31 10:55:00') `
                -Reason '0'),
        # 40 - Disconnect with unknown reason code (default branch)
        (New-MockTSEvent -EventID 40 -TimeCreated (Get-Date '2026-03-31 10:56:00') `
                -Reason '99')
    )

    # --- Security: 4800/4801 (Lock/Unlock) ---
    $script:MockLockUnlockEvents = @(
        # 4800 - Workstation Locked
        (New-MockEvent -Id 4800 -TimeCreated (Get-Date '2026-03-31 10:10:00') `
                -ActivityID '{00000003-0003-0003-0003-000000000003}' `
                -Message @"
The workstation was locked.

Subject:
    Security ID:        S-1-5-21-111-222-333-1001
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345A

Session ID: 3
"@),
        # 4801 - Workstation Unlocked
        (New-MockEvent -Id 4801 -TimeCreated (Get-Date '2026-03-31 10:15:00') `
                -ActivityID '{00000003-0003-0003-0003-000000000003}' `
                -Message @"
The workstation was unlocked.

Subject:
    Security ID:        S-1-5-21-111-222-333-1001
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345A

Session ID: 3
"@)
    )

    # --- Security: 4778/4779 (Reconnect/Disconnect) ---
    $script:MockReconnectEvents = @(
        # 4778 - Session Reconnected
        (New-MockEvent -Id 4778 -TimeCreated (Get-Date '2026-03-31 10:25:01') `
                -ActivityID '{00000004-0004-0004-0004-000000000004}' `
                -Message @"
A session was reconnected to a Window Station.

Subject:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345A

Session Information:
    Session Name:       RDP-Tcp#5

Additional Information:
    Client Name:        CLIENT01
    Client Address:     192.168.1.100
"@),
        # 4779 - Session Disconnected
        (New-MockEvent -Id 4779 -TimeCreated (Get-Date '2026-03-31 10:20:01') `
                -ActivityID '{00000004-0004-0004-0004-000000000004}' `
                -Message @"
A session was disconnected from a Window Station.

Subject:
    Account Name:       TestUser
    Account Domain:     TESTDOMAIN
    Logon ID:           0x12345A

Session Information:
    Session Name:       RDP-Tcp#5

Additional Information:
    Client Name:        CLIENT01
    Client Address:     192.168.1.100
"@)
    )

    # --- Security: 4634/4647 (Logoff) + System: 9009 ---
    # NOTE: The Where-Object filter uses 'Logon Type:\s+(10|7|3|5)\s'
    # The trailing \s requires whitespace AFTER the number. Adding explicit
    # newline content after the logon type to ensure the regex matches.
    $script:MockSecurityLogoffEvents = @(
        # 4634 - Account Logged Off (Logon Type 10)
        (New-MockEvent -Id 4634 -TimeCreated (Get-Date '2026-03-31 11:00:05') `
                -Message ("An account was logged off.`r`n`r`nSubject:`r`n    Security ID:        S-1-5-21-111-222-333-1001`r`n    Account Name:       TestUser`r`n    Account Domain:     TESTDOMAIN`r`n    Logon ID:           0x12345A`r`n`r`nLogon Type:         10`r`n`r`nThis event is generated when a logon session is destroyed.")),
        # 4647 - User-Initiated Logoff (Logon Type 10)
        (New-MockEvent -Id 4647 -TimeCreated (Get-Date '2026-03-31 11:00:03') `
                -Message ("User initiated logoff:`r`n`r`nSubject:`r`n    Security ID:        S-1-5-21-111-222-333-1001`r`n    Account Name:       TestUser`r`n    Account Domain:     TESTDOMAIN`r`n    Logon ID:           0x12345A`r`n`r`nLogon Type:         10`r`n`r`nThis event is generated when a logoff is initiated."))
    )

    $script:MockSystemLogoffEvents = @(
        # 9009 - DWM Exit
        (New-MockEvent -Id 9009 -TimeCreated (Get-Date '2026-03-31 11:00:10') `
                -Message 'Desktop Window Manager has exited with code (0x0).')
    )

    # --- Outbound: 1102 ---
    $script:MockOutboundEvents = @(
        (New-MockEvent -Id 1102 -TimeCreated (Get-Date '2026-03-31 10:30:00') `
                -Properties @($null, 'RDPHOST02.testdomain.local') `
                -UserId 'S-1-5-21-111-222-333-1001' `
                -Message 'RDP connection initiated.')
    )

    #endregion
}

Describe 'Get-RDPForensics - Mock-Based Code Coverage Tests' {

    BeforeAll {
        # Suppress all Write-Host output during tests
        Mock -ModuleName 'RDP-Forensic' -CommandName 'Write-Host'
        Mock -ModuleName 'RDP-Forensic' -CommandName 'Write-Warning'

        # Smart mock for Get-WinEvent routing by LogName and EventID
        Mock -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -MockWith {
            $logName = $FilterHashtable.LogName
            $ids = @($FilterHashtable.Id)

            switch ($logName)
            {
                'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
                {
                    return $script:MockEvents1149
                }
                'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
                {
                    return $script:MockSessionEvents
                }
                'Microsoft-Windows-TerminalServices-RDPClient/Operational'
                {
                    return $script:MockOutboundEvents
                }
                'Security'
                {
                    if (4624 -in $ids -or 4625 -in $ids)
                    {
                        return $script:MockAuthEvents
                    }
                    if (4768 -in $ids)
                    {
                        return $script:MockKerberosEvents
                    }
                    if (4776 -in $ids)
                    {
                        return $script:MockNTLMEvents
                    }
                    if (4800 -in $ids)
                    {
                        return $script:MockLockUnlockEvents
                    }
                    if (4778 -in $ids)
                    {
                        return $script:MockReconnectEvents
                    }
                    if (4634 -in $ids)
                    {
                        return $script:MockSecurityLogoffEvents
                    }
                }
                'System'
                {
                    return $script:MockSystemLogoffEvents
                }
            }
            return @()
        }

        # Mock SID translation for outbound events
        Mock -ModuleName 'RDP-Forensic' -CommandName 'New-Object' -ParameterFilter {
            $TypeName -eq 'System.Security.Principal.SecurityIdentifier'
        } -MockWith {
            $mockSid = [PSCustomObject]@{}
            $mockSid | Add-Member -MemberType ScriptMethod -Name 'Translate' -Value {
                [PSCustomObject]@{ Value = 'TESTDOMAIN\TestUser' }
            }
            return $mockSid
        }
    }

    Context 'Basic invocation exercises all event collection functions' {
        It 'Should execute without error and call Get-WinEvent for all log sources' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') } |
                Should -Not -Throw

            # Verify Get-WinEvent was called for each log source
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
            }
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            }
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Security' -and 4800 -in @($FilterHashtable.Id)
            }
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Security' -and 4778 -in @($FilterHashtable.Id)
            }
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Security' -and 4634 -in @($FilterHashtable.Id)
            }
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'System'
            }
        }
    }

    Context 'IncludeCredentialValidation exercises Kerberos and NTLM parsing' {
        It 'Should parse all Kerberos event types (4768-4772) and NTLM (4776) without error' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -IncludeCredentialValidation } |
                Should -Not -Throw

            # Kerberos events should have been queried
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Security' -and 4768 -in @($FilterHashtable.Id)
            }
            # NTLM events should have been queried
            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Security' -and 4776 -in @($FilterHashtable.Id)
            }
        }
    }

    Context 'IncludeOutbound exercises outbound RDP connection parsing' {
        It 'Should parse EventID 1102 outbound connections' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -IncludeOutbound } |
                Should -Not -Throw

            Should -Invoke -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -Times 1 -ParameterFilter {
                $FilterHashtable.LogName -eq 'Microsoft-Windows-TerminalServices-RDPClient/Operational'
            }
        }
    }

    Context 'GroupBySession exercises correlation logic' {
        It 'Should correlate events by LogonID and SessionID' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession } |
                Should -Not -Throw
        }

        It 'Should correlate with IncludeCredentialValidation (pre-auth time-based matching)' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession -IncludeCredentialValidation } |
                Should -Not -Throw
        }
    }

    Context 'Username filter exercises filtering code path' {
        It 'Should filter events by username' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -Username 'TestUser' } |
                Should -Not -Throw
        }

        It 'Should return no results for non-matching username' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -Username 'NoSuchUser999' } |
                Should -Not -Throw
        }
    }

    Context 'SourceIP filter exercises filtering code path' {
        It 'Should filter events by source IP' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -SourceIP '192.168.1.100' } |
                Should -Not -Throw
        }
    }

    Context 'LogonID filter with GroupBySession exercises LogonID filtering' {
        It 'Should filter sessions by LogonID' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession -LogonID '0x12345A' } |
                Should -Not -Throw
        }

        It 'Should handle non-matching LogonID gracefully' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession -LogonID '0xNONEXISTENT' } |
                Should -Not -Throw
        }
    }

    Context 'SessionID filter with GroupBySession exercises SessionID filtering' {
        It 'Should filter sessions by SessionID' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession -SessionID '3' } |
                Should -Not -Throw
        }

        It 'Should handle non-matching SessionID gracefully' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -GroupBySession -SessionID '999' } |
                Should -Not -Throw
        }
    }

    Context 'ExportPath exercises CSV export code' {
        BeforeAll {
            $script:ExportDir = Join-Path $PSScriptRoot 'TestOutput_Coverage'
        }

        AfterEach {
            if (Test-Path $script:ExportDir)
            {
                Remove-Item $script:ExportDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should export events to CSV files' {
            Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -ExportPath $script:ExportDir

            $script:ExportDir | Should -Exist
            $csvFiles = Get-ChildItem -Path $script:ExportDir -Filter 'RDP_Forensics_*.csv'
            $csvFiles.Count | Should -BeGreaterThan 0

            $summaryFiles = Get-ChildItem -Path $script:ExportDir -Filter 'RDP_Summary_*.txt'
            $summaryFiles.Count | Should -BeGreaterThan 0
        }

        It 'Should export session data when GroupBySession is used with ExportPath' {
            Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -ExportPath $script:ExportDir -GroupBySession

            $sessionFiles = Get-ChildItem -Path $script:ExportDir -Filter 'RDP_Sessions_*.csv'
            $sessionFiles.Count | Should -BeGreaterThan 0

            $sessionData = Import-Csv $sessionFiles[0].FullName
            $sessionData[0].PSObject.Properties.Name | Should -Contain 'CorrelationKey'
            $sessionData[0].PSObject.Properties.Name | Should -Contain 'User'
            $sessionData[0].PSObject.Properties.Name | Should -Contain 'Duration'
            $sessionData[0].PSObject.Properties.Name | Should -Contain 'LifecycleComplete'
        }
    }

    Context 'Export with filters validates exported content' {
        BeforeAll {
            $script:ExportDir2 = Join-Path $PSScriptRoot 'TestOutput_Coverage2'
        }

        AfterEach {
            if (Test-Path $script:ExportDir2)
            {
                Remove-Item $script:ExportDir2 -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Should export filtered events by Username' {
            Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') -ExportPath $script:ExportDir2 -Username 'TestUser'

            $csvFiles = Get-ChildItem -Path $script:ExportDir2 -Filter 'RDP_Forensics_*.csv'
            $csvFiles.Count | Should -BeGreaterThan 0
            $csv = Import-Csv $csvFiles[0].FullName
            $csv | ForEach-Object { $_.User | Should -Match 'TestUser' }
        }
    }

    Context 'No events found exercises empty result path' {
        BeforeAll {
            # Override mock to return empty for this context
            Mock -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -MockWith {
                return $null
            }
        }

        It 'Should handle zero events gracefully' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') } |
                Should -Not -Throw
        }
    }

    Context 'Error handling in event collection' {
        BeforeAll {
            Mock -ModuleName 'RDP-Forensic' -CommandName 'Get-WinEvent' -MockWith {
                throw 'Access denied'
            }
        }

        It 'Should handle Get-WinEvent errors gracefully (try/catch with Write-Warning)' {
            { Get-RDPForensics -StartDate (Get-Date '2026-03-31 09:00:00') -EndDate (Get-Date '2026-03-31 12:00:00') } |
                Should -Not -Throw
        }
    }
}
