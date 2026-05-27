BeforeAll {
    # Import the built module
    $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
    $ModulePath = Join-Path (Join-Path $script:ProjectRoot 'source') 'Public'
    $builtModule = Get-ChildItem -Path (Join-Path (Join-Path (Join-Path $script:ProjectRoot 'output') 'module') 'RDP-Forensic') -Filter 'RDP-Forensic.psd1' -Recurse | Select-Object -First 1
    if ($builtModule)
    {
        Import-Module $builtModule.FullName -Force
    }

    $script:ScriptPath = Join-Path $ModulePath 'Get-RDPForensics.ps1'
}

Describe "Get-RDPForensics Domain Controller Query Tests" {

    Context "DomainController Parameter" {
        It "Should accept DomainController parameter" {
            $params = (Get-Command Get-RDPForensics).Parameters
            $params.ContainsKey('DomainController') | Should -Be $true
        }

        It "DomainController should accept string array" {
            $param = (Get-Command Get-RDPForensics).Parameters['DomainController']
            $param.ParameterType.Name | Should -Be 'String[]'
        }

        It "DomainController should not be mandatory" {
            $param = (Get-Command Get-RDPForensics).Parameters['DomainController']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Not -Contain $true
        }

        It "DomainController should accept multiple values" {
            $param = (Get-Command Get-RDPForensics).Parameters['DomainController']
            $param.ParameterType.IsArray | Should -Be $true
        }
    }

    Context "AllDomainControllers Parameter" {
        It "Should accept AllDomainControllers parameter" {
            $params = (Get-Command Get-RDPForensics).Parameters
            $params.ContainsKey('AllDomainControllers') | Should -Be $true
        }

        It "AllDomainControllers should be a switch parameter" {
            $param = (Get-Command Get-RDPForensics).Parameters['AllDomainControllers']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It "AllDomainControllers should not be mandatory" {
            $param = (Get-Command Get-RDPForensics).Parameters['AllDomainControllers']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Not -Contain $true
        }
    }

    Context "DC Query Helper Function" {
        It "Should contain Get-DCAuthenticationEvents function definition" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'function Get-DCAuthenticationEvents'
        }

        It "Get-DCAuthenticationEvents should accept DCList parameter" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'param\s*\(\s*\[string\[\]\]\$DCList'
        }

        It "Get-DCAuthenticationEvents should accept Start and End parameters" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '\[DateTime\]\$Start'
            $content | Should -Match '\[DateTime\]\$End'
        }

        It "Should use Invoke-Command for WinRM as primary transport" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Invoke-Command\s+-ComputerName\s+\$dc'
        }

        It "Should fall back to Get-WinEvent -ComputerName for RPC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Get-WinEvent\s+-ComputerName\s+\$dc'
        }

        It "Should query Kerberos events (4768-4772) on DC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match '4768,\s*4769,\s*4770,\s*4771,\s*4772'
        }

        It "Should query NTLM events (4776) on DC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Id\s*=\s*4776'
        }

        It "Should filter out local NTLM events on DC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Source Workstation.*LOCAL\|LOCALHOST\|127'
        }
    }

    Context "DC Auto-Discovery" {
        It "Should attempt nltest /sc_query for secure channel DC discovery" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'nltest\s+/sc_query'
        }

        It "Should attempt Get-ADDomainController for AllDomainControllers" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Get-ADDomainController\s+-Filter'
        }

        It "Should fall back to nltest /dclist when AD module unavailable" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'nltest\s+/dclist'
        }

        It "Should detect if running on a Domain Controller" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'ProductType\s*-eq\s*2'
        }
    }

    Context "DomainController Implies IncludeCredentialValidation" {
        It "Should enable IncludeCredentialValidation when DomainController is specified" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'if\s*\(\$DomainController\s+-or\s+\$AllDomainControllers\)'
            $content | Should -Match '\$IncludeCredentialValidation\s*=\s*\[switch\]::new\(\$true\)'
        }
    }

    Context "DC Event Parsing" {
        It "Should parse 4768 TGT events from DC with DC name in details" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Kerberos TGT Success.*Kerberos TGT Failed'
            $content | Should -Match 'DC:\s*\$\(\$event\.MachineName\)'
        }

        It "Should parse 4769 service ticket events from DC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Kerberos Service Ticket Success.*Kerberos Service Ticket Failed'
        }

        It "Should parse 4771 pre-auth failures with error descriptions" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Kerberos Pre-auth Failed'
            $content | Should -Match 'Wrong password'
            $content | Should -Match 'Clock skew too large'
        }

        It "Should parse 4776 NTLM events from DC" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'NTLM Credential Validation Success.*NTLM Credential Validation Failed'
        }

        It "Should include DC hostname in parsed event Details" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            # All DC event types should include the DC machine name
            $dcDetailMatches = [regex]::Matches($content, 'DC:\s*\$\(\$event\.MachineName\)')
            $dcDetailMatches.Count | Should -BeGreaterOrEqual 6
        }
    }

    Context "Separate Local and DC Collection" {
        It "Should collect local auth events (4624/4625/4648) separately from DC events" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            # When DC targets exist, local collection should NOT include Kerberos/NTLM
            $content | Should -Match 'Get-RDPAuthenticationEvents.*-IncludeKerberosAndNTLM\s+\$false'
        }

        It "Should fall back to local-only when no DC targets" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'Get-RDPAuthenticationEvents.*-IncludeKerberosAndNTLM\s+\$IncludeCredentialValidation\.IsPresent'
        }
    }

    Context "PowerShell Version Compatibility" {
        It "Should not use PS 7+ only syntax in DC query code" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            # No null-coalescing, null-conditional, pipeline chain, or clean block
            $content | Should -Not -Match '\?\?[^}]'
            $content | Should -Not -Match '\?\.'
            $content | Should -Not -Match '\|\|'
            $content | Should -Not -Match '&&'
        }

        It "Should not use 3-argument Join-Path (PS 5.1 incompatible)" {
            # Verify no Join-Path calls with 3 positional path arguments exist
            # (2-arg Join-Path is fine, only 3+ args breaks PS 5.1)
            $content = Get-Content -Path $script:ScriptPath -Raw
            # Match Join-Path with -Path and -ChildPath and -AdditionalChildPath (PS 7 only syntax)
            $content | Should -Not -Match 'Join-Path\s+-Path\s+\S+\s+-ChildPath\s+\S+\s+-AdditionalChildPath'
        }
    }

    Context "Help Documentation" {
        It "Should document DomainController parameter in help" {
            $help = Get-Help Get-RDPForensics -Parameter DomainController
            $help | Should -Not -BeNullOrEmpty
            $help.Description.Text | Should -Match 'Domain Controller'
        }

        It "Should document AllDomainControllers parameter in help" {
            $help = Get-Help Get-RDPForensics -Parameter AllDomainControllers
            $help | Should -Not -BeNullOrEmpty
            $help.Description.Text | Should -Match 'ALL Domain Controllers'
        }

        It "Should have updated IncludeCredentialValidation help without DC-only constraint" {
            $help = Get-Help Get-RDPForensics -Parameter IncludeCredentialValidation
            $help.Description.Text | Should -Not -Match 'Only use this parameter when.*Running on a Domain Controller'
            $help.Description.Text | Should -Match 'auto-discovers'
        }

        It "Should include DomainController example" {
            $help = Get-Help Get-RDPForensics -Examples
            $helpText = $help | Out-String
            $helpText | Should -Match '-DomainController'
        }

        It "Should include AllDomainControllers example" {
            $help = Get-Help Get-RDPForensics -Examples
            $helpText = $help | Out-String
            $helpText | Should -Match '-AllDomainControllers'
        }
    }

    Context "Header Display" {
        It "Should display DC target info in header when DCs are specified" {
            $content = Get-Content -Path $script:ScriptPath -Raw
            $content | Should -Match 'DC Target\(s\)'
        }
    }
}
