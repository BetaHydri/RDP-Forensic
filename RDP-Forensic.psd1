@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'RDP-Forensic.psm1'
    
    # Version number of this module.
    ModuleVersion        = '1.0.5'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # ID used to uniquely identify this module
    GUID                 = 'a8f3d2c1-5b4e-4a9d-8c7f-1e2d3a4b5c6d'
    
    # Author of this module
    Author               = 'Jan Tiedemann'
    
    # Company or vendor of this module
    CompanyName          = 'BetaHydri'
    
    # Copyright statement for this module
    Copyright            = '(c) 2025 Jan Tiedemann. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description          = 'Comprehensive PowerShell toolkit for analyzing and tracking Remote Desktop Protocol (RDP) connections in Windows environments. Provides forensic analysis, real-time monitoring, and detailed reporting of RDP activities across multiple Windows Event Log sources.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '5.1'
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @('Get-RDPForensics', 'Get-CurrentRDPSessions')
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()
    
    # Variables to export from this module
    VariablesToExport    = @()
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('RDP', 'Forensics', 'Security', 'EventLog', 'RemoteDesktop', 'Audit', 'Compliance', 'Monitoring', 'Windows', 'Investigation')
            
            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/BetaHydri/RDP-Forensic/blob/main/LICENSE'
            
            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/BetaHydri/RDP-Forensic'
            
            # A URL to an icon representing this module.
            # IconUri = ''
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.0.0 (2025-12-09)
- Initial release
- Comprehensive RDP connection lifecycle tracking
- Multi-source event log correlation (5 log sources)
- 15+ Event IDs monitoring
- Real-time session monitoring
- Brute force attack detection
- CSV export with summary reports
- Advanced filtering (username, IP, date range)
- Outbound connection tracking
- 10 ready-to-use example scenarios
- Complete test suite with Pester
'@
            
            # Prerelease string of this module
            # Prerelease = ''
            
            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false
            
            # External dependent modules of this module
            # ExternalModuleDependencies = @()
        }
    }
    
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
