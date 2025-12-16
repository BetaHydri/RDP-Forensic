# RDP Forensics Module Loader
# Version: 1.0.8
# Author: Jan Tiedemann
# Import this to load all functions as cmdlets

# Get script directory
$ModulePath = $PSScriptRoot

# Import main forensics function
. "$ModulePath\Get-RDPForensics.ps1"

# Import session monitoring function
. "$ModulePath\Get-CurrentRDPSessions.ps1"

# Export functions
Export-ModuleMember -Function @(
    'Get-RDPForensics',
    'Get-CurrentRDPSessions'
)

Write-Host "RDP Forensics Module loaded successfully!" -ForegroundColor Green
Write-Host "Available commands:" -ForegroundColor Cyan
Write-Host "  - Get-RDPForensics" -ForegroundColor Gray
Write-Host "  - Get-CurrentRDPSessions" -ForegroundColor Gray
Write-Host "`nUse Get-Help <command> -Detailed for more information" -ForegroundColor Yellow
