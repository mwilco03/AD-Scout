@{
    RootModule        = 'ADScout.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'AD-Scout Contributors'
    CompanyName       = 'Community'
    Copyright         = '(c) 2025 AD-Scout Contributors. MIT License.'
    Description       = 'PowerShell-native Active Directory security assessment framework. Extensible rules, pluggable reporters, cross-version compatible.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Invoke-ADScoutScan'
        'Get-ADScoutRule'
        'New-ADScoutRule'
        'Register-ADScoutRule'
        'Export-ADScoutReport'
        'Export-ADScoutNISTReport'
        'Get-ADScoutRemediation'
        'Set-ADScoutConfig'
        'Get-ADScoutConfig'
        'Show-ADScoutDashboard'
        'Stop-ADScoutDashboard'
        'Get-ADScoutDashboard'
        'Save-ADScoutBaseline'
        'Update-ADScoutHistory'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'Assessment', 'Compliance', 'MITRE', 'CIS', 'NIST', 'NIST800-53')
            LicenseUri   = 'https://github.com/mwilco03/AD-Scout/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/mwilco03/AD-Scout'
            IconUri      = ''
            ReleaseNotes = @'
## v0.2.0 - Live Dashboard Release
- Added interactive web dashboard using PSP (PowerShell Server Pages)
- Three persona-based views: Auditor, Manager, Technician
- Baseline comparison with trend tracking
- Category breakdown with drill-down
- Framework mapping display (MITRE, CIS, NIST, STIG)
- One-click export to HTML, JSON, CSV, SARIF
- Auto-refresh capability
- API endpoints for programmatic access
- New commands: Stop-ADScoutDashboard, Get-ADScoutDashboard, Save-ADScoutBaseline, Update-ADScoutHistory
'@
            Prerelease   = 'beta'
        }
    }
}
