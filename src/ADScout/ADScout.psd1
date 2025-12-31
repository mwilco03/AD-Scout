@{
    RootModule        = 'ADScout.psm1'
    ModuleVersion     = '0.1.0'
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
        'Get-ADScoutRemediation'
        'Set-ADScoutConfig'
        'Get-ADScoutConfig'
        'Show-ADScoutDashboard'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'Assessment', 'Compliance', 'MITRE', 'CIS')
            LicenseUri   = 'https://github.com/mwilco03/AD-Scout/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/mwilco03/AD-Scout'
            IconUri      = ''
            ReleaseNotes = 'Initial release'
            Prerelease   = 'alpha'
        }
    }
}
