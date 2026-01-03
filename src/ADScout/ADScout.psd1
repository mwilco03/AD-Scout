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

    # Optional modules - loaded on demand when features are used
    # ActiveDirectory: Required for AD cmdlet-based collection (falls back to ADSI if unavailable)
    # GroupPolicy: Required for GPO scanning features
    # Microsoft.Graph.*: Required for Entra ID/Microsoft Graph integration
    # Note: These are not hard requirements - the module degrades gracefully if unavailable

    FunctionsToExport = @(
        # Core scanning
        'Invoke-ADScoutScan'
        'Get-ADScoutRule'
        'New-ADScoutRule'
        'Register-ADScoutRule'

        # Reporting
        'Export-ADScoutReport'
        'Export-ADScoutNISTReport'
        'Get-ADScoutRemediation'
        'Show-ADScoutDashboard'

        # Configuration
        'Set-ADScoutConfig'
        'Get-ADScoutConfig'

        # Microsoft Graph / Entra ID
        'Connect-ADScoutGraph'
        'Disconnect-ADScoutGraph'
        'Test-ADScoutGraphConnection'

        # Baseline storage
        'Export-ADScoutBaseline'
        'Import-ADScoutBaseline'
        'Compare-ADScoutBaseline'

        # CSV helpers
        'ConvertFrom-ADScoutCSV'
        'ConvertTo-ADScoutCSV'
        'Test-ADScoutCSVEncoding'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'Assessment', 'Compliance', 'MITRE', 'CIS', 'NIST', 'NIST800-53', 'EntraID', 'AzureAD', 'MicrosoftGraph')
            LicenseUri   = 'https://github.com/mwilco03/AD-Scout/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/mwilco03/AD-Scout'
            IconUri      = ''
            ReleaseNotes = 'Initial release'
            Prerelease   = 'alpha'
        }
    }
}
