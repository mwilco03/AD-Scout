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

        # SIEM Integrations
        'Export-ADScoutElasticsearch'
        'New-ADScoutElasticsearchIndex'
        'Export-ADScoutSplunk'
        'Test-ADScoutSplunkConnection'
        'Export-ADScoutSentinel'
        'New-ADScoutSentinelAnalyticsRule'
        'Test-ADScoutSentinelConnection'

        # Configuration
        'Set-ADScoutConfig'
        'Get-ADScoutConfig'

        # Microsoft Graph / Entra ID
        'Connect-ADScoutGraph'
        'Disconnect-ADScoutGraph'
        'Test-ADScoutGraphConnection'

        # EDR Integration
        'Connect-ADScoutEDR'
        'Disconnect-ADScoutEDR'
        'Test-ADScoutEDRConnection'
        'Switch-ADScoutEDRConnection'
        'Get-ADScoutEDRConnection'
        'Invoke-ADScoutEDRCommand'
        'Invoke-ADScoutEDRCollection'
        'Get-ADScoutEDRHost'
        'Get-ADScoutEDRCapabilities'
        'Get-ADScoutEDRProvider'
        'Get-ADScoutEDRTemplate'

        # Baseline storage
        'Export-ADScoutBaseline'
        'Import-ADScoutBaseline'
        'Compare-ADScoutBaseline'

        # Scan history / trend tracking
        'Save-ADScoutScanHistory'
        'Get-ADScoutScanHistory'

        # Engagement Management
        'New-ADScoutEngagement'
        'Get-ADScoutEngagement'
        'Set-ADScoutEngagement'
        'Remove-ADScoutEngagement'
        'Invoke-ADScoutEngagementScan'
        'Get-ADScoutEngagementScans'

        # Exception Management
        'New-ADScoutException'
        'Get-ADScoutException'
        'Set-ADScoutException'
        'Remove-ADScoutException'
        'Test-ADScoutException'
        'Invoke-ADScoutExceptionCleanup'
        'Get-ADScoutExceptionReport'

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
            Tags         = @('ActiveDirectory', 'Security', 'Audit', 'Assessment', 'Compliance', 'MITRE', 'CIS', 'NIST', 'NIST800-53', 'EntraID', 'AzureAD', 'MicrosoftGraph', 'EDR', 'CrowdStrike', 'PSFalcon', 'DefenderATP', 'MDE', 'RemoteExecution')
            LicenseUri   = 'https://github.com/mwilco03/AD-Scout/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/mwilco03/AD-Scout'
            IconUri      = ''
            ReleaseNotes = 'Initial release'
            Prerelease   = 'alpha'
        }
    }
}
