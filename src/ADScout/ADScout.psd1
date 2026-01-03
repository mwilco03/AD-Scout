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

        # Remediation automation
        'Invoke-ADScoutRemediation'
        'Undo-ADScoutRemediation'
        'Get-ADScoutRemediationHistory'
        'Resume-ADScoutRemediation'
        'Get-ADScoutRemediationQueue'
        'Export-ADScoutRemediationReport'
        'Send-ADScoutRemediationToSIEM'

        # Change management integration
        'Register-ADScoutChangeManagement'
        'Get-ADScoutChangeManagement'
        'New-ADScoutChangeTicket'
        'Update-ADScoutChangeTicket'

        # Notifications
        'Register-ADScoutNotification'
        'Get-ADScoutNotification'
        'Send-ADScoutNotification'

        # Rollback management
        'Set-ADScoutRollbackPolicy'
        'Get-ADScoutRollbackPolicy'
        'Invoke-ADScoutRollbackCleanup'

        # Scope and environment
        'Get-ADScoutRemediationScope'
        'Set-ADScoutRemediationScope'
        'Test-ADScoutEnvironment'

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
