<#
.SYNOPSIS
    Detects Domain Controllers with LDAP channel binding disabled.

.DESCRIPTION
    Checks if LDAP channel binding is enforced. Channel binding provides
    additional protection against LDAP relay attacks beyond signing.

.NOTES
    Rule ID    : DLL-LDAP-ChannelBindingDisabled
    Category   : DLLRequired
    Requires   : Native .NET
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-LDAP-ChannelBindingDisabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAP Channel Binding Not Enforced'
    Description = 'LDAP channel binding is not enforced on Domain Controllers, leaving them vulnerable to sophisticated LDAP relay attacks.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'DomainControllers'

    RequiresDLL     = $false
    FallbackBehavior = 'Continue'

    References  = @(
        @{ Title = 'LDAP Channel Binding'; Url = 'https://support.microsoft.com/kb4034879' }
        @{ Title = 'March 2020 LDAP Update'; Url = 'https://support.microsoft.com/kb4520412' }
        @{ Title = 'CVE-2017-8563'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-8563' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1557')
    }

    CIS   = @('2.3.6.2')
    STIG  = @('V-73677')
    NIST  = @('SC-8', 'SC-23')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
        Maximum = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                # Check registry for channel binding setting
                $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                $channelBinding = $null

                if ($dcName -eq $env:COMPUTERNAME) {
                    $channelBinding = Get-ItemProperty -Path $regPath -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty LdapEnforceChannelBinding
                } else {
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
                        $key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
                        if ($key) {
                            $channelBinding = $key.GetValue('LdapEnforceChannelBinding')
                            $key.Close()
                        }
                        $reg.Close()
                    } catch {
                        $channelBinding = $null
                    }
                }

                # Channel binding values:
                # 0 = Disabled (vulnerable)
                # 1 = When supported (default since March 2020)
                # 2 = Always required (most secure)

                if ($null -eq $channelBinding -or $channelBinding -lt 2) {
                    $status = switch ($channelBinding) {
                        0 { 'Disabled' }
                        1 { 'When Supported' }
                        $null { 'Not Configured (default)' }
                        default { "Unknown ($channelBinding)" }
                    }

                    $findings += [PSCustomObject]@{
                        DomainController       = $dcName
                        OperatingSystem        = $dc.OperatingSystem
                        ChannelBindingValue    = $channelBinding
                        ChannelBindingStatus   = $status
                        RequiredValue          = 2
                        RiskLevel              = if ($channelBinding -eq 0) { 'High' } else { 'Medium' }
                        Impact                 = 'LDAP relay attacks possible'
                        DistinguishedName      = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-LDAP-ChannelBindingDisabled: Error checking $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable LDAP channel binding via registry or Group Policy.'
        Impact      = 'Medium - May affect legacy LDAP clients that don''t support channel binding.'
        Script      = {
            param($Finding, $Domain)

            @"
# Enable LDAP Channel Binding

# Channel binding values:
# 0 = Never (disabled, vulnerable)
# 1 = When supported by client (default since March 2020)
# 2 = Always required (recommended)

# IMPORTANT: Before enforcing (value 2), audit first to identify
# clients that don't support channel binding.

# Step 1: Enable auditing (recommended first step)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'LdapEnforceChannelBinding' -Value 1 -Type DWord

# Monitor Event ID 3039 in Directory Service log for failures

# Step 2: After verifying clients are compatible, enforce:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord

# Via Group Policy:
# Use ADMX templates for domain controller LDAP settings
# "Domain controller: LDAP server channel binding token requirements" = "Always"

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
    Select-Object LdapEnforceChannelBinding

# Check for binding failures:
Get-WinEvent -FilterHashtable @{
    LogName = 'Directory Service'
    ID = 3039
} -MaxEvents 10 -ErrorAction SilentlyContinue
"@
        }
    }
}
