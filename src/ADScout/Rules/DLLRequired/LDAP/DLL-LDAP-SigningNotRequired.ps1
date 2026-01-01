<#
.SYNOPSIS
    Detects Domain Controllers where LDAP signing is not required.

.DESCRIPTION
    Uses protocol-level testing to verify LDAP signing requirements.
    LDAP signing prevents man-in-the-middle attacks on LDAP connections.

.NOTES
    Rule ID    : DLL-LDAP-SigningNotRequired
    Category   : DLLRequired
    Requires   : Native .NET (SMBLibrary optional for enhanced detection)
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-LDAP-SigningNotRequired'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAP Signing Not Required (Protocol-Level Detection)'
    Description = 'LDAP signing is not enforced on Domain Controllers, enabling LDAP relay and man-in-the-middle attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    RequiresDLL     = $false  # Works with native .NET
    FallbackBehavior = 'Continue'

    References  = @(
        @{ Title = 'LDAP Signing Requirements'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements' }
        @{ Title = 'LDAP Relay Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1557')
    }

    CIS   = @('2.3.6.1')
    STIG  = @('V-36435', 'V-14831')
    ANSSI = @('vuln1_ldap_signing')
    NIST  = @('SC-8', 'SC-23')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-LDAPSigningScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.Vulnerable) {
                    $vulnerabilities = @()
                    if ($scanResult.SimpleBindAllowed) { $vulnerabilities += 'Simple Bind Allowed' }
                    if ($scanResult.UnsignedBindAllowed) { $vulnerabilities += 'Unsigned Bind Allowed' }
                    if ($scanResult.AnonymousBindAllowed) { $vulnerabilities += 'Anonymous Bind Allowed' }

                    $findings += [PSCustomObject]@{
                        DomainController       = $dcName
                        OperatingSystem        = $dc.OperatingSystem
                        SigningRequired        = $scanResult.SigningRequired
                        SimpleBindAllowed      = $scanResult.SimpleBindAllowed
                        UnsignedBindAllowed    = $scanResult.UnsignedBindAllowed
                        AnonymousBindAllowed   = $scanResult.AnonymousBindAllowed
                        Vulnerabilities        = ($vulnerabilities -join ', ')
                        RiskLevel              = if ($scanResult.SimpleBindAllowed) { 'Critical' } else { 'High' }
                        AttackVector           = 'LDAP Relay, Credential interception, MITM'
                        DistinguishedName      = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-LDAP-SigningNotRequired: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable LDAP signing requirement via Group Policy.'
        Impact      = 'Medium - May affect legacy applications using simple bind.'
        Script      = {
            param($Finding, $Domain)

            @"
# Enable LDAP Signing Requirement

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Domain controller: LDAP server signing requirements" = "Require signing"
# "Network security: LDAP client signing requirements" = "Require signing"

# Option 2: Configure via Registry (on each DC)
# Server side (require signing)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'LDAPServerIntegrity' -Value 2 -Type DWord

# Client side (require signing)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' `
    -Name 'LDAPClientIntegrity' -Value 2 -Type DWord

# Values:
# 0 = Never require signing
# 1 = Require signing if requested by client
# 2 = Always require signing

# Enable LDAP Channel Binding (Windows Server 2020+)
# This provides additional protection against relay attacks
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord

# Values for LdapEnforceChannelBinding:
# 0 = Disabled
# 1 = Enabled when supported (default starting March 2020)
# 2 = Always required

# Audit before enforcing:
# Set LdapEnforceChannelBinding = 1 and monitor event logs
# Look for Event ID 3039 in Directory Service log

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
    Select-Object LDAPServerIntegrity, LdapEnforceChannelBinding

# Note: Restart of AD DS service or reboot may be required
"@
        }
    }
}
