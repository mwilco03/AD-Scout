<#
.SYNOPSIS
    Detects anonymous LSA RPC access on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary to detect if anonymous users can query LSA
    for domain information and trust relationships.

.NOTES
    Rule ID    : DLL-RPC-LSAAnonymous
    Category   : DLLRequired
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-RPC-LSAAnonymous'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Anonymous LSA Queries Allowed'
    Description = 'Anonymous users can query LSA for domain information and trust relationships, enabling reconnaissance.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll', 'RPCForSMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'LSA Enumeration'; Url = 'https://attack.mitre.org/techniques/T1482/' }
        @{ Title = 'Restrict Anonymous Access'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1482')   # Domain Trust Discovery
    }

    CIS   = @('2.3.10.4')
    STIG  = @('V-73675')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
        Maximum = 50
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-RPC-LSAAnonymous: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-LSAScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.Vulnerable) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        LSAPipeAccessible     = $scanResult.LSAPipeAccessible
                        DomainInfoAccess      = $scanResult.DomainInfoAccess
                        TrustEnumeration      = $scanResult.TrustEnumeration
                        TrustCount            = ($scanResult.Trusts | Measure-Object).Count
                        PolicyAccess          = $scanResult.PolicyAccess
                        RiskLevel             = if ($scanResult.TrustEnumeration) { 'High' } else { 'Medium' }
                        AttackVector          = 'Trust enumeration, Domain reconnaissance'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-RPC-LSAAnonymous: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict anonymous LSA access via Group Policy.'
        Impact      = 'Low - Legitimate applications should authenticate.'
        Script      = {
            param($Finding, $Domain)

            @"
# Restrict Anonymous LSA Access

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled

# Option 2: Configure via Registry
# Restrict anonymous access
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymous' -Value 2 -Type DWord

# Clear named pipes accessible to null sessions
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'NullSessionPipes' -Value @() -Type MultiString

# Restrict null session access
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'RestrictNullSessAccess' -Value 1 -Type DWord

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object RestrictAnonymous
"@
        }
    }
}
