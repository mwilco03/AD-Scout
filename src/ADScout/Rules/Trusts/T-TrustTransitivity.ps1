@{
    Id          = 'T-TrustTransitivity'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'Transitive External Trusts'
    Description = 'Detects external trusts that are transitive. External trusts should generally be non-transitive to limit lateral movement paths between forests.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Trusts'

    References  = @(
        @{ Title = 'Understanding Trust Direction'; Url = 'https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust' }
        @{ Title = 'Security Considerations for Trusts'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack' }
    )

    MITRE = @{
        Tactics    = @('TA0008')  # Lateral Movement
        Techniques = @('T1482')   # Domain Trust Discovery
    }

    CIS   = @('5.6')
    STIG  = @('V-36438')
    ANSSI = @('vuln2_trusts_transitivity')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($trust in $Data) {
            # Check if external trust and transitive
            if ($trust.TrustType -eq 'External' -and
                $trust.TrustAttributes -band 0x00000001) {  # TRUST_ATTRIBUTE_NON_TRANSITIVE is NOT set

                $findings += [PSCustomObject]@{
                    TrustedDomain     = $trust.Target
                    TrustDirection    = $trust.Direction
                    TrustType         = $trust.TrustType
                    TrustAttributes   = $trust.TrustAttributes
                    IsTransitive      = $true
                    WhenCreated       = $trust.WhenCreated
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reconfigure external trusts to be non-transitive where business requirements allow. If transitivity is required, implement SID filtering and selective authentication.'
        Impact      = 'High - May affect cross-domain resource access'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Transitive external trusts detected
# These should be reviewed and made non-transitive where possible

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Trust: $($item.TrustedDomain)
# To make non-transitive (requires recreation):
# 1. Document all resources accessed across trust
# 2. Remove trust: Remove-ADObject -Identity 'CN=$($item.TrustedDomain),CN=System,$((Get-ADDomain).DistinguishedName)'
# 3. Recreate as non-transitive:
# netdom trust $env:USERDNSDOMAIN /domain:$($item.TrustedDomain) /add /transitive:no

"@
            }
            return $commands
        }
    }
}
