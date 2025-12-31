@{
    Id          = 'T-SelectiveAuthDisabled'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'Selective Authentication Not Enabled'
    Description = 'Detects forest trusts without selective authentication. Without selective authentication, all users from trusted forests can authenticate to all resources.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Trusts'

    References  = @(
        @{ Title = 'Selective Authentication'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/forest-trust-types' }
        @{ Title = 'Understanding When to Use Selective Authentication'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.8')
    STIG  = @('V-36440')
    ANSSI = @('vuln2_trusts_selectiveauth')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($trust in $Data) {
            # TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010 indicates selective auth
            $selectiveAuthEnabled = ($trust.TrustAttributes -band 0x00000010) -ne 0
            $isForestTrust = ($trust.TrustAttributes -band 0x00000008) -ne 0

            if ($isForestTrust -and -not $selectiveAuthEnabled) {
                $findings += [PSCustomObject]@{
                    TrustedDomain           = $trust.Target
                    TrustDirection          = $trust.Direction
                    SelectiveAuthentication = 'Disabled'
                    Risk                    = 'All users from trusted forest can access resources'
                    WhenCreated             = $trust.WhenCreated
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable selective authentication on forest trusts. This requires explicit permission grants on resources for trusted forest users.'
        Impact      = 'High - Users from trusted forests will lose access until explicitly granted'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Enable selective authentication on forest trusts
# WARNING: This will require reconfiguring resource permissions

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Enable selective authentication for: $($item.TrustedDomain)
# Using Active Directory Domains and Trusts:
# 1. Right-click the domain, select Properties
# 2. Click the Trusts tab
# 3. Select the trust and click Properties
# 4. Select 'Selective Authentication'

# Or using netdom:
netdom trust $env:USERDNSDOMAIN /domain:$($item.TrustedDomain) /SelectiveAuth:yes

# After enabling, grant 'Allowed to Authenticate' permission on specific servers

"@
            }
            return $commands
        }
    }
}
