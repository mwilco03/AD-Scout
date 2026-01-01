@{
    Id          = 'P-ServiceAccountPrivileges'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Service Accounts with Excessive Privileges'
    Description = 'Identifies service accounts that are members of privileged groups. Service accounts should use least-privilege and Group Managed Service Accounts (gMSA) where possible.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Group Managed Service Accounts Overview'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
        @{ Title = 'Service Account Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/planning-for-compromise' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.4')
    STIG  = @('V-36434')
    ANSSI = @('vuln2_service_accounts_priv')
    NIST  = @('AC-5', 'AC-6(5)')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 8
    }

    Detect = {
        param($Data, $Domain)

        $privilegedGroupSids = @(
            '*-512'   # Domain Admins
            '*-519'   # Enterprise Admins
            '*-518'   # Schema Admins
            'S-1-5-32-544'  # Administrators
        )

        $serviceAccountPatterns = @(
            '^svc[-_]'
            '[-_]svc$'
            '^service[-_]'
            '[-_]service$'
            '^sql'
            '^iis'
            '^app[-_]'
        )

        $findings = @()

        foreach ($user in $Data) {
            # Check if this looks like a service account
            $isServiceAccount = $false
            foreach ($pattern in $serviceAccountPatterns) {
                if ($user.SamAccountName -match $pattern) {
                    $isServiceAccount = $true
                    break
                }
            }

            # Also check ServicePrincipalName
            if ($user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0) {
                $isServiceAccount = $true
            }

            if ($isServiceAccount) {
                # Check if member of privileged groups
                $privilegedMemberships = @()
                foreach ($groupSid in $user.MemberOfSids) {
                    foreach ($privPattern in $privilegedGroupSids) {
                        if ($groupSid -like $privPattern) {
                            $privilegedMemberships += $groupSid
                        }
                    }
                }

                if ($privilegedMemberships.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        SamAccountName      = $user.SamAccountName
                        DisplayName         = $user.DisplayName
                        PrivilegedGroups    = $privilegedMemberships -join ', '
                        SPNs                = ($user.ServicePrincipalName -join ', ')
                        PasswordLastSet     = $user.PasswordLastSet
                        Enabled             = $user.Enabled
                        DistinguishedName   = $user.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove service accounts from privileged groups. Migrate to Group Managed Service Accounts (gMSA) where possible. Implement least-privilege access.'
        Impact      = 'High - Services may fail if permissions are removed without proper planning'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Service accounts with excessive privileges detected

# Recommended approach:
# 1. Document what services use each account
# 2. Determine minimum required permissions
# 3. Create gMSA replacements where possible
# 4. Test in non-production first

# To create a gMSA:
# New-ADServiceAccount -Name 'gMSA_ServiceName' -DNSHostName 'gMSA_ServiceName.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup'

# Affected service accounts:
"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName)
# Current privileged groups: $($item.PrivilegedGroups)
# SPNs: $($item.SPNs)

"@
            }
            return $commands
        }
    }
}
