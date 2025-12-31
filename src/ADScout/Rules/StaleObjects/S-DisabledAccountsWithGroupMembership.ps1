@{
    Id          = 'S-DisabledAccountsWithGroupMembership'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Disabled Accounts with Group Memberships'
    Description = 'Identifies disabled accounts that still have group memberships. If re-enabled, these accounts immediately gain all previous permissions.'
    Severity    = 'Low'
    Weight      = 10
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Account Deprovisioning Best Practices'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-restore' }
    )

    MITRE = @{
        Tactics    = @('TA0003')  # Persistence
        Techniques = @('T1098')   # Account Manipulation
    }

    CIS   = @('5.20')
    STIG  = @()
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 2
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($user in $Data) {
            if (-not $user.Enabled -and $user.MemberOf -and $user.MemberOf.Count -gt 1) {
                # Count privileged group memberships
                $privilegedGroups = @()
                foreach ($group in $user.MemberOf) {
                    if ($group -match 'Admin|Operator|Manager|Enterprise|Schema|Domain Controllers') {
                        $privilegedGroups += $group
                    }
                }

                $findings += [PSCustomObject]@{
                    SamAccountName     = $user.SamAccountName
                    DisplayName        = $user.DisplayName
                    Enabled            = $user.Enabled
                    GroupCount         = $user.MemberOf.Count
                    PrivilegedGroups   = ($privilegedGroups -join ', ')
                    HasPrivilegedAccess = ($privilegedGroups.Count -gt 0)
                    WhenDisabled       = $user.Modified
                    DistinguishedName  = $user.DistinguishedName
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove group memberships from disabled accounts or delete accounts if no longer needed. This prevents privilege restoration if accounts are re-enabled.'
        Impact      = 'None - Accounts are already disabled'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Disabled accounts with residual group memberships
# Remove memberships to prevent privilege restoration if re-enabled

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Account: $($item.SamAccountName) (Disabled)
# Group memberships: $($item.GroupCount)
# Privileged groups: $($item.PrivilegedGroups)

# Remove all group memberships:
Get-ADUser -Identity '$($item.SamAccountName)' -Properties MemberOf |
    ForEach-Object {
        `$_.MemberOf | ForEach-Object {
            Remove-ADGroupMember -Identity `$_ -Members '$($item.SamAccountName)' -Confirm:`$false
        }
    }

"@
            }

            $commands += @"


# Bulk cleanup - remove all disabled users from groups:

# Get-ADUser -Filter 'Enabled -eq `$false' -Properties MemberOf |
#     Where-Object { `$_.MemberOf.Count -gt 1 } |
#     ForEach-Object {
#         `$user = `$_
#         `$_.MemberOf | Where-Object { `$_ -ne `$user.PrimaryGroup } | ForEach-Object {
#             Remove-ADGroupMember -Identity `$_ -Members `$user -Confirm:`$false
#         }
#     }
"@
            return $commands
        }
    }
}
