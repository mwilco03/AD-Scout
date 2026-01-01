@{
    Id          = 'P-PrivilegedGroupMembership'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Excessive Privileged Group Membership'
    Description = 'Identifies domains with an excessive number of members in highly privileged groups (Domain Admins, Enterprise Admins, Schema Admins). Large privileged groups increase attack surface.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Best Practices for Securing Active Directory'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'Reducing the Active Directory Attack Surface'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface' }
    )

    MITRE = @{
        Tactics    = @('TA0004')  # Privilege Escalation
        Techniques = @('T1078.002')  # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.2', '5.3')
    STIG  = @('V-36433')
    ANSSI = @('vuln1_privileged_members')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $privilegedGroups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
        )

        $findings = @()
        $thresholds = @{
            'Domain Admins'     = 5
            'Enterprise Admins' = 3
            'Schema Admins'     = 2
            'Administrators'    = 10
        }

        foreach ($group in $Data) {
            $groupName = $group.Name

            if ($groupName -in $privilegedGroups) {
                $memberCount = ($group.Members | Measure-Object).Count
                $threshold = $thresholds[$groupName]

                if ($memberCount -gt $threshold) {
                    $findings += [PSCustomObject]@{
                        GroupName       = $groupName
                        MemberCount     = $memberCount
                        Threshold       = $threshold
                        ExcessCount     = $memberCount - $threshold
                        Members         = ($group.Members | Select-Object -First 20) -join ', '
                        DistinguishedName = $group.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and reduce privileged group membership. Implement Just-In-Time (JIT) access and Privileged Access Workstations (PAWs).'
        Impact      = 'Medium - Users removed from groups will lose administrative access'
        Script      = {
            param($Finding, $Domain)

            $commands = @()
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Review members of $($item.GroupName) - Currently has $($item.MemberCount) members (threshold: $($item.Threshold))
# List current members:

Get-ADGroupMember -Identity '$($item.GroupName)' | Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize

# To remove a user from the group:
# Remove-ADGroupMember -Identity '$($item.GroupName)' -Members '<SamAccountName>' -Confirm:`$false
"@
            }
            return $commands -join "`n"
        }
    }
}
