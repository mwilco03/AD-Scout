@{
    Id          = 'S-AdminCount'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Stale AdminCount Attribute on Non-Privileged Accounts'
    Description = 'User accounts have the AdminCount attribute set to 1 but are no longer members of any privileged groups. These accounts retain ACL inheritance blocking from AdminSDHolder but no longer have administrative privileges, creating an inconsistent security state.'
    Severity    = 'Low'
    Weight      = 5
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'AdminSDHolder'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
        @{ Title = 'AdminCount Cleanup'; Url = 'https://adsecurity.org/?p=1906' }
        @{ Title = 'SDProp Process'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals' }
    )

    MITRE = @{
        Tactics    = @('TA0003')  # Persistence
        Techniques = @('T1078.002')  # Valid Accounts: Domain Accounts
    }

    CIS   = @('5.30')
    STIG  = @()
    ANSSI = @('vuln3_admincount')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 1
        MaxPoints = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get list of privileged groups
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Replicator'
        )

        # Get members of all privileged groups
        $privilegedMembers = @{}
        foreach ($groupName in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    $privilegedMembers[$member.SamAccountName] = $true
                }
            } catch { }
        }

        # Check each user with AdminCount = 1
        foreach ($user in $Data) {
            if ($user.AdminCount -eq 1) {
                $accountName = $user.SamAccountName

                # Skip if still privileged
                if ($privilegedMembers.ContainsKey($accountName)) { continue }

                # Skip built-in accounts
                if ($accountName -eq 'Administrator' -or $accountName -eq 'krbtgt') { continue }

                $findings += [PSCustomObject]@{
                    AccountName         = $accountName
                    DistinguishedName   = $user.DistinguishedName
                    AdminCount          = 1
                    IsCurrentlyPrivileged = $false
                    Enabled             = $user.Enabled
                    LastLogon           = $user.LastLogonDate
                    RiskLevel           = 'Low'
                    Issue               = 'AdminCount=1 but not in privileged groups'
                    Impact              = 'ACL inheritance blocked, may have unusual permissions'
                    Recommendation      = 'Clear AdminCount and re-enable inheritance'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Clear the AdminCount attribute and re-enable ACL inheritance on accounts that are no longer members of privileged groups.'
        Impact      = 'Low - May affect any custom permissions set on these accounts. Verify before clearing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Clean Up Stale AdminCount Attributes
# Affected Accounts: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): AdminCount=1, Not in privileged groups" } | Out-String)

# BACKGROUND:
# AdminSDHolder and SDProp process:
# 1. SDProp runs hourly on PDC emulator
# 2. Sets AdminCount=1 on privileged accounts
# 3. Copies ACLs from AdminSDHolder to protect these accounts
# 4. Disables ACL inheritance
#
# When accounts are removed from privileged groups:
# - AdminCount is NOT automatically cleared
# - Inheritance remains disabled
# - Custom permissions may remain

# REMEDIATION:

# Step 1: Verify account is truly not privileged
foreach (`$account in @('$($Finding.Findings.AccountName -join "','")')) {
    `$user = Get-ADUser -Identity `$account -Properties MemberOf
    `$privilegedMembership = `$user.MemberOf | Get-ADGroup | Where-Object {
        `$_.Name -match 'Admins|Operators|Replicator'
    }

    if (`$privilegedMembership) {
        Write-Warning "`$account is still in: `$(`$privilegedMembership.Name -join ', ')"
        continue
    }

    # Step 2: Clear AdminCount
    Set-ADUser -Identity `$account -Clear AdminCount
    Write-Host "Cleared AdminCount for `$account"

    # Step 3: Re-enable ACL inheritance
    `$userDN = (Get-ADUser -Identity `$account).DistinguishedName
    `$acl = Get-Acl "AD:\`$userDN"
    `$acl.SetAccessRuleProtection(`$false, `$true)  # Enable inheritance, keep existing
    Set-Acl "AD:\`$userDN" `$acl
    Write-Host "Re-enabled inheritance for `$account"
}

# AUTOMATED SCRIPT (use with caution):
`$staleAdminCount = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf |
    Where-Object {
        `$privileged = `$_.MemberOf | Get-ADGroup -ErrorAction SilentlyContinue |
            Where-Object { `$_.Name -match 'Admins|Operators|Replicator' }
        -not `$privileged
    }

foreach (`$user in `$staleAdminCount) {
    Write-Host "Cleaning `$(`$user.SamAccountName)..."
    # Set-ADUser -Identity `$user -Clear AdminCount
    # Then re-enable inheritance as above
}

# VERIFY:
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount |
    Select-Object SamAccountName, AdminCount |
    Format-Table

"@
            return $commands
        }
    }
}
