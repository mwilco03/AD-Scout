@{
    Id          = 'P-AdminNum'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Excessive Number of Domain Administrators'
    Description = 'Detects when the number of Domain Admins exceeds recommended thresholds. Too many privileged accounts increase attack surface and make credential management difficult.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Least Privilege Administration'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models' }
        @{ Title = 'Tiered Administration'; Url = 'https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model' }
        @{ Title = 'PingCastle Rule P-AdminNum'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1078.002', 'T1003')  # Domain Accounts, OS Credential Dumping
    }

    CIS   = @()  # CIS recommends limiting admin accounts but no specific control number
    STIG  = @()  # No specific STIG for admin count threshold
    ANSSI = @()
    NIST  = @('AC-2', 'AC-6')  # Account Management, Least Privilege

    Scoring = @{
        Type      = 'ThresholdBased'
        Threshold = 5
        Points    = 2
        MaxPoints = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Thresholds
        $warningThreshold = 5     # Warning if more than 5 Domain Admins
        $criticalThreshold = 10   # Critical if more than 10 Domain Admins

        # Groups to check
        $privilegedGroups = @(
            @{ Name = 'Domain Admins'; RID = 512; Description = 'Full domain control' }
            @{ Name = 'Enterprise Admins'; RID = 519; Description = 'Full forest control' }
            @{ Name = 'Administrators'; RID = 544; Description = 'Built-in administrators' }
        )

        try {
            foreach ($groupInfo in $privilegedGroups) {
                $group = $Data.Groups | Where-Object {
                    $_.Name -eq $groupInfo.Name -or
                    $_.SamAccountName -eq $groupInfo.Name -or
                    ($_.SID -and $_.SID -match "-$($groupInfo.RID)$")
                } | Select-Object -First 1

                if (-not $group) {
                    # Try to find directly
                    try {
                        $rootDSE = [ADSI]"LDAP://RootDSE"
                        $defaultNC = $rootDSE.defaultNamingContext.ToString()

                        $searchBase = if ($groupInfo.RID -ge 500 -and $groupInfo.RID -le 600) {
                            "CN=Builtin,$defaultNC"
                        } else {
                            "CN=Users,$defaultNC"
                        }

                        $searcher = New-Object DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = [ADSI]"LDAP://$searchBase"
                        $searcher.Filter = "(&(objectClass=group)(cn=$($groupInfo.Name)))"
                        $searcher.PropertiesToLoad.AddRange(@('member', 'distinguishedName'))

                        $result = $searcher.FindOne()
                        if ($result) {
                            $group = @{
                                Name = $groupInfo.Name
                                DistinguishedName = $result.Properties['distinguishedname'][0]
                                Members = $result.Properties['member']
                            }
                        }
                    } catch { continue }
                }

                if (-not $group) { continue }

                # Count members (including nested)
                $members = @()
                $directMembers = @()

                if ($group.Members) {
                    $directMembers = @($group.Members | Where-Object { $_ })
                } elseif ($group.member) {
                    $directMembers = @($group.member | Where-Object { $_ })
                }

                # Get all members including nested (recursively)
                $allMembers = @()
                try {
                    $allMembers = Get-ADGroupMember -Identity $groupInfo.Name -Recursive -ErrorAction SilentlyContinue |
                        Where-Object { $_.objectClass -eq 'user' }
                } catch {
                    $allMembers = $directMembers
                }

                $memberCount = @($allMembers).Count
                $directMemberCount = @($directMembers).Count

                # Count enabled vs disabled
                $enabledCount = 0
                $disabledCount = 0
                $serviceAccountCount = 0

                foreach ($member in $allMembers) {
                    if ($member.Enabled -eq $false) {
                        $disabledCount++
                    } else {
                        $enabledCount++
                    }

                    if ($member.SamAccountName -match '^svc|^service|_svc$') {
                        $serviceAccountCount++
                    }
                }

                if ($memberCount -gt $warningThreshold) {
                    $severity = 'Medium'
                    if ($memberCount -gt $criticalThreshold) {
                        $severity = 'High'
                    }

                    $findings += [PSCustomObject]@{
                        GroupName           = $groupInfo.Name
                        Description         = $groupInfo.Description
                        TotalMembers        = $memberCount
                        DirectMembers       = $directMemberCount
                        EnabledMembers      = $enabledCount
                        DisabledMembers     = $disabledCount
                        ServiceAccounts     = $serviceAccountCount
                        WarningThreshold    = $warningThreshold
                        CriticalThreshold   = $criticalThreshold
                        Severity            = $severity
                        Risk                = "$memberCount members in $($groupInfo.Name)"
                        Impact              = 'Large attack surface for privileged credential theft'
                        Recommendation      = 'Reduce membership and implement least privilege'
                    }
                }
            }

            # Additional check: Users with AdminCount=1 but not in admin groups
            $adminCountUsers = @($Data.Users | Where-Object {
                ($_.AdminCount -eq 1 -or $_.adminCount -eq 1) -and
                ($_.Enabled -eq $true -or -not ($_.userAccountControl -band 2))
            })

            if ($adminCountUsers.Count -gt $criticalThreshold * 2) {
                $findings += [PSCustomObject]@{
                    Finding             = 'Excessive AdminCount=1 accounts'
                    Count               = $adminCountUsers.Count
                    Severity            = 'Medium'
                    Risk                = 'Many accounts have AdminCount=1 (SDProp protected)'
                    Impact              = 'May indicate privilege creep or orphaned accounts'
                    Recommendation      = 'Review and clean up AdminCount=1 accounts'
                }
            }

        } catch {
            Write-Verbose "P-AdminNum: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and reduce privileged group membership. Implement role-based access control and use dedicated admin accounts only when needed.'
        Impact      = 'Medium - Requires identifying legitimate admin needs. May require workflow changes for users losing privileges.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Excessive Admin Accounts Remediation
#
# Issues found:
$($Finding.Findings | ForEach-Object { "# - $($_.GroupName): $($_.TotalMembers) members (threshold: $($_.WarningThreshold))" } | Out-String)

# Best practices:
# - Domain Admins: 2-5 members (minimum viable)
# - Enterprise Admins: Usually empty (used only for forest operations)
# - Administrators: Same as Domain Admins

# STEP 1: Review current membership
`$privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins')

foreach (`$groupName in `$privilegedGroups) {
    Write-Host "`n=== `$groupName ===" -ForegroundColor Yellow
    Get-ADGroupMember -Identity `$groupName -Recursive |
        Where-Object { `$_.objectClass -eq 'user' } |
        ForEach-Object {
            `$user = Get-ADUser `$_.SamAccountName -Properties LastLogonDate, PasswordLastSet, Description
            [PSCustomObject]@{
                Name = `$user.Name
                SamAccountName = `$user.SamAccountName
                Enabled = `$user.Enabled
                LastLogon = `$user.LastLogonDate
                PasswordAge = if (`$user.PasswordLastSet) { ((Get-Date) - `$user.PasswordLastSet).Days } else { 'Unknown' }
                Description = `$user.Description
            }
        } | Format-Table -AutoSize
}

# STEP 2: Identify accounts to remove
Write-Host @"

CRITERIA FOR REMOVAL:
1. Inactive accounts (no logon in 90+ days)
2. Accounts without business justification
3. Generic/shared accounts
4. Service accounts (should use gMSA instead)
5. Duplicate accounts (same person multiple accounts)

"@ -ForegroundColor Cyan

# Find inactive Domain Admins
Write-Host "Inactive Domain Admins (no logon in 90 days):" -ForegroundColor Yellow
Get-ADGroupMember "Domain Admins" -Recursive |
    Where-Object { `$_.objectClass -eq 'user' } |
    ForEach-Object { Get-ADUser `$_ -Properties LastLogonDate } |
    Where-Object { `$_.LastLogonDate -lt (Get-Date).AddDays(-90) -or `$_.LastLogonDate -eq `$null } |
    Select-Object Name, SamAccountName, LastLogonDate

# STEP 3: Remove unnecessary members
# Example - remove specific user:
# Remove-ADGroupMember -Identity "Domain Admins" -Members "username" -Confirm:`$false

# STEP 4: Implement tiered administration
Write-Host @"

TIERED ADMINISTRATION MODEL:
Tier 0: Domain Controllers, AD, PKI, Privileged Identity Management
        - Only Tier 0 admins can log into these systems
        - Separate accounts from Tier 1/2

Tier 1: Servers (member servers, databases, applications)
        - Tier 1 admin accounts for server management
        - Cannot access Tier 0

Tier 2: Workstations and devices
        - Help desk, desktop support
        - Cannot access Tier 0 or Tier 1

"@ -ForegroundColor Cyan

# STEP 5: Create dedicated admin accounts
# Naming convention: a-username (for admin accounts)
# Example:
# New-ADUser -Name "a-jsmith" -SamAccountName "a-jsmith" -Description "Admin account for John Smith"
# Add-ADGroupMember -Identity "Domain Admins" -Members "a-jsmith"

# STEP 6: Implement Privileged Access Workstations (PAWs)
# Domain admin accounts should only be used from PAWs
# - Hardened workstations
# - No internet access
# - No email
# - GPO restrictions

# STEP 7: Use Just-In-Time administration
# Azure AD PIM or MIM PAM for:
# - Time-limited group membership
# - Approval workflows
# - Audit trails

# STEP 8: Clean up AdminCount orphans
Write-Host "`nAccounts with AdminCount=1 not in admin groups:" -ForegroundColor Yellow
`$adminGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators')
`$adminMembers = `$adminGroups | ForEach-Object {
    Get-ADGroupMember `$_ -Recursive -ErrorAction SilentlyContinue
} | Select-Object -Unique -ExpandProperty SamAccountName

Get-ADUser -Filter { AdminCount -eq 1 } |
    Where-Object { `$_.SamAccountName -notin `$adminMembers } |
    Select-Object Name, SamAccountName

# To clear AdminCount (run as Enterprise Admin):
# Get-ADUser -Filter { AdminCount -eq 1 } |
#     Where-Object { `$_.SamAccountName -notin `$adminMembers } |
#     Set-ADUser -Clear AdminCount

"@
            return $commands
        }
    }
}
