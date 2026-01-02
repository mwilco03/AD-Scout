@{
    Id          = 'P-OperatorsEmpty'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Operator Groups Not Empty'
    Description = 'Detects when Account Operators or Server Operators groups have members. These groups have significant privileges that can lead to domain compromise and should be empty in secure environments.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Operator Group Risks'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
        @{ Title = 'Account Operators Abuse'; Url = 'https://adsecurity.org/?p=3658' }
        @{ Title = 'PingCastle Rule P-OperatorsEmpty'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1078.002', 'T1098')  # Valid Accounts: Domain, Account Manipulation
    }

    CIS   = @()  # Operator group guidance varies by CIS benchmark version
    STIG  = @()  # Privileged group STIGs are AD-version specific
    ANSSI = @()
    NIST  = @('AC-2', 'AC-6')  # Account Management, Least Privilege

    Scoring = @{
        Type      = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Operator groups that should be empty
        $operatorGroups = @{
            'Account Operators' = @{
                RID = 548
                Risk = 'Can create/modify most user and group accounts, can log on to DCs'
                Capability = 'Create users, reset passwords, modify group membership (except protected groups)'
            }
            'Server Operators' = @{
                RID = 549
                Risk = 'Can log on to DCs, manage services, and access files'
                Capability = 'Log on locally to DCs, backup/restore files, manage services, shutdown DCs'
            }
            'Backup Operators' = @{
                RID = 551
                Risk = 'Can backup and restore files, bypassing ACLs'
                Capability = 'Read any file (backup privilege), restore files to overwrite (SeRestorePrivilege)'
            }
            'Print Operators' = @{
                RID = 550
                Risk = 'Can log on to DCs and load printer drivers (code execution)'
                Capability = 'Log on to DCs, install printer drivers (potential for malicious drivers)'
            }
        }

        try {
            foreach ($groupName in $operatorGroups.Keys) {
                $groupInfo = $operatorGroups[$groupName]

                # Try to find the group in collected data
                $group = $Data.Groups | Where-Object {
                    $_.Name -eq $groupName -or
                    $_.SamAccountName -eq $groupName -or
                    ($_.SID -and $_.SID.ToString() -match "-$($groupInfo.RID)$")
                } | Select-Object -First 1

                $members = @()

                if ($group) {
                    if ($group.Members) {
                        $members = @($group.Members)
                    }
                } else {
                    # Try via ADSI
                    try {
                        $domainDN = $Domain.DistinguishedName
                        $groupDN = "CN=$groupName,CN=Builtin,$domainDN"
                        $adsiGroup = [ADSI]"LDAP://$groupDN"

                        if ($adsiGroup.Member) {
                            $members = @($adsiGroup.Member)
                        }
                    } catch {
                        # Group might not exist or can't be accessed
                    }
                }

                if ($members.Count -gt 0) {
                    $memberNames = @()
                    foreach ($member in $members) {
                        if ($member -is [string]) {
                            # DN format
                            $memberName = ($member -split ',')[0] -replace 'CN=', ''
                            $memberNames += $memberName
                        } else {
                            $memberNames += $member.ToString()
                        }
                    }

                    # Determine severity based on group
                    $severity = 'High'
                    if ($groupName -eq 'Account Operators') {
                        $severity = 'Critical'  # Can create accounts and escalate
                    }

                    $findings += [PSCustomObject]@{
                        GroupName           = $groupName
                        MemberCount         = $members.Count
                        Members             = ($memberNames | Select-Object -First 10) -join ', '
                        TruncatedMembers    = if ($members.Count -gt 10) { "... and $($members.Count - 10) more" } else { '' }
                        Risk                = $groupInfo.Risk
                        Capability          = $groupInfo.Capability
                        Severity            = $severity
                        Recommendation      = 'Remove all members from this group'
                        AttackScenario      = "Compromising any member grants $($groupInfo.Capability)"
                    }
                }
            }

        } catch {
            Write-Verbose "P-OperatorsEmpty: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all members from Account Operators, Server Operators, and other operator groups. Use more granular delegation with custom groups for specific administrative tasks.'
        Impact      = 'High - Users will lose operator privileges. Ensure replacement delegation is in place before removing access.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Operator Groups Remediation
#
# Groups with members:
$($Finding.Findings | ForEach-Object { "# - $($_.GroupName): $($_.MemberCount) members`n#   Members: $($_.Members) $($_.TruncatedMembers)" } | Out-String)

# WHY THESE GROUPS SHOULD BE EMPTY:
#
# Account Operators can:
#   - Create and modify most user/group accounts
#   - Reset passwords for non-admin users
#   - Log on to Domain Controllers locally
#   - PATH TO DOMAIN ADMIN via account manipulation
#
# Server Operators can:
#   - Log on to DCs locally
#   - Manage services (install malicious service)
#   - Backup/restore files (extract NTDS.dit)
#   - Shutdown DCs (denial of service)
#
# Backup Operators can:
#   - Backup any file (SeBackupPrivilege) - extract NTDS.dit
#   - Restore any file (SeRestorePrivilege) - overwrite system files
#
# Print Operators can:
#   - Log on to DCs
#   - Load printer drivers (code execution)

# STEP 1: Identify current members and their needs
$($Finding.Findings | ForEach-Object { @"
Write-Host "Members of $($_.GroupName):"
Get-ADGroupMember -Identity "$($_.GroupName)" | Select-Object Name, SamAccountName, objectClass

"@ })

# STEP 2: Create proper delegation groups (if needed)
# Instead of operator groups, create specific delegation:

# For account management tasks:
New-ADGroup -Name "Delegated-UserAccountManagers" `
    -GroupScope DomainLocal `
    -Description "Delegated user account management"

# Grant specific permissions via OU delegation instead

# STEP 3: Remove all members from operator groups
$($Finding.Findings | ForEach-Object { @"
# Remove all members from $($_.GroupName)
Get-ADGroupMember -Identity "$($_.GroupName)" | ForEach-Object {
    Remove-ADGroupMember -Identity "$($_.GroupName)" -Members `$_.SamAccountName -Confirm:`$false
    Write-Host "Removed `$(`$_.SamAccountName) from $($_.GroupName)"
}

"@ })

# STEP 4: Verify groups are empty
$($Finding.Findings | ForEach-Object { @"
Write-Host "$($_.GroupName) members after cleanup:"
Get-ADGroupMember -Identity "$($_.GroupName)" | Select-Object Name

"@ })

# STEP 5: Set up proper OU-level delegation
# Example: Allow user creation in a specific OU
`$delegatedOU = "OU=Users,DC=domain,DC=com"
`$delegatedGroup = "Delegated-UserAccountManagers"

# Grant create user objects permission
dsacls `$delegatedOU /G "`${delegatedGroup}:CC;user"

# Grant password reset permission
dsacls `$delegatedOU /G "`${delegatedGroup}:CA;Reset Password"

# STEP 6: Monitor for re-addition of members
# Set up alerts for changes to operator group membership
# Event ID 4728, 4732, 4756 (member added to security groups)

"@
            return $commands
        }
    }
}
