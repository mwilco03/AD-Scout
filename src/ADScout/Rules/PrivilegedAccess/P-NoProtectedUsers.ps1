@{
    Id          = 'P-NoProtectedUsers'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Protected Users Group Not Utilized'
    Description = 'Privileged accounts are not members of the Protected Users security group. This group provides additional protections against credential theft including: no NTLM authentication, no DES/RC4 Kerberos encryption, no credential delegation, and short TGT lifetime.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Protected Users Security Group'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group' }
        @{ Title = 'Credential Theft Mitigations'; Url = 'https://attack.mitre.org/mitigations/M1015/' }
        @{ Title = 'Pass-the-Hash Prevention'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003', 'T1550.002')  # OS Credential Dumping, Pass the Hash
    }

    CIS   = @('5.28')
    STIG  = @('V-63333')
    ANSSI = @('vuln2_protected_users')
    NIST  = @('IA-5')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find Protected Users group and privileged groups
        $protectedUsersMembers = @()
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
        $privilegedMembers = @{}

        foreach ($group in $Data) {
            $groupName = $group.SamAccountName

            if ($groupName -eq 'Protected Users') {
                # Get Protected Users members
                $members = @()
                if ($group.Members) { $members = $group.Members }
                elseif ($group.Member) { $members = $group.Member }

                foreach ($member in $members) {
                    $memberName = $member
                    if ($member -match 'CN=([^,]+)') {
                        $memberName = $Matches[1]
                    }
                    $protectedUsersMembers += $memberName
                }
            }

            if ($groupName -in $privilegedGroups) {
                # Get privileged group members
                $members = @()
                if ($group.Members) { $members = $group.Members }
                elseif ($group.Member) { $members = $group.Member }

                foreach ($member in $members) {
                    $memberName = $member
                    if ($member -match 'CN=([^,]+)') {
                        $memberName = $Matches[1]
                    }
                    if (-not $privilegedMembers.ContainsKey($memberName)) {
                        $privilegedMembers[$memberName] = @()
                    }
                    $privilegedMembers[$memberName] += $groupName
                }
            }
        }

        # Find privileged users not in Protected Users
        foreach ($member in $privilegedMembers.Keys) {
            if ($member -notin $protectedUsersMembers) {
                # Skip service accounts and computer accounts
                if ($member -match '\$$' -or $member -match '^svc[_-]' -or $member -match 'service') {
                    continue
                }

                $findings += [PSCustomObject]@{
                    AccountName           = $member
                    PrivilegedGroups      = ($privilegedMembers[$member] -join ', ')
                    InProtectedUsers      = $false
                    MissingProtections    = @(
                        'NTLM authentication allowed'
                        'Credential caching allowed'
                        'DES/RC4 Kerberos encryption allowed'
                        'Unconstrained delegation allowed'
                        'Long TGT lifetime (10 hours default)'
                    ) -join '; '
                    RiskLevel             = 'Medium'
                    AttackVectors         = 'Pass-the-Hash, Credential Dumping, Kerberos Ticket Theft'
                }
            }
        }

        # Also check if Protected Users is empty
        if ($protectedUsersMembers.Count -eq 0 -and $privilegedMembers.Count -gt 0) {
            $findings = @([PSCustomObject]@{
                AccountName           = 'N/A - Protected Users group is empty'
                PrivilegedGroups      = "Domain has $($privilegedMembers.Count) privileged accounts"
                InProtectedUsers      = $false
                MissingProtections    = 'No privileged accounts have Protected Users protections'
                RiskLevel             = 'Medium'
                AttackVectors         = 'All privileged accounts vulnerable to credential theft techniques'
            }) + $findings
        }

        return $findings
    }

    Remediation = @{
        Description = 'Add privileged accounts (Domain Admins, Enterprise Admins, etc.) to the Protected Users security group. Test thoroughly as some applications may not support the restrictions.'
        Impact      = 'Medium - NTLM authentication will fail for these accounts. Some applications may need updates to support Kerberos-only authentication.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Add Privileged Accounts to Protected Users Group
# Accounts Missing Protection: $($Finding.Findings.Count)

# IMPORTANT PREREQUISITES:
# - Domain functional level must be Windows Server 2012 R2 or higher
# - All DCs must run Windows Server 2012 R2 or higher
# - Test with non-critical admin accounts first

# Check domain functional level:
(Get-ADDomain).DomainMode

# List current Protected Users members:
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName

# Accounts to add:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName) (Member of: $($_.PrivilegedGroups))" } | Out-String)

# Add accounts to Protected Users:
`$accountsToProtect = @(
$($Finding.Findings | Where-Object { $_.AccountName -ne 'N/A - Protected Users group is empty' } | ForEach-Object { "    '$($_.AccountName)'" } | Out-String -NoNewline)
)

foreach (`$account in `$accountsToProtect) {
    try {
        Add-ADGroupMember -Identity "Protected Users" -Members `$account
        Write-Host "Added `$account to Protected Users"
    } catch {
        Write-Warning "Failed to add `$account: `$_"
    }
}

# RESTRICTIONS APPLIED BY PROTECTED USERS:
# 1. NTLM authentication is blocked
# 2. Kerberos uses AES encryption only (no DES/RC4)
# 3. Credentials are not cached
# 4. Kerberos TGT lifetime is 4 hours (not 10)
# 5. Unconstrained delegation is blocked

# TESTING CONSIDERATIONS:
# - Verify all services used by these accounts support Kerberos
# - Test RDP, file share access, and application logins
# - Check event logs for NTLM auth failures (Event ID 4776)
# - Have a plan to remove accounts if issues arise

# Verify membership:
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName

# Monitor for NTLM failures after adding:
# Event ID 4776 in Security log on DCs

"@
            return $commands
        }
    }
}
