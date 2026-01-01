<#
.SYNOPSIS
    Detects risky Backup Operators group membership.

.DESCRIPTION
    Members of the Backup Operators group can backup files including the NTDS.dit
    database, enabling offline credential extraction. This rule identifies members
    and validates if membership is appropriate.

.NOTES
    Rule ID    : DP-BackupOperators
    Category   : DataProtection
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'DP-BackupOperators'
    Version     = '1.0.0'
    Category    = 'DataProtection'
    Title       = 'Backup Operators Group Membership'
    Description = 'Identifies members of the Backup Operators group who can backup the AD database and extract credentials offline. This group should have minimal membership.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'Groups,Users'

    References  = @(
        @{ Title = 'Backup Operators Abuse'; Url = 'https://attack.mitre.org/techniques/T1003/003/' }
        @{ Title = 'Backup Operators Privileges'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#backup-operators' }
        @{ Title = 'AD Tiering Model'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0005')  # Credential Access, Defense Evasion
        Techniques = @('T1003.003', 'T1078.002')  # NTDS, Domain Accounts
    }

    CIS   = @('5.2')
    STIG  = @('V-36661')
    ANSSI = @('R39')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get Backup Operators group
        try {
            $backupOperators = Get-ADGroup -Identity 'Backup Operators' -Properties Members -ErrorAction SilentlyContinue

            if ($backupOperators -and $backupOperators.Members.Count -gt 0) {
                # Get recursive membership
                $members = Get-ADGroupMember -Identity 'Backup Operators' -Recursive -ErrorAction SilentlyContinue

                foreach ($member in $members) {
                    $issues = @()
                    $riskLevel = 'Medium'

                    # Get detailed member info
                    $memberDetails = $null
                    if ($member.objectClass -eq 'user') {
                        $memberDetails = Get-ADUser -Identity $member.SamAccountName -Properties * -ErrorAction SilentlyContinue
                    } elseif ($member.objectClass -eq 'computer') {
                        $memberDetails = Get-ADComputer -Identity $member.SamAccountName -Properties * -ErrorAction SilentlyContinue
                    }

                    # Check if regular user (not service account)
                    if ($member.objectClass -eq 'user') {
                        if ($memberDetails) {
                            # Check if enabled
                            if ($memberDetails.Enabled) {
                                $issues += 'Active user account'
                            }

                            # Check if not in privileged OU
                            if ($memberDetails.DistinguishedName -notmatch 'Admin|Tier.?0|Service|Privileged') {
                                $issues += 'Not in administrative OU'
                                $riskLevel = 'High'
                            }

                            # Check last logon
                            if ($memberDetails.LastLogonDate) {
                                $daysSinceLogon = ((Get-Date) - $memberDetails.LastLogonDate).Days
                                if ($daysSinceLogon -gt 90) {
                                    $issues += "Last logon $daysSinceLogon days ago"
                                }
                            }

                            # Check if also in Domain Admins (redundant and risky)
                            $groups = $memberDetails.MemberOf | ForEach-Object {
                                (Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue).Name
                            }
                            if ($groups -contains 'Domain Admins') {
                                $issues += 'Also in Domain Admins (redundant)'
                            }

                            # Check password age
                            if ($memberDetails.PasswordLastSet) {
                                $pwdAge = ((Get-Date) - $memberDetails.PasswordLastSet).Days
                                if ($pwdAge -gt 365) {
                                    $issues += "Password $pwdAge days old"
                                    $riskLevel = 'High'
                                }
                            }
                        }
                    }

                    # Any membership is noteworthy
                    if ($issues.Count -eq 0) {
                        $issues += 'Member of high-privilege group - validate necessity'
                    }

                    $findings += [PSCustomObject]@{
                        AccountName       = $member.SamAccountName
                        AccountType       = $member.objectClass
                        Enabled           = if ($memberDetails) { $memberDetails.Enabled } else { 'Unknown' }
                        Description       = if ($memberDetails) { $memberDetails.Description } else { '' }
                        LastLogonDate     = if ($memberDetails.LastLogonDate) { $memberDetails.LastLogonDate } else { 'Never/Unknown' }
                        PasswordLastSet   = if ($memberDetails.PasswordLastSet) { $memberDetails.PasswordLastSet } else { 'Unknown' }
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        Privilege         = 'Can backup NTDS.dit and extract credentials offline'
                        DistinguishedName = $member.DistinguishedName
                    }
                }
            }
        } catch {
            # Report error as finding
            $findings += [PSCustomObject]@{
                AccountName       = 'Error'
                AccountType       = 'N/A'
                Enabled           = 'N/A'
                Description       = 'Unable to enumerate Backup Operators group'
                LastLogonDate     = 'N/A'
                PasswordLastSet   = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                Privilege         = 'N/A'
                DistinguishedName = 'N/A'
            }
        }

        # Also check for Backup Operators equivalent (SeBackupPrivilege)
        try {
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue
            foreach ($gpo in $gpos) {
                $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                if ($report -match 'SeBackupPrivilege') {
                    # Parse to find who has the privilege
                    if ($report -match 'SeBackupPrivilege.*?<Member.*?Name="([^"]+)"') {
                        $findings += [PSCustomObject]@{
                            AccountName       = $Matches[1]
                            AccountType       = 'GPO Assignment'
                            Enabled           = 'N/A'
                            Description       = "SeBackupPrivilege via GPO: $($gpo.DisplayName)"
                            LastLogonDate     = 'N/A'
                            PasswordLastSet   = 'N/A'
                            Issues            = 'Backup privilege assigned via GPO'
                            RiskLevel         = 'Medium'
                            Privilege         = 'SeBackupPrivilege'
                            DistinguishedName = 'N/A'
                        }
                    }
                }
            }
        } catch {}

        return $findings
    }

    Remediation = @{
        Description = 'Minimize Backup Operators membership and use dedicated service accounts with monitoring.'
        Impact      = 'Low - Backup functionality can be maintained with proper service accounts.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Backup Operators Security Hardening
#############################################################################
#
# The Backup Operators group grants powerful privileges:
# - SeBackupPrivilege: Read any file regardless of ACLs
# - SeRestorePrivilege: Write any file regardless of ACLs
# - Can backup NTDS.dit and SYSTEM hive offline
# - Attackers can extract all domain credentials from backup
#
# Current Backup Operators members:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Audit Current Membership
#############################################################################

# List all Backup Operators:
Get-ADGroupMember -Identity 'Backup Operators' -Recursive |
    ForEach-Object {
        if (`$_.objectClass -eq 'user') {
            Get-ADUser -Identity `$_.SamAccountName -Properties Description, Enabled, LastLogonDate
        } else {
            Get-ADComputer -Identity `$_.SamAccountName -Properties Description, Enabled
        }
    } | Format-Table Name, Enabled, LastLogonDate, Description

#############################################################################
# Step 2: Remove Unnecessary Members
#############################################################################

# Remove users who don't need backup privileges:
# Get-ADGroupMember -Identity 'Backup Operators' |
#     Where-Object { `$_.SamAccountName -ne 'backup_svc' } |
#     ForEach-Object {
#         Remove-ADGroupMember -Identity 'Backup Operators' -Members `$_ -Confirm:`$false
#         Write-Host "Removed `$(`$_.SamAccountName) from Backup Operators"
#     }

#############################################################################
# Step 3: Use Dedicated Service Accounts
#############################################################################

# Create a dedicated backup service account:
`$backupSvc = @{
    Name = 'svc_backup'
    SamAccountName = 'svc_backup'
    UserPrincipalName = 'svc_backup@domain.com'
    Description = 'Dedicated backup service account'
    AccountPassword = (Read-Host -AsSecureString 'Enter password')
    PasswordNeverExpires = `$false
    CannotChangePassword = `$false
    Enabled = `$true
    Path = 'OU=Service Accounts,OU=Admin,DC=domain,DC=com'
}
# New-ADUser @backupSvc

# Add to Backup Operators:
# Add-ADGroupMember -Identity 'Backup Operators' -Members 'svc_backup'

#############################################################################
# Step 4: Protect Service Account
#############################################################################

# Add to Protected Users if possible (test first):
# Add-ADGroupMember -Identity 'Protected Users' -Members 'svc_backup'

# Set a strong password policy:
# Apply Fine-Grained Password Policy with:
# - 24+ character password
# - 90-day rotation
# - Account lockout

# Restrict logon to backup servers only:
# Set-ADUser -Identity 'svc_backup' -LogonWorkstations 'BACKUP01,BACKUP02'

#############################################################################
# Step 5: Monitor Backup Operators Activity
#############################################################################

# Enable auditing for Backup Operators logons:
# Event ID 4624 with Logon Type 2 or 10

# Monitor for suspicious backup activity:
# Event ID 4656: Handle to object requested
# Event ID 4663: Attempt to access object
# Event ID 4690: Handle duplicated

# Create alert for Backup Operators logons:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match 'Backup Operators'
} | Select-Object TimeCreated, Message

#############################################################################
# Step 6: Implement Just-In-Time Access
#############################################################################

# Instead of permanent membership, use JIT:
# 1. Keep Backup Operators empty by default
# 2. Add service account only when backup runs
# 3. Remove after backup completes

# Example script for scheduled task:
`$backupScript = @'
# Add to Backup Operators
Add-ADGroupMember -Identity 'Backup Operators' -Members 'svc_backup'

# Run backup
& 'C:\Backup\backup.exe'

# Remove from Backup Operators
Remove-ADGroupMember -Identity 'Backup Operators' -Members 'svc_backup' -Confirm:`$false
'@

#############################################################################
# Step 7: Alternative Backup Methods
#############################################################################

# Consider using:
# 1. Azure Backup with Azure AD authentication
# 2. Windows Server Backup with specific delegation
# 3. Veeam/Commvault with dedicated backup proxy
# 4. Volume shadow copy without Backup Operators

# For AD backup specifically, use:
# - Windows Server Backup with System State
# - Azure AD Connect (for hybrid)
# - Veeam with Application-Aware Processing

#############################################################################
# Verification
#############################################################################

# Verify Backup Operators membership is minimal:
Get-ADGroupMember -Identity 'Backup Operators' |
    Select-Object Name, SamAccountName, objectClass |
    Format-Table -AutoSize

# Verify no unexpected SeBackupPrivilege assignments:
whoami /priv | Select-String 'SeBackupPrivilege'

"@
            return $commands
        }
    }
}
