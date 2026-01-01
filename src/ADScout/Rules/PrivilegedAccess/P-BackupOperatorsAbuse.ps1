@{
    Id          = 'P-BackupOperatorsAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Backup Operators Group Membership'
    Description = 'Detects members in the Backup Operators group. Members can backup any file including NTDS.dit and registry hives, enabling offline extraction of all domain credentials. This group should be empty or very strictly controlled.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Backup Operators Privilege'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
        @{ Title = 'NTDS.dit Extraction'; Url = 'https://attack.mitre.org/techniques/T1003/003/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.003')  # NTDS
    }

    CIS   = @('5.4.8')
    STIG  = @('V-220958')
    ANSSI = @('R57')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $backupOps = Get-ADGroup -Identity "Backup Operators" -Properties Members -ErrorAction SilentlyContinue

            if ($backupOps) {
                $members = Get-ADGroupMember -Identity $backupOps -Recursive -ErrorAction SilentlyContinue

                if ($members -and $members.Count -gt 0) {
                    foreach ($member in $members) {
                        $memberDetails = $null
                        if ($member.objectClass -eq 'user') {
                            $memberDetails = Get-ADUser -Identity $member.SamAccountName -Properties Enabled, Description, LastLogonDate -ErrorAction SilentlyContinue
                        }

                        $findings += [PSCustomObject]@{
                            GroupName           = 'Backup Operators'
                            MemberName          = $member.SamAccountName
                            MemberType          = $member.objectClass
                            MemberDN            = $member.distinguishedName
                            Enabled             = if ($memberDetails) { $memberDetails.Enabled } else { 'N/A' }
                            Description         = if ($memberDetails) { $memberDetails.Description } else { 'N/A' }
                            LastLogon           = if ($memberDetails) { $memberDetails.LastLogonDate } else { 'N/A' }
                            RiskLevel           = 'High'
                            AttackCapability    = @(
                                'Can backup any file regardless of ACLs',
                                'Can backup NTDS.dit (all password hashes)',
                                'Can backup SYSTEM/SAM registry hives',
                                'Can backup any sensitive files',
                                'SeBackupPrivilege enables file read bypass'
                            ) -join '; '
                        }
                    }
                }
            }
        }
        catch {
            # Group may not exist or cannot be queried
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all members from Backup Operators group. Use dedicated backup service accounts with minimal privileges instead.'
        Impact      = 'Medium - Review backup solutions before removing'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# BACKUP OPERATORS GROUP
# ================================================================
# Backup Operators have SeBackupPrivilege which allows:
# - Reading ANY file regardless of ACLs
# - Backing up NTDS.dit to extract all password hashes
# - Backing up SAM/SYSTEM for local credential extraction
#
# This is effectively Domain Admin equivalent for data access!

# ================================================================
# CURRENT MEMBERS
# ================================================================

Get-ADGroupMember -Identity "Backup Operators" -Recursive | ``
    Select-Object Name, SamAccountName, objectClass

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Member: $($item.MemberName)
# Type: $($item.MemberType)
# Last Logon: $($item.LastLogon)
# Description: $($item.Description)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# 1. IDENTIFY BACKUP SOLUTION
# What actually needs backup access?
# - Backup software service account?
# - Manual backup by admins?

# 2. REMOVE FROM BACKUP OPERATORS
# Most backup solutions don't need this group membership

`$members = Get-ADGroupMember -Identity "Backup Operators"
foreach (`$member in `$members) {
    Write-Host "Review before removing: `$(`$member.SamAccountName)"
    # Remove-ADGroupMember -Identity "Backup Operators" -Members `$member -Confirm:`$false
}

# 3. CONFIGURE BACKUP ACCESS PROPERLY
# For backup software:
# - Use dedicated service account
# - Grant specific file/folder permissions needed
# - Avoid SeBackupPrivilege if possible

# 4. IF BACKUP OF AD IS NEEDED
# Use Windows Server Backup with DC system state backup
# This should be run by Domain Admins, not Backup Operators

# ================================================================
# MONITORING
# ================================================================

# Monitor for backup privilege usage:
# Event ID 4674 - Privileged operation attempted
# Look for: SeBackupPrivilege usage by non-backup accounts

# Monitor NTDS.dit access:
# Event ID 4663 - Object access
# Path: %SystemRoot%\NTDS\ntds.dit

"@
            return $commands
        }
    }
}
