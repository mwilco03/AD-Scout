@{
    Id          = 'P-SchemaAdmin'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Schema Admins Group Populated'
    Description = 'The Schema Admins group has permanent members. This group should be empty except when actively making schema changes, as schema modifications are irreversible.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'Schema Admins Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-schema-admins-groups-in-active-directory' }
        @{ Title = 'Privileged Group Management'; Url = 'https://attack.mitre.org/techniques/T1098/' }
    )

    MITRE = @{
        Tactics    = @('TA0003')  # Persistence
        Techniques = @('T1098')   # Account Manipulation
    }

    CIS   = @('5.3')
    STIG  = @('V-36458')
    ANSSI = @('vuln2_schema_admin')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $schemaAdmins = $Data | Where-Object { $_.Name -eq 'Schema Admins' }

        if ($schemaAdmins -and $schemaAdmins.Members -and $schemaAdmins.Members.Count -gt 0) {
            $findings += [PSCustomObject]@{
                GroupName           = 'Schema Admins'
                MemberCount         = $schemaAdmins.Members.Count
                Members             = ($schemaAdmins.Members | Select-Object -First 10) -join ', '
                DistinguishedName   = $schemaAdmins.DistinguishedName
                Risk                = 'Schema changes are forest-wide and irreversible'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all permanent members from Schema Admins. Add members only when actively making schema changes, then remove immediately after.'
        Impact      = 'Low - Group should be empty in normal operations'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Schema Admins group should be empty except during schema changes
# Current members: $($Finding.Findings[0].MemberCount)

# List current members:
Get-ADGroupMember -Identity 'Schema Admins' | Select-Object Name, SamAccountName, ObjectClass

# Remove all members (after verification):
Get-ADGroupMember -Identity 'Schema Admins' | ForEach-Object {
    Remove-ADGroupMember -Identity 'Schema Admins' -Members `$_ -Confirm:`$false
    Write-Host "Removed: `$(`$_.SamAccountName)"
}

# Document the process for adding members when needed:
# 1. Document business justification
# 2. Add member: Add-ADGroupMember -Identity 'Schema Admins' -Members 'AdminAccount'
# 3. Make schema changes
# 4. Remove member immediately: Remove-ADGroupMember -Identity 'Schema Admins' -Members 'AdminAccount'
# 5. Verify group is empty

# Same process should be followed for Enterprise Admins

"@
            return $commands
        }
    }
}
