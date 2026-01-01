@{
    Id          = 'P-DangerousACL'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Dangerous Extended Rights on AD Objects'
    Description = 'Low-privileged users or groups have dangerous extended rights on Active Directory objects, such as DCSync (DS-Replication-Get-Changes), WriteDACL, WriteOwner, or GenericAll. These rights allow attackers to escalate privileges or extract credentials.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'DCSync Attack'; Url = 'https://attack.mitre.org/techniques/T1003/006/' }
        @{ Title = 'AD ACL Abuse'; Url = 'https://attack.mitre.org/techniques/T1222/001/' }
        @{ Title = 'BloodHound ACL Analysis'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1003.006', 'T1222.001')  # DCSync, File and Directory Permissions Modification
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_dcsync', 'vuln1_dangerous_acl')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous rights GUIDs
        $dangerousRights = @{
            # Replication Rights (DCSync)
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'

            # Generic dangerous rights
            '00000000-0000-0000-0000-000000000000' = 'GenericAll'
        }

        # Well-known privileged SIDs that are expected to have these rights
        $privilegedSIDs = @(
            'S-1-5-32-544',    # Administrators
            'S-1-5-9',          # Enterprise DCs
            'S-1-5-18'          # SYSTEM
        )

        try {
            # Get domain DN
            $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
            if ($Domain.DistinguishedName) {
                $domainDN = $Domain.DistinguishedName
            }

            # Get the domain object ACL
            $domainObj = [ADSI]"LDAP://$domainDN"
            $acl = $domainObj.ObjectSecurity

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()
                $objectType = $ace.ObjectType.ToString()

                # Skip ALLOW-only, we're looking for grants
                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Check for dangerous extended rights
                $isDangerous = $false
                $dangerousRight = ''

                # Check for replication rights
                if ($dangerousRights.ContainsKey($objectType.ToLower())) {
                    $isDangerous = $true
                    $dangerousRight = $dangerousRights[$objectType.ToLower()]
                }

                # Check for GenericAll/WriteDacl/WriteOwner
                if ($rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $isDangerous = $true
                    $dangerousRight = $rights
                }

                if ($isDangerous) {
                    # Check if this is an unexpected principal
                    $sid = $null
                    try {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        $sid = $identity
                    }

                    # Skip known privileged accounts
                    $isPrivileged = $privilegedSIDs | Where-Object { $sid -match $_ -or $sid -eq $_ }

                    # Also skip Domain Admins, Enterprise Admins by name pattern
                    $isPrivilegedByName = $identity -match 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|Domain Controllers'

                    if (-not $isPrivileged -and -not $isPrivilegedByName) {
                        $findings += [PSCustomObject]@{
                            Principal           = $identity
                            SID                 = $sid
                            DangerousRight      = $dangerousRight
                            ObjectType          = if ($objectType -eq '00000000-0000-0000-0000-000000000000') { 'All Objects' } else { $objectType }
                            TargetObject        = $domainDN
                            AccessControlType   = $ace.AccessControlType.ToString()
                            RiskLevel           = if ($dangerousRight -match 'Replication|GenericAll') { 'Critical' } else { 'High' }
                            AttackPath          = if ($dangerousRight -match 'Replication') { 'DCSync - Can extract all password hashes' } else { 'Can modify object permissions for privilege escalation' }
                        }
                    }
                }
            }
        } catch {
            # If we can't check ACLs, note it for manual review
            $findings += [PSCustomObject]@{
                Principal           = 'Unable to enumerate'
                SID                 = 'N/A'
                DangerousRight      = 'Unable to check'
                ObjectType          = 'N/A'
                TargetObject        = 'Domain root'
                AccessControlType   = 'N/A'
                RiskLevel           = 'Unknown'
                AttackPath          = 'Manual ACL review required'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove dangerous ACL entries from non-privileged principals. Ensure only authorized accounts have replication and write rights.'
        Impact      = 'Medium - Removing ACLs may break applications or delegated administration. Verify each principal before removal.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Remove Dangerous ACL Entries from AD Objects
# WARNING: Review each entry carefully before removal

# Affected Principals:
$($Finding.Findings | ForEach-Object { "# - $($_.Principal): $($_.DangerousRight) on $($_.TargetObject)" } | Out-String)

# Use BloodHound or ADExplorer to visualize attack paths first:
# https://bloodhound.readthedocs.io/

# To remove specific ACE entries:
`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-Acl "AD:\`$domainDN"

# Example: Remove DCSync rights from a specific user
# `$principal = "DOMAIN\SuspiciousUser"
# `$ace = `$acl.Access | Where-Object {
#     `$_.IdentityReference -eq `$principal -and
#     `$_.ObjectType -match '1131f6a'
# }
# `$acl.RemoveAccessRule(`$ace)
# Set-Acl "AD:\`$domainDN" `$acl

# Audit all DCSync capable principals:
`$replicationGUIDs = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
)

Get-Acl "AD:\`$domainDN" | Select-Object -ExpandProperty Access |
    Where-Object { `$_.ObjectType -in `$replicationGUIDs } |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType

"@
            return $commands
        }
    }
}
