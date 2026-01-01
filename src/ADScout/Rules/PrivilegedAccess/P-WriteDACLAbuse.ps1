@{
    Id          = 'P-WriteDACLAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'WriteDACL Permission on Critical Objects'
    Description = 'Detects users or groups with WriteDACL permission on critical AD objects (domain root, admin groups, DCs). WriteDACL allows modifying the security descriptor, enabling attackers to grant themselves any permission including GenericAll.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'AD ACL Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
        @{ Title = 'BloodHound Edges'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html' }
        @{ Title = 'DACL Abuse'; Url = 'https://attack.mitre.org/techniques/T1222/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1222.001', 'T1098')  # File and Directory Permissions Modification, Account Manipulation
    }

    CIS   = @('5.4.1')
    STIG  = @('V-220980')
    ANSSI = @('R45')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical objects to check
        $criticalObjects = @()

        try {
            $domain = Get-ADDomain
            $criticalObjects += @{ DN = $domain.DistinguishedName; Type = 'Domain Root' }

            # Get privileged groups
            $privilegedGroups = @(
                'Domain Admins',
                'Enterprise Admins',
                'Schema Admins',
                'Administrators',
                'Account Operators',
                'Backup Operators'
            )

            foreach ($groupName in $privilegedGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                    if ($group) {
                        $criticalObjects += @{ DN = $group.DistinguishedName; Type = "Privileged Group: $groupName" }
                    }
                }
                catch { }
            }

            # Domain Controllers OU
            $dcOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
            $criticalObjects += @{ DN = $dcOU; Type = 'Domain Controllers OU' }

            # AdminSDHolder
            $adminSDHolder = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
            $criticalObjects += @{ DN = $adminSDHolder; Type = 'AdminSDHolder' }

            foreach ($obj in $criticalObjects) {
                try {
                    $acl = Get-Acl "AD:$($obj.DN)" -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        # Check for WriteDACL
                        if ($ace.ActiveDirectoryRights -match 'WriteDacl') {
                            $principal = $ace.IdentityReference.Value

                            # Skip expected principals
                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|BUILTIN\\Administrators') {
                                continue
                            }

                            # Check if it's a low-privileged principal
                            $isLowPriv = $principal -match 'Domain Users|Authenticated Users|Everyone|Users'

                            # Try to resolve to see if it's a user or group
                            $principalType = 'Unknown'
                            try {
                                $adPrincipal = Get-ADObject -Filter "SamAccountName -eq '$($principal.Split('\')[-1])'" -Properties objectClass -ErrorAction SilentlyContinue
                                if ($adPrincipal) {
                                    $principalType = $adPrincipal.objectClass
                                }
                            }
                            catch { }

                            $findings += [PSCustomObject]@{
                                TargetObject        = $obj.Type
                                TargetDN            = $obj.DN
                                Principal           = $principal
                                PrincipalType       = $principalType
                                Permission          = 'WriteDACL'
                                IsLowPrivileged     = $isLowPriv
                                RiskLevel           = if ($isLowPriv) { 'Critical' } else { 'High' }
                                Inherited           = $ace.IsInherited
                                AttackPath          = 'WriteDACL -> Grant GenericAll -> Full Control'
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            # Domain info unavailable
        }

        return $findings | Sort-Object RiskLevel, TargetObject
    }

    Remediation = @{
        Description = 'Remove WriteDACL permissions from non-administrative principals on critical AD objects.'
        Impact      = 'Medium - May affect delegated administration if not reviewed carefully'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# WRITEDACL PERMISSION ABUSE
# ================================================================
# WriteDACL allows modifying the Access Control List of an object.
#
# Attack:
# 1. Attacker has WriteDACL on Domain Admins group
# 2. Attacker adds ACE granting themselves GenericAll
# 3. Attacker adds themselves to Domain Admins
# 4. Full domain compromise

# ================================================================
# VULNERABLE OBJECTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Target: $($item.TargetObject)
# DN: $($item.TargetDN)
# Principal with WriteDACL: $($item.Principal)
# Risk Level: $($item.RiskLevel)
# Inherited: $($item.Inherited)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove WriteDACL from: $($item.Principal) on $($item.TargetObject)
`$targetDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$targetDN"

# Find and remove the specific ACE:
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    `$_.ActiveDirectoryRights -match 'WriteDacl'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment to execute):
# Set-Acl "AD:`$targetDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# VERIFICATION
# ================================================================

# After remediation, verify permissions:
`$criticalObjects = @(
    (Get-ADDomain).DistinguishedName,
    (Get-ADGroup "Domain Admins").DistinguishedName,
    "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"
)

foreach (`$obj in `$criticalObjects) {
    Write-Host "Checking: `$obj"
    (Get-Acl "AD:`$obj").Access |
        Where-Object { `$_.ActiveDirectoryRights -match 'WriteDacl' } |
        Select-Object IdentityReference, ActiveDirectoryRights, IsInherited
}

# ================================================================
# MONITORING
# ================================================================

# Enable auditing on critical objects:
# - Event ID 5136 (Directory Service Changes)
# - Event ID 4662 (Operation performed on object)
#
# Look for changes to nTSecurityDescriptor attribute

"@
            return $commands
        }
    }
}
