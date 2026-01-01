@{
    Id          = 'P-WriteOwnerAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'WriteOwner Permission on Critical Objects'
    Description = 'Detects principals with WriteOwner permission on critical AD objects. WriteOwner allows changing object ownership, and owners have implicit rights to modify the DACL, leading to full control escalation.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'WriteOwner Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces' }
        @{ Title = 'BloodHound WriteOwner'; Url = 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writeowner' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')
        Techniques = @('T1222.001', 'T1098')
    }

    CIS   = @('5.4.5')
    STIG  = @('V-220984')
    ANSSI = @('R49')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 45
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical objects to check
        $criticalObjects = @()

        try {
            $domain = Get-ADDomain

            # Domain root
            $criticalObjects += @{ DN = $domain.DistinguishedName; Type = 'Domain Root' }

            # Privileged groups
            @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') | ForEach-Object {
                try {
                    $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                    if ($group) {
                        $criticalObjects += @{ DN = $group.DistinguishedName; Type = "Group: $_" }
                    }
                }
                catch { }
            }

            # Privileged users
            $privilegedUsers = $Data.Users | Where-Object {
                $_.AdminCount -eq 1 -and $_.Enabled
            } | Select-Object -First 20  # Limit for performance

            foreach ($user in $privilegedUsers) {
                $criticalObjects += @{ DN = $user.DistinguishedName; Type = "Admin User: $($user.SamAccountName)" }
            }

            # Domain Controllers
            $dcs = Get-ADComputer -Filter { PrimaryGroupID -eq 516 } -Properties DistinguishedName -ErrorAction SilentlyContinue
            foreach ($dc in $dcs) {
                $criticalObjects += @{ DN = $dc.DistinguishedName; Type = "DC: $($dc.Name)" }
            }

            foreach ($obj in $criticalObjects) {
                try {
                    $acl = Get-Acl "AD:$($obj.DN)" -ErrorAction SilentlyContinue
                    if (-not $acl) { continue }

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        if ($ace.ActiveDirectoryRights -match 'WriteOwner') {
                            $principal = $ace.IdentityReference.Value

                            # Skip expected principals
                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|BUILTIN\\Administrators') {
                                continue
                            }

                            $findings += [PSCustomObject]@{
                                TargetObject        = $obj.Type
                                TargetDN            = $obj.DN
                                Principal           = $principal
                                Permission          = 'WriteOwner'
                                RiskLevel           = 'Critical'
                                Inherited           = $ace.IsInherited
                                AttackPath          = 'WriteOwner -> Become Owner -> WriteDACL (implicit) -> GenericAll'
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        return $findings | Sort-Object TargetObject
    }

    Remediation = @{
        Description = 'Remove WriteOwner permissions from non-administrative principals on critical AD objects.'
        Impact      = 'Low - WriteOwner is rarely needed for normal operations'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# WRITEOWNER PERMISSION ABUSE
# ================================================================
# WriteOwner allows changing the owner of an object.
# The owner has implicit WriteDACL rights.
#
# Attack chain:
# WriteOwner -> Change owner to self -> WriteDACL -> GenericAll

# ================================================================
# VULNERABLE OBJECTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Target: $($item.TargetObject)
# DN: $($item.TargetDN)
# Principal with WriteOwner: $($item.Principal)
# Attack Path: $($item.AttackPath)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove WriteOwner from: $($item.Principal) on $($item.TargetObject)
`$targetDN = "$($item.TargetDN)"
`$acl = Get-Acl "AD:`$targetDN"

`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq "$($item.Principal)" -and
    `$_.ActiveDirectoryRights -match 'WriteOwner'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply (uncomment):
# Set-Acl "AD:`$targetDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# CHECK CURRENT OWNERS
# ================================================================

# Also verify current owners of critical objects:
`$criticalObjects = @(
    (Get-ADDomain).DistinguishedName,
    (Get-ADGroup "Domain Admins").DistinguishedName,
    (Get-ADGroup "Enterprise Admins").DistinguishedName
)

foreach (`$obj in `$criticalObjects) {
    `$acl = Get-Acl "AD:`$obj"
    Write-Host "Object: `$obj"
    Write-Host "Owner: `$(`$acl.Owner)"
    Write-Host ""
}

# Owners should be Domain Admins or BUILTIN\Administrators

# ================================================================
# CHANGE OWNER (if needed)
# ================================================================

# To fix incorrect ownership:
# `$acl = Get-Acl "AD:CN=Domain Admins,CN=Users,DC=domain,DC=com"
# `$owner = [System.Security.Principal.NTAccount]"DOMAIN\Domain Admins"
# `$acl.SetOwner(`$owner)
# Set-Acl "AD:CN=Domain Admins,CN=Users,DC=domain,DC=com" `$acl

"@
            return $commands
        }
    }
}
