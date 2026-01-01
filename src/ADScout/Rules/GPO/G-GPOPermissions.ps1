@{
    Id          = 'G-GPOPermissions'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Dangerous GPO Permissions'
    Description = 'Identifies Group Policy Objects with permissions that allow low-privileged users to modify them. GPO modification can lead to domain-wide compromise.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Abusing GPO Permissions'; Url = 'https://wald0.com/?p=179' }
        @{ Title = 'SharpGPOAbuse'; Url = 'https://github.com/FSecureLABS/SharpGPOAbuse' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1484.001')          # Domain Policy Modification: Group Policy Modification
    }

    CIS   = @('5.15')
    STIG  = @('V-36447')
    ANSSI = @('vuln1_gpo_permissions')
    NIST  = @('AC-3', 'AC-6', 'SI-7')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Principals that should NOT have GPO edit rights
        $dangerousPrincipals = @(
            'Domain Users'
            'Authenticated Users'
            'Everyone'
            'Users'
        )

        $dangerousRights = @(
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
            'WriteDacl'
            'WriteOwner'
            'GpoEditDeleteModifySecurity'
        )

        foreach ($gpo in $Data) {
            $dangerousAces = @()

            foreach ($ace in $gpo.ACL) {
                $identity = $ace.IdentityReference.Value

                # Check if dangerous principal
                $isDangerous = $false
                foreach ($principal in $dangerousPrincipals) {
                    if ($identity -like "*$principal*") {
                        $isDangerous = $true
                        break
                    }
                }

                if ($isDangerous) {
                    # Check for dangerous rights
                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right -or
                            $ace.GPOPermissions -match $right) {
                            $dangerousAces += [PSCustomObject]@{
                                Principal = $identity
                                Rights    = $ace.ActiveDirectoryRights
                            }
                            break
                        }
                    }
                }
            }

            if ($dangerousAces.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    GPOName           = $gpo.DisplayName
                    GPOId             = $gpo.Id
                    DangerousACEs     = $dangerousAces
                    LinksTo           = ($gpo.Links -join ', ')
                    WhenCreated       = $gpo.WhenCreated
                    WhenChanged       = $gpo.WhenChanged
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove edit permissions from low-privileged groups. Only Domain Admins and designated GPO administrators should have modification rights.'
        Impact      = 'Low - Restricts who can modify policies'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Dangerous GPO permissions detected
# Low-privileged users can modify these GPOs

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName) (ID: $($item.GPOId))
# Linked to: $($item.LinksTo)
# Dangerous permissions:
$(foreach ($ace in $item.DangerousACEs) { "# - $($ace.Principal): $($ace.Rights)`n" })

# Remove dangerous permissions using GPMC or PowerShell:
# `$gpo = Get-GPO -Guid '$($item.GPOId)'
# `$gpo.SetSecurityInfo(`$gpo.Owner, `$gpo.Group, 'Protected', `$null)

# Or use Set-GPPermission to remove specific access:
# Set-GPPermission -Guid '$($item.GPOId)' -TargetName 'Domain Users' -TargetType Group -PermissionLevel None

"@
            }
            return $commands
        }
    }
}
