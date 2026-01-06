@{
    Id          = 'P-AdminSDHolder'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'AdminSDHolder ACL Modifications'
    Description = 'Detects non-default permissions on the AdminSDHolder container. Attackers modify AdminSDHolder to maintain persistent access to privileged accounts.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'AdminSDHolder'

    References  = @(
        @{ Title = 'AdminSDHolder, Protected Groups and SDPROP'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
        @{ Title = 'Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp'; Url = 'https://adsecurity.org/?p=1906' }
    )

    MITRE = @{
        Tactics    = @('TA0003')  # Persistence
        Techniques = @('T1098')   # Account Manipulation
    }

    CIS   = @('5.1')
    STIG  = @('V-36432')
    ANSSI = @('vuln1_intruders_bad_admincount')
    NIST  = @('AC-3', 'SI-7')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        # Default allowed trustees on AdminSDHolder
        $defaultTrustees = @(
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'SYSTEM'
            'Account Operators'
            'Backup Operators'
            'Print Operators'
            'Server Operators'
            'Replicator'
            'ENTERPRISE DOMAIN CONTROLLERS'
        )

        # Legitimate SIDs that are always expected
        $legitimateSIDs = @(
            'S-1-5-32-544'      # Administrators
            'S-1-5-18'          # SYSTEM
            'S-1-5-9'           # Enterprise DCs
            'S-1-5-32-548'      # Account Operators
            'S-1-5-32-551'      # Backup Operators
            'S-1-5-32-550'      # Print Operators
            'S-1-5-32-549'      # Server Operators
        )

        $findings = @()

        try {
            # Get AdminSDHolder ACL directly via ADSI
            $domainDN = $null
            if ($Domain.DistinguishedName) {
                $domainDN = $Domain.DistinguishedName
            } else {
                $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            }

            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
            $adminSDHolder = [ADSI]"LDAP://$adminSDHolderDN"
            $acl = $adminSDHolder.ObjectSecurity

            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $trusteeName = $ace.IdentityReference.Value

                # Check if this is a default trustee
                $isDefault = $false
                foreach ($defaultTrustee in $defaultTrustees) {
                    if ($trusteeName -like "*\$defaultTrustee" -or $trusteeName -eq $defaultTrustee -or $trusteeName -like "*$defaultTrustee") {
                        $isDefault = $true
                        break
                    }
                }

                # Check by SID if not matched by name
                if (-not $isDefault) {
                    try {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($trusteeName)
                        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                        foreach ($legitSID in $legitimateSIDs) {
                            if ($sid -eq $legitSID) {
                                $isDefault = $true
                                break
                            }
                        }

                        # Check domain-relative privileged SIDs
                        if ($sid -match '-512$' -or $sid -match '-519$') {
                            $isDefault = $true
                        }
                    } catch {
                        # Can't resolve SID, keep checking
                    }
                }

                if (-not $isDefault) {
                    $findings += [PSCustomObject]@{
                        Trustee               = $trusteeName
                        Rights                = $ace.ActiveDirectoryRights.ToString()
                        Inherited             = $ace.IsInherited
                        ObjectType            = $ace.ObjectType.ToString()
                        RiskLevel             = 'Critical'
                        DistinguishedName     = $adminSDHolderDN
                        AttackType            = 'AdminSDHolder Persistence'
                    }
                }
            }
        } catch {
            # Can't access AdminSDHolder - likely permissions issue
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove unauthorized permissions from the AdminSDHolder container. Only domain default groups should have access.'
        Impact      = 'High - Changes will propagate to all protected accounts within 60 minutes'
        Script      = {
            param($Finding, $Domain)

            # Generate remediation commands
            $commands = @()
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Remove unauthorized ACE for: $($item.Trustee)

`$adminSDHolder = Get-ADObject -Filter 'Name -eq "AdminSDHolder"' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)"
`$acl = Get-Acl -Path "AD:`$(`$adminSDHolder.DistinguishedName)"
`$aceToRemove = `$acl.Access | Where-Object { `$_.IdentityReference -eq '$($item.Trustee)' }
`$acl.RemoveAccessRule(`$aceToRemove)
Set-Acl -Path "AD:`$(`$adminSDHolder.DistinguishedName)" -AclObject `$acl
"@
            }
            return $commands -join "`n"
        }
    }
}
