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
        )

        $findings = @()

        foreach ($ace in $Data.ACL) {
            $trusteeName = $ace.IdentityReference.Value

            # Check if this is a non-default trustee
            $isDefault = $false
            foreach ($defaultTrustee in $defaultTrustees) {
                if ($trusteeName -like "*\$defaultTrustee" -or $trusteeName -eq $defaultTrustee) {
                    $isDefault = $true
                    break
                }
            }

            if (-not $isDefault -and $ace.AccessControlType -eq 'Allow') {
                $findings += [PSCustomObject]@{
                    Trustee      = $trusteeName
                    Rights       = $ace.ActiveDirectoryRights
                    Inherited    = $ace.IsInherited
                    ObjectType   = $ace.ObjectType
                }
            }
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
