@{
    Id          = 'A-LAPSPermissions'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Excessive LAPS Password Read Permissions'
    Description = 'Detects accounts or groups with permissions to read LAPS passwords that should not have this access. Excessive LAPS read permissions allow attackers to retrieve local admin passwords for lateral movement.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'ACLs'

    References  = @(
        @{ Title = 'LAPS Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-security' }
        @{ Title = 'LAPS Privilege Escalation'; Url = 'https://adsecurity.org/?p=3164' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1003', 'T1078.003')  # Credential Dumping, Local Accounts
    }

    CIS   = @('5.6.2')
    STIG  = @('V-220951')
    ANSSI = @('R49')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Expected principals that should have LAPS read access
        $expectedPrincipals = @(
            'Domain Admins',
            'Enterprise Admins',
            'LAPS Admins',
            'LAPS Password Readers',
            'Workstation Admins',
            'Server Admins',
            'Helpdesk'  # Often legitimately needs this
        )

        # LAPS attribute GUIDs
        # Legacy LAPS: ms-Mcs-AdmPwd
        # Windows LAPS: msLAPS-Password, msLAPS-EncryptedPassword

        # Check OU-level permissions for LAPS attributes
        if ($Data.OUPermissions) {
            foreach ($ou in $Data.OUPermissions) {
                foreach ($ace in $ou.AccessRules) {
                    # Check if this grants access to LAPS attributes
                    $isLAPSAccess = $false

                    if ($ace.ObjectType -match 'ms-Mcs-AdmPwd|msLAPS-Password|msLAPS-EncryptedPassword') {
                        $isLAPSAccess = $true
                    }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|ReadProperty' -and $isLAPSAccess) {
                        # Check if this is an unexpected principal
                        $isExpected = $false
                        foreach ($expected in $expectedPrincipals) {
                            if ($ace.IdentityReference -match $expected) {
                                $isExpected = $true
                                break
                            }
                        }

                        if (-not $isExpected) {
                            $findings += [PSCustomObject]@{
                                OU                  = $ou.DistinguishedName
                                Principal           = $ace.IdentityReference
                                AccessType          = $ace.AccessControlType
                                Rights              = $ace.ActiveDirectoryRights
                                LAPSAttribute       = 'LAPS Password Read'
                                IsInherited         = $ace.IsInherited
                                RiskLevel           = 'High'
                                Risk                = 'Can read local admin passwords for systems in this OU'
                                Recommendation      = 'Remove if not authorized'
                            }
                        }
                    }
                }
            }
        }

        # Alternative: Query directly for LAPS read permissions
        try {
            $rootDSE = Get-ADRootDSE
            $defaultNC = $rootDSE.defaultNamingContext

            # Get OUs and check their ACLs
            $ous = Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor

            foreach ($ou in $ous) {
                $acl = $ou.nTSecurityDescriptor

                foreach ($ace in $acl.Access) {
                    # Check for LAPS attribute access
                    if ($ace.ObjectType -match '(ms-Mcs-AdmPwd|msLAPS)' -or
                        ($ace.ActiveDirectoryRights -match 'GenericAll' -and $ace.ObjectType -eq [Guid]::Empty)) {

                        $identity = $ace.IdentityReference.Value

                        # Skip expected principals
                        $isExpected = $false
                        foreach ($expected in $expectedPrincipals) {
                            if ($identity -match $expected) {
                                $isExpected = $true
                                break
                            }
                        }

                        # Skip well-known system accounts
                        if ($identity -match 'SYSTEM|SELF|CREATOR OWNER|Domain Controllers') {
                            $isExpected = $true
                        }

                        if (-not $isExpected -and $ace.AccessControlType -eq 'Allow') {
                            $findings += [PSCustomObject]@{
                                OU                  = $ou.DistinguishedName
                                Principal           = $identity
                                AccessType          = $ace.AccessControlType
                                Rights              = $ace.ActiveDirectoryRights
                                IsInherited         = $ace.IsInherited
                                RiskLevel           = 'High'
                                Risk                = 'Unauthorized LAPS password access'
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Continue with available data
        }

        return $findings | Sort-Object -Property OU, Principal -Unique
    }

    Remediation = @{
        Description = 'Review and remove excessive LAPS read permissions. Implement least-privilege access to LAPS passwords.'
        Impact      = 'Medium - May affect legitimate admin access if removed incorrectly'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# LAPS PERMISSION REVIEW
# ================================================================
# Only specific admin groups should be able to read LAPS passwords.
# Excessive access allows lateral movement via local admin passwords.

# ================================================================
# AUDIT CURRENT LAPS PERMISSIONS
# ================================================================

# Find who can read LAPS passwords:
Import-Module LAPS -ErrorAction SilentlyContinue

# For Windows LAPS:
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=domain,DC=com"

# For Legacy LAPS:
Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=domain,DC=com"

# ================================================================
# IDENTIFIED EXCESSIVE PERMISSIONS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# OU: $($item.OU)
# Principal: $($item.Principal)
# Rights: $($item.Rights)
# Inherited: $($item.IsInherited)

# To remove (if not inherited):
`$acl = Get-ACL "AD:\$($item.OU)"
`$aceToRemove = `$acl.Access | Where-Object { `$_.IdentityReference -eq '$($item.Principal)' }
`$acl.RemoveAccessRule(`$aceToRemove)
Set-ACL "AD:\$($item.OU)" -AclObject `$acl

"@
            }

            $commands += @"

# ================================================================
# SET CORRECT PERMISSIONS
# ================================================================

# Remove all current read permissions:
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=domain,DC=com" -AllowedPrincipals @()

# Grant to appropriate groups only:
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=domain,DC=com" ``
    -AllowedPrincipals "Workstation Admins"

Set-LapsADReadPasswordPermission -Identity "OU=Servers,DC=domain,DC=com" ``
    -AllowedPrincipals "Server Admins"

# ================================================================
# BEST PRACTICE: Use Just-In-Time Access
# ================================================================

# Instead of permanent LAPS read access:
# 1. Use Azure AD PIM for time-limited access
# 2. Implement PAM solution with approval workflow
# 3. Use PowerShell JEA for constrained access

"@
            return $commands
        }
    }
}
