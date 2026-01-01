<#
.SYNOPSIS
    Detects ESC5 - Vulnerable PKI object ACLs.

.DESCRIPTION
    Identifies vulnerable permissions on PKI objects including CA server objects,
    NTAuthCertificates, and PKI containers. These permissions can allow attackers
    to compromise the entire PKI infrastructure.

.NOTES
    Rule ID    : C-ESC5-PKIObjectACL
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC5-PKIObjectACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC5 - Vulnerable PKI Object ACLs'
    Description = 'Identifies vulnerable permissions on critical PKI objects including CA objects, NTAuthCertificates, and PKI containers that could lead to PKI infrastructure compromise.'
    Severity    = 'Critical'
    Weight      = 80
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC5'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PKI Object Permissions'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/' }
        @{ Title = 'ADCS Exploitation - ESC5'; Url = 'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003', 'TA0006')  # Privilege Escalation, Persistence, Credential Access
        Techniques = @('T1649', 'T1222.001')  # Steal or Forge Authentication Certificates
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_adcs_esc5')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous rights for PKI objects
        $dangerousRights = @(
            'WriteDacl'
            'WriteOwner'
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
        )

        # Legitimate principals for PKI objects
        $legitimatePrincipals = @(
            'Enterprise Admins'
            'Domain Admins'
            'Administrators'
            'SYSTEM'
            'Cert Publishers'
            'Enterprise Read-only Domain Controllers'
        )

        try {
            $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext

            # Check PKI containers
            $pkiContainers = @(
                "CN=Public Key Services,CN=Services,$configNC"
                "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
                "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
                "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"
                "CN=AIA,CN=Public Key Services,CN=Services,$configNC"
                "CN=CDP,CN=Public Key Services,CN=Services,$configNC"
            )

            foreach ($containerDN in $pkiContainers) {
                try {
                    $container = [ADSI]"LDAP://$containerDN"
                    if (-not $container.Path) { continue }

                    $acl = $container.ObjectSecurity

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        $identity = $ace.IdentityReference.Value
                        $rights = $ace.ActiveDirectoryRights.ToString()

                        # Check for dangerous rights
                        $hasDangerousRights = $false
                        $grantedRights = @()

                        foreach ($dangerousRight in $dangerousRights) {
                            if ($rights -match $dangerousRight) {
                                $hasDangerousRights = $true
                                $grantedRights += $dangerousRight
                            }
                        }

                        if (-not $hasDangerousRights) { continue }

                        # Check if principal is legitimate
                        $isLegitimate = $false
                        foreach ($legitPrincipal in $legitimatePrincipals) {
                            if ($identity -like "*$legitPrincipal*") {
                                $isLegitimate = $true
                                break
                            }
                        }

                        if (-not $isLegitimate) {
                            $containerName = ($containerDN -split ',')[0] -replace 'CN='

                            $findings += [PSCustomObject]@{
                                ObjectType          = 'PKI Container'
                                ObjectName          = $containerName
                                Principal           = $identity
                                DangerousRights     = ($grantedRights -join ', ')
                                Inherited           = $ace.IsInherited
                                RiskLevel           = 'Critical'
                                Impact              = switch ($containerName) {
                                    'NTAuthCertificates' { 'Can add rogue CA - enables Golden Certificate attacks' }
                                    'Certificate Templates' { 'Can add/modify templates for privilege escalation' }
                                    'Enrollment Services' { 'Can modify CA enrollment settings' }
                                    'Public Key Services' { 'Full PKI infrastructure control' }
                                    default { 'Can modify PKI configuration' }
                                }
                                DistinguishedName   = $containerDN
                            }
                        }
                    }
                } catch {
                    # Container doesn't exist or access denied
                }
            }

            # Check CA server computer objects
            if ($Data.CertificateAuthorities) {
                foreach ($ca in $Data.CertificateAuthorities) {
                    $caName = $ca.Name
                    if (-not $caName) { $caName = $ca.DisplayName }

                    # Find the CA's computer object
                    try {
                        $caComputer = Get-ADComputer -Filter "Name -eq '$caName'" -Properties nTSecurityDescriptor -ErrorAction Stop
                        if ($caComputer) {
                            $acl = $caComputer.nTSecurityDescriptor

                            foreach ($ace in $acl.Access) {
                                if ($ace.AccessControlType -ne 'Allow') { continue }

                                $identity = $ace.IdentityReference.Value
                                $rights = $ace.ActiveDirectoryRights.ToString()

                                # Check for dangerous rights
                                $hasDangerousRights = $false
                                $grantedRights = @()

                                foreach ($dangerousRight in $dangerousRights) {
                                    if ($rights -match $dangerousRight) {
                                        $hasDangerousRights = $true
                                        $grantedRights += $dangerousRight
                                    }
                                }

                                if (-not $hasDangerousRights) { continue }

                                # Check if principal is legitimate
                                $isLegitimate = $false
                                foreach ($legitPrincipal in $legitimatePrincipals) {
                                    if ($identity -like "*$legitPrincipal*") {
                                        $isLegitimate = $true
                                        break
                                    }
                                }

                                if (-not $isLegitimate) {
                                    $findings += [PSCustomObject]@{
                                        ObjectType          = 'CA Computer Object'
                                        ObjectName          = $caName
                                        Principal           = $identity
                                        DangerousRights     = ($grantedRights -join ', ')
                                        Inherited           = $ace.IsInherited
                                        RiskLevel           = 'Critical'
                                        Impact              = 'Can compromise CA server - enables certificate forgery'
                                        DistinguishedName   = $caComputer.DistinguishedName
                                    }
                                }
                            }
                        }
                    } catch {
                        # CA computer not found in AD
                    }
                }
            }

        } catch {
            # Unable to enumerate PKI objects
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove dangerous permissions from PKI objects. Only Enterprise Admins should have full control over PKI infrastructure.'
        Impact      = 'High - May affect PKI administration workflows. Test changes in non-production first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC5 - PKI Object ACL Vulnerabilities
#############################################################################
#
# Critical PKI objects have vulnerable permissions that allow:
# - Adding rogue CAs to NTAuthCertificates (Golden Certificate)
# - Modifying certificate templates
# - Compromising CA server configuration
# - Complete PKI infrastructure takeover
#
#############################################################################

# Affected Objects:
$($Finding.Findings | ForEach-Object { "# - $($_.ObjectName) ($($_.ObjectType)): $($_.Principal) has $($_.DangerousRights)" } | Out-String)

# Review PKI object permissions
`$configNC = (Get-ADRootDSE).configurationNamingContext

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

#############################################################################
# Object: $($item.ObjectName) ($($item.ObjectType))
# Principal: $($item.Principal)
# Rights: $($item.DangerousRights)
# Impact: $($item.Impact)
#############################################################################

# View current ACL
`$obj = [ADSI]"LDAP://$($item.DistinguishedName)"
`$obj.ObjectSecurity.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)'
} | Format-List

# Remove the dangerous ACE
`$acl = `$obj.ObjectSecurity
`$aceToRemove = `$acl.Access | Where-Object {
    `$_.IdentityReference.Value -eq '$($item.Principal)' -and
    `$_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll|GenericWrite'
}
foreach (`$ace in `$aceToRemove) {
    `$acl.RemoveAccessRule(`$ace)
}
`$obj.ObjectSecurity = `$acl
`$obj.CommitChanges()

"@
            }

            $commands += @"

#############################################################################
# Protect NTAuthCertificates (Critical)
#############################################################################

# NTAuthCertificates contains the list of trusted CAs for domain authentication
# Only Enterprise Admins should have write access

`$ntAuthDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,`$configNC"
`$ntAuth = [ADSI]"LDAP://`$ntAuthDN"

Write-Host "Current NTAuthCertificates permissions:" -ForegroundColor Cyan
`$ntAuth.ObjectSecurity.Access | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType

# Monitor for NTAuthCertificates modifications (Event ID 5136)
# This is critical for detecting Golden Certificate attacks

#############################################################################
# Best Practices
#############################################################################

# 1. Only Enterprise Admins should have write access to PKI objects
# 2. Enable auditing on all PKI containers
# 3. Monitor for certificate template changes
# 4. Review CA security configuration regularly
# 5. Use separate accounts for PKI administration

"@
            return $commands
        }
    }
}
