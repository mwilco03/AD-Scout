<#
.SYNOPSIS
    Detects ESC7 - Vulnerable CA access control.

.DESCRIPTION
    Identifies Certificate Authority configurations where non-privileged users have
    dangerous permissions such as ManageCA or ManageCertificates rights. These rights
    allow attackers to issue arbitrary certificates or modify CA configuration.

.NOTES
    Rule ID    : C-ESC7-CAACL
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC7-CAACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC7 - Vulnerable CA Access Control'
    Description = 'Identifies Certificate Authorities where non-privileged users have ManageCA or ManageCertificates rights, allowing unauthorized certificate issuance or CA configuration changes.'
    Severity    = 'Critical'
    Weight      = 90
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC7'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'CA Permissions and Rights'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-authority-role-service' }
        @{ Title = 'Certipy ESC7 Exploitation'; Url = 'https://github.com/ly4k/Certipy' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003', 'TA0006')  # Privilege Escalation, Persistence, Credential Access
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @('5.18')
    STIG  = @('V-73805')
    ANSSI = @('vuln1_adcs_esc7')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # CA rights that are dangerous for non-admins
        # Reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786426(v=ws.11)
        $dangerousCARights = @{
            'ManageCA' = 'Can modify CA configuration, add/remove templates, change security settings'
            'ManageCertificates' = 'Can issue, revoke, and manage certificates - enables ESC7 attack'
            'Issue and Manage Certificates' = 'Can approve pending requests and issue certificates'
        }

        # Legitimate principals for CA management
        $legitimatePrincipals = @(
            'Enterprise Admins'
            'Domain Admins'
            'Administrators'
            'SYSTEM'
            'Cert Publishers'
            'Certificate Service DCOM Access'
        )

        if ($Data.CertificateAuthorities) {
            foreach ($ca in $Data.CertificateAuthorities) {
                $caName = $ca.Name
                if (-not $caName) { $caName = $ca.DisplayName }
                if (-not $caName) { continue }

                # Check CA security permissions
                $caSecurityDescriptor = $ca.Security
                if (-not $caSecurityDescriptor) {
                    # Try to get from the CA object
                    try {
                        $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                        $caEnrollmentDN = "CN=$caName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
                        $caObj = [ADSI]"LDAP://$caEnrollmentDN"
                        $caSecurityDescriptor = $caObj.ObjectSecurity
                    } catch {
                        continue
                    }
                }

                if (-not $caSecurityDescriptor) { continue }

                foreach ($ace in $caSecurityDescriptor.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    $identity = $ace.IdentityReference.Value
                    $rights = $ace.ActiveDirectoryRights.ToString()

                    # Check for ManageCA/ManageCertificates style rights
                    $hasDangerousRights = $false
                    $dangerousRight = ''

                    # ExtendedRight with specific GUIDs or generic dangerous rights
                    if ($rights -match 'ExtendedRight') {
                        # ManageCA GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                        # ManageCertificates GUID: 0e10c967-78fb-11d2-90d4-00c04f79dc55
                        $objectType = $ace.ObjectType.ToString().ToLower()

                        if ($objectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') {
                            $hasDangerousRights = $true
                            $dangerousRight = 'ManageCA'
                        } elseif ($objectType -eq '0e10c967-78fb-11d2-90d4-00c04f79dc55') {
                            $hasDangerousRights = $true
                            $dangerousRight = 'ManageCertificates'
                        }
                    }

                    # Also check for GenericAll which includes all CA rights
                    if ($rights -match 'GenericAll') {
                        $hasDangerousRights = $true
                        $dangerousRight = 'GenericAll (includes ManageCA and ManageCertificates)'
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

                    # Also check SID-based legitimacy
                    if (-not $isLegitimate) {
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                            # Check for privileged SIDs
                            if ($sid -match '-512$' -or $sid -match '-519$' -or $sid -eq 'S-1-5-32-544' -or $sid -eq 'S-1-5-18') {
                                $isLegitimate = $true
                            }
                        } catch {
                            # Can't resolve, assume not legitimate
                        }
                    }

                    if (-not $isLegitimate) {
                        $riskDescription = if ($dangerousCARights.ContainsKey($dangerousRight)) {
                            $dangerousCARights[$dangerousRight]
                        } else {
                            'Full CA control'
                        }

                        $findings += [PSCustomObject]@{
                            CAName              = $caName
                            Principal           = $identity
                            DangerousRight      = $dangerousRight
                            RiskDescription     = $riskDescription
                            AttackPath          = if ($dangerousRight -match 'ManageCertificates') {
                                'ESC7: Attacker can issue certificates directly or approve pending requests'
                            } else {
                                'ESC7: Attacker can modify CA configuration and enable vulnerable settings'
                            }
                            RiskLevel           = 'Critical'
                            DistinguishedName   = $ca.DistinguishedName
                        }
                    }
                }

                # Also check for EDITF_ATTRIBUTESUBJECTALTNAME2 flag which is related
                if ($ca.Flags -band 0x00040000) {  # EDITF_ATTRIBUTESUBJECTALTNAME2
                    $findings += [PSCustomObject]@{
                        CAName              = $caName
                        Principal           = 'CA Configuration'
                        DangerousRight      = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
                        RiskDescription     = 'CA allows specifying SAN in certificate requests'
                        AttackPath          = 'ESC6/ESC7: Any user with enroll rights can specify arbitrary SAN values'
                        RiskLevel           = 'Critical'
                        DistinguishedName   = $ca.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove ManageCA and ManageCertificates rights from non-privileged users. These rights should only be granted to dedicated PKI administrators.'
        Impact      = 'High - May affect delegated CA management workflows.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC7 - CA Access Control Vulnerabilities
#############################################################################
#
# Non-privileged users have dangerous CA management rights:
#
# ManageCA Rights:
# - Modify CA configuration
# - Add/remove certificate templates
# - Change CA security settings
# - Enable EDITF_ATTRIBUTESUBJECTALTNAME2
#
# ManageCertificates Rights:
# - Issue certificates directly
# - Approve pending certificate requests
# - Revoke any certificate
# - Export private keys (if enabled)
#
# Attack Path:
# 1. Use ManageCertificates to approve/issue certs for any user
# 2. Use ManageCA to enable EDITF flag then request as any user
# 3. Use forged certificate to authenticate as Domain Admin
#
#############################################################################

# Affected CAs:
$($Finding.Findings | ForEach-Object { "# - $($_.CAName): $($_.Principal) has $($_.DangerousRight)" } | Out-String)

"@

            foreach ($item in $Finding.Findings) {
                if ($item.DangerousRight -eq 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
                    $commands += @"

#############################################################################
# CA: $($item.CAName)
# Issue: EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled
#############################################################################

# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag
certutil -config "$($item.CAName)" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc

# Verify the change
certutil -config "$($item.CAName)" -getreg policy\EditFlags

"@
                } else {
                    $commands += @"

#############################################################################
# CA: $($item.CAName)
# Principal: $($item.Principal)
# Rights: $($item.DangerousRight)
#############################################################################

# Remove CA permissions using certutil
# First, view current permissions:
certutil -config "$($item.CAName)" -getconfig CAPolicy

# Use the Certification Authority MMC snap-in:
# 1. Open certsrv.msc
# 2. Right-click CA > Properties > Security tab
# 3. Remove '$($item.Principal)' or uncheck Manage CA/Manage Certificates

# Or using PowerShell PSPKI module:
Import-Module PSPKI
`$ca = Get-CertificationAuthority -Name '$($item.CAName)'
`$ca | Get-CertificationAuthorityAcl | Format-List

# Remove specific permission:
# `$ca | Get-CertificationAuthorityAcl |
#     Remove-CertificationAuthorityAcl -Identity '$($item.Principal)' -Confirm:`$false

"@
                }
            }

            $commands += @"

#############################################################################
# CA Security Best Practices
#############################################################################

# 1. ManageCA should only be granted to:
#    - Enterprise Admins
#    - Dedicated PKI Administrator accounts
#    - NEVER to regular IT staff or service accounts

# 2. ManageCertificates should be limited to:
#    - Dedicated certificate operators
#    - Only when certificate approval workflow is required

# 3. Use separate admin accounts for PKI management
#    (Tier 0 in the administrative tier model)

# 4. Enable CA auditing for all certificate operations

# 5. Review CA permissions regularly (at least quarterly)

# Audit current CA permissions across all CAs:
Import-Module PSPKI
Get-CertificationAuthority | ForEach-Object {
    Write-Host "`n=== `$(`$_.DisplayName) ===" -ForegroundColor Cyan
    `$_ | Get-CertificationAuthorityAcl | Format-Table Identity, Rights, AccessControlType
}

"@
            return $commands
        }
    }
}
