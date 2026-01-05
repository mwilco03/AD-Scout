@{
    Id          = 'PKI-ESC7-CAACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC7 - Vulnerable Certificate Authority Access Control'
    Description = 'Detects Certificate Authorities where low-privileged users have dangerous permissions such as ManageCA or ManageCertificates. ManageCA allows enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6). ManageCertificates allows approving pending requests, bypassing approval requirements.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'CertificateAuthorities'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC7'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'CA Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')
        Techniques = @('T1649', 'T1098')
    }

    CIS   = @('5.3.6')
    STIG  = @('V-220975')
    ANSSI = @('R70')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # CA rights to check
        # ManageCA = 0x01
        # ManageCertificates = 0x02

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $caPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

            $cas = Get-ADObject -SearchBase $caPath -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties * -ErrorAction SilentlyContinue

            foreach ($ca in $cas) {
                $acl = Get-Acl "AD:$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
                $vulnerableACEs = @()

                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Deny') { continue }

                    # Check for CA management rights
                    $hasManageCA = $ace.ActiveDirectoryRights -match 'GenericAll' -or
                                   ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and
                                    ($ace.ObjectType -eq '00000000-0000-0000-0000-000000000000' -or
                                     $ace.ObjectType -eq $null))

                    $hasWriteAccess = $ace.ActiveDirectoryRights -match 'GenericWrite|WriteDacl|WriteOwner|WriteProperty'

                    if ($hasManageCA -or $hasWriteAccess) {
                        $principal = $ace.IdentityReference.Value

                        # Check if low-privileged
                        if ($principal -match 'Authenticated Users|Domain Users|Domain Computers|Everyone|Users') {
                            $vulnerableACEs += [PSCustomObject]@{
                                Principal   = $principal
                                Rights      = $ace.ActiveDirectoryRights.ToString()
                                Capability  = if ($hasManageCA) { 'ManageCA (can enable ESC6)' } else { 'WriteDACL/WriteOwner' }
                            }
                        }
                    }
                }

                if ($vulnerableACEs.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        CAName              = $ca.Name
                        CADisplayName       = $ca.displayName
                        CADNSHostName       = $ca.dNSHostName
                        DistinguishedName   = $ca.DistinguishedName
                        VulnerabilityType   = 'ESC7 - CA ACL Vulnerability'
                        VulnerableACEs      = ($vulnerableACEs | ForEach-Object { "$($_.Principal): $($_.Capability)" }) -join '; '
                        RiskLevel           = 'Critical'
                        AttackPaths         = @(
                            'ManageCA: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 -> ESC6',
                            'ManageCertificates: Approve pending requests -> bypass approval',
                            'WriteDACL: Grant self ManageCA rights -> above attacks'
                        ) -join '; '
                    }
                }
            }
        }
        catch {
            # AD CS may not be installed
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove ManageCA and ManageCertificates rights from low-privileged users on Certificate Authorities.'
        Impact      = 'Low - Only affects CA management capabilities'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC7 - VULNERABLE CA ACL
# ================================================================
# Dangerous permissions on the CA object allow:
#
# ManageCA (CA Administrator):
# - Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (creates ESC6)
# - Install/uninstall CA
# - Modify CA configuration
#
# ManageCertificates (Certificate Manager):
# - Approve/deny pending certificate requests
# - Revoke certificates
# - Bypass manager approval requirements

# ================================================================
# VULNERABLE CAS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# CA: $($item.CAName)
# Host: $($item.CADNSHostName)
# Vulnerable ACEs: $($item.VulnerableACEs)
# Attack Paths: $($item.AttackPaths)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# Check current CA permissions:
# Open certsrv.msc on the CA
# Right-click CA > Properties > Security tab

# OR via certutil:
# certutil -config "CA\CAName" -getreg CA\Security

# Remove dangerous principals from:
# - Certificate Managers (ManageCertificates)
# - CA Administrators (ManageCA)

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# For CA: $($item.CAName)
`$caDN = "$($item.DistinguishedName)"
`$acl = Get-Acl "AD:`$caDN"

# Remove dangerous ACEs:
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -match 'Authenticated Users|Domain Users|Everyone' -and
    `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply changes:
# Set-Acl "AD:`$caDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# BEST PRACTICES
# ================================================================

# CA Administrators should be:
# - Dedicated PKI admin accounts
# - Members of a specific "PKI Admins" group
# - NOT regular Domain Admins (separation of duties)

# Certificate Managers (if used) should be:
# - Specific individuals responsible for cert approval
# - Documented and audited
# - Trained on what to approve/deny

# ================================================================
# MONITORING
# ================================================================

# Monitor for CA configuration changes:
# - Event ID 4899 (CA policy change)
# - Event ID 4900 (CA security change)
# - Changes to EditFlags registry key

"@
            return $commands
        }
    }
}
