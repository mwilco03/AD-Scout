@{
    Id          = 'PKI-ESC5-PKIObjectACL'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC5 - Vulnerable PKI AD Object Access Control'
    Description = 'Detects PKI-related Active Directory objects (CA server computer object, PKI containers) where low-privileged users have write permissions. Compromising these objects can lead to CA takeover or PKI configuration manipulation.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Certified Pre-Owned - ESC5'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PKI Object Security'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')
        Techniques = @('T1649', 'T1484')
    }

    CIS   = @('5.3.8')
    STIG  = @('V-220977')
    ANSSI = @('R72')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $dangerousRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteProperty',
            'WriteDacl',
            'WriteOwner'
        )

        try {
            $configNC = (Get-ADRootDSE).configurationNamingContext

            # Objects to check
            $pkiObjects = @(
                @{ Path = "CN=Public Key Services,CN=Services,$configNC"; Type = 'PKI Container' },
                @{ Path = "CN=AIA,CN=Public Key Services,CN=Services,$configNC"; Type = 'AIA Container' },
                @{ Path = "CN=CDP,CN=Public Key Services,CN=Services,$configNC"; Type = 'CDP Container' },
                @{ Path = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC"; Type = 'Trusted Root CAs' },
                @{ Path = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"; Type = 'NTAuth Certificates' }
            )

            foreach ($obj in $pkiObjects) {
                try {
                    $adObj = Get-ADObject -Identity $obj.Path -Properties * -ErrorAction SilentlyContinue
                    if (-not $adObj) { continue }

                    $acl = Get-Acl "AD:$($obj.Path)" -ErrorAction SilentlyContinue
                    $vulnerableACEs = @()

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        $hasDangerousRight = $false
                        foreach ($right in $dangerousRights) {
                            if ($ace.ActiveDirectoryRights -match $right) {
                                $hasDangerousRight = $true
                                break
                            }
                        }

                        if (-not $hasDangerousRight) { continue }

                        $principal = $ace.IdentityReference.Value
                        if ($principal -match 'Authenticated Users|Domain Users|Domain Computers|Everyone|Users') {
                            $vulnerableACEs += [PSCustomObject]@{
                                Principal = $principal
                                Rights    = $ace.ActiveDirectoryRights.ToString()
                            }
                        }
                    }

                    if ($vulnerableACEs.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = $obj.Type
                            ObjectDN            = $obj.Path
                            VulnerabilityType   = 'ESC5 - PKI Object Write Access'
                            VulnerableACEs      = ($vulnerableACEs | ForEach-Object { "$($_.Principal): $($_.Rights)" }) -join '; '
                            RiskLevel           = 'High'
                            Impact              = switch ($obj.Type) {
                                'PKI Container'      { 'Control over all PKI configuration' }
                                'AIA Container'      { 'Can manipulate CA certificate distribution' }
                                'CDP Container'      { 'Can manipulate CRL distribution' }
                                'Trusted Root CAs'   { 'Can add rogue trusted root CAs' }
                                'NTAuth Certificates'{ 'Can add certificates trusted for AD authentication' }
                                default              { 'Unknown impact' }
                            }
                        }
                    }
                }
                catch {
                    # Object may not exist
                }
            }

            # Check CA computer objects
            $caPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
            $cas = Get-ADObject -SearchBase $caPath -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties dNSHostName -ErrorAction SilentlyContinue

            foreach ($ca in $cas) {
                $caHostname = $ca.dNSHostName
                $caComputer = Get-ADComputer -Filter "DNSHostName -eq '$caHostname'" -Properties * -ErrorAction SilentlyContinue

                if ($caComputer) {
                    $acl = Get-Acl "AD:$($caComputer.DistinguishedName)" -ErrorAction SilentlyContinue
                    $vulnerableACEs = @()

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        $hasDangerousRight = $false
                        foreach ($right in $dangerousRights) {
                            if ($ace.ActiveDirectoryRights -match $right) {
                                $hasDangerousRight = $true
                                break
                            }
                        }

                        if (-not $hasDangerousRight) { continue }

                        $principal = $ace.IdentityReference.Value
                        if ($principal -match 'Authenticated Users|Domain Users|Domain Computers|Everyone|Users') {
                            $vulnerableACEs += [PSCustomObject]@{
                                Principal = $principal
                                Rights    = $ace.ActiveDirectoryRights.ToString()
                            }
                        }
                    }

                    if ($vulnerableACEs.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = 'CA Computer Object'
                            ObjectDN            = $caComputer.DistinguishedName
                            CAName              = $ca.Name
                            VulnerabilityType   = 'ESC5 - CA Computer Object Write Access'
                            VulnerableACEs      = ($vulnerableACEs | ForEach-Object { "$($_.Principal): $($_.Rights)" }) -join '; '
                            RiskLevel           = 'Critical'
                            Impact              = 'Write access to CA computer = potential RBCD attack or credential theft'
                        }
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
        Description = 'Remove write permissions from low-privileged users on PKI AD objects.'
        Impact      = 'Low - Only affects PKI object management'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ESC5 - VULNERABLE PKI AD OBJECTS
# ================================================================
# PKI infrastructure objects in AD should be protected.
# Write access allows:
# - NTAuthCertificates: Add certs trusted for AD auth
# - Certification Authorities: Add rogue root CAs
# - CA Computer Object: RBCD attack against CA

# ================================================================
# VULNERABLE OBJECTS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Object: $($item.ObjectType)
# DN: $($item.ObjectDN)
# Vulnerable ACEs: $($item.VulnerableACEs)
# Impact: $($item.Impact)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Object: $($item.ObjectDN)
`$objDN = "$($item.ObjectDN)"
`$acl = Get-Acl "AD:`$objDN"

# Remove dangerous ACEs:
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -match 'Authenticated Users|Domain Users|Everyone' -and
    `$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner'
} | ForEach-Object {
    `$acl.RemoveAccessRule(`$_)
}

# Apply:
# Set-Acl "AD:`$objDN" `$acl

"@
            }

            $commands += @"

# ================================================================
# NTAUTHCERTIFICATES PROTECTION
# ================================================================

# NTAuthCertificates is CRITICAL - certificates here are trusted
# for smart card logon and other AD authentication.
#
# If attacker can write here, they can add their own CA cert
# and issue certificates trusted by AD.

`$ntAuthDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"

# View current certificates:
certutil -viewstore -enterprise NTAuth

# Only Enterprise Admins and PKI Admins should have write access

# ================================================================
# CA COMPUTER PROTECTION
# ================================================================

# CA computer objects should be:
# - In a protected OU (Tier 0)
# - With restricted write access
# - Monitored for RBCD attacks (msDS-AllowedToActOnBehalfOfOtherIdentity)

# Check for RBCD on CA computers:
Get-ADComputer -Filter "ServicePrincipalName -like '*certsvc*'" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { `$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
    Select-Object Name, @{N='RBCD';E={`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access}}

"@
            return $commands
        }
    }
}
