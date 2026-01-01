<#
.SYNOPSIS
    Detects long-lived certificates and potential certificate-based persistence.

.DESCRIPTION
    Attackers can use certificates for persistent access since certificates may
    remain valid even after password changes. This rule identifies certificates
    with excessive validity periods and potential backdoor certificates.

.NOTES
    Rule ID    : PERS-CertificateBackdoor
    Category   : Persistence
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'PERS-CertificateBackdoor'
    Version     = '1.0.0'
    Category    = 'Persistence'
    Title       = 'Certificate-Based Persistence'
    Description = 'Identifies certificates with excessive validity periods or suspicious characteristics that could be used for persistent access.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'CertificateAuthorities,Users'

    References  = @(
        @{ Title = 'Certificate Persistence'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PERSIST1 - User Certificate Theft'; Url = 'https://attack.mitre.org/techniques/T1649/' }
        @{ Title = 'Certificate Lifespan'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/managing-certificates-issued-to-accounts' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0006')  # Persistence, Credential Access
        Techniques = @('T1649', 'T1556.005')  # Steal or Forge Authentication Certificates, Domain Controller Authentication
    }

    CIS   = @('5.2.8')
    STIG  = @('V-254452')
    ANSSI = @('R44')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $maxValidityDays = 365  # Certificates over 1 year are suspicious for user auth

        $configNC = "CN=Configuration,$((Get-ADDomain).DistinguishedName)"

        # Check certificate templates for excessive validity
        try {
            $templates = Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } `
                -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
                -Properties * -ErrorAction SilentlyContinue

            foreach ($template in $templates) {
                $issues = @()
                $riskLevel = 'Medium'

                # Check validity period (in 100-nanosecond intervals)
                # pKIExpirationPeriod is stored as negative value
                if ($template.'pKIExpirationPeriod') {
                    $expirationBytes = $template.'pKIExpirationPeriod'
                    # Convert to days (roughly)
                    $validityDays = [math]::Abs([BitConverter]::ToInt64($expirationBytes, 0)) / 864000000000

                    if ($validityDays -gt $maxValidityDays) {
                        $issues += "Validity period: $([math]::Round($validityDays)) days (over 1 year)"

                        if ($validityDays -gt 730) {  # Over 2 years
                            $riskLevel = 'High'
                        }
                        if ($validityDays -gt 1825) {  # Over 5 years
                            $issues += 'EXTREMELY long validity - likely persistence risk'
                            $riskLevel = 'Critical'
                        }
                    }
                }

                # Check if template allows client authentication
                $templateEKUs = $template.'pKIExtendedKeyUsage'
                $authEKUs = @(
                    '1.3.6.1.5.5.7.3.2',   # Client Authentication
                    '1.3.6.1.4.1.311.20.2.2',  # Smart Card Logon
                    '1.3.6.1.5.2.3.4',     # PKINIT Client Auth
                    '2.5.29.37.0'          # Any Purpose
                )

                $hasAuthEKU = $false
                foreach ($eku in $templateEKUs) {
                    if ($eku -in $authEKUs) {
                        $hasAuthEKU = $true
                        break
                    }
                }

                if ($issues.Count -gt 0 -and $hasAuthEKU) {
                    $findings += [PSCustomObject]@{
                        TemplateName      = $template.Name
                        DisplayName       = $template.'displayName'
                        ValidityDays      = [math]::Round($validityDays)
                        AuthenticationEKU = $hasAuthEKU
                        SuppliesSubject   = ($template.'msPKI-Certificate-Name-Flag' -band 1) -eq 1
                        Issues            = ($issues -join '; ')
                        RiskLevel         = $riskLevel
                        PersistenceType   = 'Long-lived Auth Certificate'
                        AttackPath        = 'Enroll cert -> Use for years even after password change'
                        DistinguishedName = $template.DistinguishedName
                    }
                }
            }
        } catch {}

        # Check for recently issued suspicious certificates from CA
        if ($Data.DomainControllers) {
            $dc = $Data.DomainControllers | Select-Object -First 1
            $dcName = if ($dc.Name) { $dc.Name } else { $dc.DnsHostName }

            try {
                # Query CA for issued certificates
                $recentCerts = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $certs = certutil -view -out "RequestID,RequesterName,CommonName,NotAfter,CertificateTemplate" -restrict "Disposition=20" 2>$null

                    $results = @()
                    $currentCert = @{}

                    foreach ($line in $certs) {
                        if ($line -match 'Request ID:\s+(\d+)') {
                            if ($currentCert.RequestID) { $results += [PSCustomObject]$currentCert }
                            $currentCert = @{ RequestID = $Matches[1] }
                        }
                        elseif ($line -match 'Requester Name:\s+"(.+)"') {
                            $currentCert.RequesterName = $Matches[1]
                        }
                        elseif ($line -match 'Issued Common Name:\s+"(.+)"') {
                            $currentCert.CommonName = $Matches[1]
                        }
                        elseif ($line -match 'Certificate Expiration Date:\s+(.+)') {
                            $currentCert.NotAfter = $Matches[1]
                        }
                        elseif ($line -match 'Certificate Template:\s+"(.+)"') {
                            $currentCert.Template = $Matches[1]
                        }
                    }
                    if ($currentCert.RequestID) { $results += [PSCustomObject]$currentCert }

                    return $results | Select-Object -First 50
                } -ErrorAction SilentlyContinue

                foreach ($cert in $recentCerts) {
                    try {
                        $expDate = [DateTime]$cert.NotAfter
                        $daysUntilExpiry = ($expDate - (Get-Date)).Days

                        if ($daysUntilExpiry -gt $maxValidityDays) {
                            # Check if certificate is for a privileged user
                            $isPrivileged = $cert.CommonName -match 'Admin|Administrator|Domain Admins|Enterprise Admins|DC\$'

                            $findings += [PSCustomObject]@{
                                TemplateName      = $cert.Template
                                DisplayName       = "Issued Cert: $($cert.CommonName)"
                                ValidityDays      = $daysUntilExpiry
                                AuthenticationEKU = $true
                                SuppliesSubject   = 'N/A'
                                Issues            = "Long-lived cert for: $($cert.CommonName)"
                                RiskLevel         = if ($isPrivileged) { 'Critical' } else { 'Medium' }
                                PersistenceType   = 'Issued Certificate'
                                AttackPath        = if ($isPrivileged) { 'Privileged user cert valid for extended period' } else { 'User cert valid for extended period' }
                                DistinguishedName = "RequestID: $($cert.RequestID)"
                            }
                        }
                    } catch {}
                }
            } catch {}
        }

        # Check for certificates published in AD for users
        try {
            $usersWithCerts = Get-ADUser -Filter { userCertificate -like '*' } `
                -Properties userCertificate, SamAccountName, MemberOf `
                -ErrorAction SilentlyContinue

            foreach ($user in $usersWithCerts) {
                foreach ($certBytes in $user.userCertificate) {
                    try {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$certBytes
                        $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days

                        if ($daysUntilExpiry -gt $maxValidityDays) {
                            # Check if user is privileged
                            $groups = $user.MemberOf | ForEach-Object {
                                (Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue).Name
                            }
                            $isPrivileged = $groups -match 'Admin|Operator'

                            $findings += [PSCustomObject]@{
                                TemplateName      = 'User Certificate (AD Published)'
                                DisplayName       = $user.SamAccountName
                                ValidityDays      = $daysUntilExpiry
                                AuthenticationEKU = $true
                                SuppliesSubject   = 'N/A'
                                Issues            = "Cert expires: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
                                RiskLevel         = if ($isPrivileged) { 'High' } else { 'Medium' }
                                PersistenceType   = 'AD Published Certificate'
                                AttackPath        = 'User has long-lived cert stored in AD'
                                DistinguishedName = $user.DistinguishedName
                            }
                        }
                    } catch {}
                }
            }
        } catch {}

        return $findings
    }

    Remediation = @{
        Description = 'Reduce certificate validity periods and implement certificate lifecycle management.'
        Impact      = 'Medium - Shorter validity requires more frequent renewals.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Certificate-Based Persistence Prevention
#############################################################################
#
# Certificates can provide persistent access because:
# - They remain valid after password changes
# - They can have multi-year validity periods
# - They are often not monitored or revoked
#
# Identified risks:
$($Finding.Findings | ForEach-Object { "# - $($_.TemplateName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Review Template Validity Periods
#############################################################################

`$configNC = "CN=Configuration,`$((Get-ADDomain).DistinguishedName)"

Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties Name, 'pKIExpirationPeriod', 'pKIExtendedKeyUsage' |
    ForEach-Object {
        `$expBytes = `$_.'pKIExpirationPeriod'
        if (`$expBytes) {
            `$days = [math]::Abs([BitConverter]::ToInt64(`$expBytes, 0)) / 864000000000
            [PSCustomObject]@{
                Name = `$_.Name
                ValidityDays = [math]::Round(`$days)
                Years = [math]::Round(`$days/365, 1)
            }
        }
    } | Sort-Object ValidityDays -Descending | Format-Table -AutoSize

#############################################################################
# Step 2: Reduce Template Validity (Example)
#############################################################################

# Modify template to 1 year validity:
`$templateName = "UserAuthentication"  # Replace with actual template
`$template = Get-ADObject -Filter { Name -eq `$templateName -and objectClass -eq 'pKICertificateTemplate' } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

# Set validity to 1 year (365 days in 100-nanosecond intervals)
`$oneYearNS = -315360000000000  # Negative value for relative time
`$validityBytes = [BitConverter]::GetBytes([long]`$oneYearNS)

# Set-ADObject -Identity `$template.DistinguishedName -Replace @{
#     'pKIExpirationPeriod' = `$validityBytes
# }

#############################################################################
# Step 3: Revoke Suspicious Certificates
#############################################################################

# Find and revoke long-lived certificates:
# Use CA MMC or certutil to revoke

# List issued certificates:
certutil -view -restrict "Disposition=20" -out "RequestID,CommonName,NotAfter,CertificateTemplate"

# Revoke a specific certificate:
# certutil -revoke <SerialNumber> 1  # 1 = Key Compromise

#############################################################################
# Step 4: Implement Certificate Lifecycle Management
#############################################################################

# Best practices:
# 1. Maximum 1-year validity for user authentication certs
# 2. 90-day validity for highly privileged accounts
# 3. Automatic renewal with short validity
# 4. Monitor certificate issuance

# Configure auto-enrollment with short validity:
# Group Policy -> Computer/User Configuration
# -> Windows Settings -> Security Settings
# -> Public Key Policies -> Certificate Services Client - Auto-Enrollment
# -> Enabled

#############################################################################
# Step 5: Monitor Certificate Issuance
#############################################################################

# Enable CA auditing:
certutil -setreg CA\AuditFilter 127

# Monitor certificate events:
# Event ID 4886: Certificate request received
# Event ID 4887: Certificate issued
# Event ID 4888: Certificate request denied

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4887
} -MaxEvents 100 | Select-Object TimeCreated, Message

#############################################################################
# Step 6: Clean Up Published Certificates
#############################################################################

# Remove old certificates from AD user objects:
`$usersWithOldCerts = Get-ADUser -Filter { userCertificate -like '*' } `
    -Properties userCertificate

foreach (`$user in `$usersWithOldCerts) {
    foreach (`$certBytes in `$user.userCertificate) {
        `$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]`$certBytes
        if (`$cert.NotAfter -lt (Get-Date)) {
            Write-Host "Expired cert for `$(`$user.SamAccountName): `$(`$cert.Subject)"
            # Remove-ADUser -Identity `$user -Clear userCertificate
        }
    }
}

#############################################################################
# Step 7: Implement Certificate-Based Logon Restrictions
#############################################################################

# Require fresh certificates for privileged access:
# Use Fine-Grained Password Policies + certificate requirements

# Configure Kerberos to require certificate freshness:
# Create Authentication Policy that requires recent issuance

#############################################################################
# Verification
#############################################################################

# Re-check template validity:
Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC" `
    -Properties Name, 'pKIExpirationPeriod' |
    Where-Object { `$_.'pKIExpirationPeriod' } |
    ForEach-Object {
        `$days = [math]::Abs([BitConverter]::ToInt64(`$_.'pKIExpirationPeriod', 0)) / 864000000000
        if (`$days -gt 365) {
            Write-Host "`$(`$_.Name): `$([math]::Round(`$days)) days - REVIEW NEEDED" -ForegroundColor Yellow
        }
    }

"@
            return $commands
        }
    }
}
