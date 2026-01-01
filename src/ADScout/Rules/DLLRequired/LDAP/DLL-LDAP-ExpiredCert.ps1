<#
.SYNOPSIS
    Detects expired or expiring LDAPS certificates.

.DESCRIPTION
    Uses native .NET SSL testing to check LDAPS certificate validity
    on Domain Controllers.

.NOTES
    Rule ID    : DLL-LDAP-ExpiredCert
    Category   : DLLRequired
    Requires   : Native .NET
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-LDAP-ExpiredCert'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAPS Certificate Expired or Expiring'
    Description = 'LDAPS certificates are expired or expiring soon, which may cause authentication failures and security warnings.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    RequiresDLL     = $false
    FallbackBehavior = 'Continue'

    References  = @(
        @{ Title = 'LDAPS Certificate Requirements'; Url = 'https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority' }
        @{ Title = 'Certificate Renewal'; Url = 'https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/renew-certificates' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1499')   # Endpoint Denial of Service
    }

    NIST  = @('SC-12', 'SC-17')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 75
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $warningDays = 30  # Warn if expires within 30 days
        $criticalDays = 7  # Critical if expires within 7 days

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-LDAPSScan -ComputerName $dcName -TimeoutMs 10000

                if ($scanResult.Status -eq 'Success' -and $scanResult.LDAPSAvailable) {
                    $addFinding = $false
                    $severity = 'Medium'
                    $status = 'Valid'

                    if ($scanResult.CertificateExpired) {
                        $addFinding = $true
                        $severity = 'Critical'
                        $status = 'EXPIRED'
                    } elseif ($scanResult.CertificateDaysRemaining -le $criticalDays) {
                        $addFinding = $true
                        $severity = 'Critical'
                        $status = "Expires in $($scanResult.CertificateDaysRemaining) days"
                    } elseif ($scanResult.CertificateDaysRemaining -le $warningDays) {
                        $addFinding = $true
                        $severity = 'High'
                        $status = "Expires in $($scanResult.CertificateDaysRemaining) days"
                    }

                    if ($addFinding) {
                        $findings += [PSCustomObject]@{
                            DomainController        = $dcName
                            OperatingSystem         = $dc.OperatingSystem
                            CertificateSubject      = $scanResult.CertificateSubject
                            CertificateIssuer       = $scanResult.CertificateIssuer
                            CertificateThumbprint   = $scanResult.CertificateThumbprint
                            CertificateNotAfter     = $scanResult.CertificateNotAfter
                            DaysRemaining           = $scanResult.CertificateDaysRemaining
                            CertificateStatus       = $status
                            SelfSigned              = $scanResult.SelfSigned
                            RiskLevel               = $severity
                            Impact                  = 'LDAPS authentication failures, security warnings'
                            DistinguishedName       = $dc.DistinguishedName
                        }
                    }
                }
            } catch {
                Write-Verbose "DLL-LDAP-ExpiredCert: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Renew or replace the LDAPS certificate before expiration.'
        Impact      = 'Low - Certificate renewal is a standard maintenance task.'
        Script      = {
            param($Finding, $Domain)

            @"
# Renew LDAPS Certificate

# Step 1: Check current certificate status
foreach (`$dc in @($($Finding.Findings.DomainController | ForEach-Object { "'$_'" } -join ', '))) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object { `$_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
            Select-Object Subject, Thumbprint, NotAfter, @{N='DaysRemaining';E={(`$_.NotAfter - (Get-Date)).Days}}
    }
}

# Step 2: Request new certificate from internal CA
# Using certreq:
# certreq -new request.inf request.req
# certreq -submit request.req certificate.cer
# certreq -accept certificate.cer

# Step 3: If using auto-enrollment, trigger certificate renewal
gpupdate /force

# Or manually request via Certificates MMC:
# 1. Open certlm.msc (Local Computer certificates)
# 2. Navigate to Personal > Certificates
# 3. Right-click > All Tasks > Request New Certificate
# 4. Select the Domain Controller certificate template

# Step 4: Verify new certificate
Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { `$_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
    Select-Object Subject, NotAfter

# Note: LDAPS certificate should have:
# - Server Authentication EKU (1.3.6.1.5.5.7.3.1)
# - Subject matching DC FQDN
# - Valid chain to trusted root
"@
        }
    }
}
