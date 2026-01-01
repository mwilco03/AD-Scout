<#
.SYNOPSIS
    Detects ESC9 - Certificate templates with CT_FLAG_NO_SECURITY_EXTENSION.

.DESCRIPTION
    ESC9 occurs when certificate templates have the CT_FLAG_NO_SECURITY_EXTENSION flag,
    which prevents the new szOID_NTDS_CA_SECURITY_EXT from being embedded in certificates.
    Combined with weak mapping (StrongCertificateBindingEnforcement=0), this enables attacks.

.NOTES
    Rule ID    : C-ESC9-NoSecurityExtension
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC9-NoSecurityExtension'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'ESC9 - No Security Extension Flag'
    Description = 'Identifies certificate templates with CT_FLAG_NO_SECURITY_EXTENSION that may enable certificate mapping attacks when combined with weak enforcement.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'CertificateTemplates'

    References  = @(
        @{ Title = 'Certipy ESC9'; Url = 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-டmore-7237d88061f7' }
        @{ Title = 'KB5014754 - Certificate Mapping'; Url = 'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16' }
        @{ Title = 'ESC9/ESC10 Exploitation'; Url = 'https://posts.specterops.io/adcs-esc9-esc10-f2a5c8d27a55' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1649')  # Steal or Forge Authentication Certificates
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_adcs_esc9')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # CT_FLAG_NO_SECURITY_EXTENSION = 0x80000
        $noSecurityExtFlag = 0x80000

        # First check registry for StrongCertificateBindingEnforcement
        $weakMappingEnabled = $false
        $mappingMode = 'Unknown'

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers | Select-Object -First 1) {
                try {
                    $dcName = $dc.Name
                    if (-not $dcName) { $dcName = $dc.DnsHostName }

                    $regResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue

                    if ($regResult) {
                        $mappingMode = $regResult.StrongCertificateBindingEnforcement
                        # 0 = Disabled (vulnerable), 1 = Compatibility mode, 2 = Full enforcement
                        if ($mappingMode -eq 0) {
                            $weakMappingEnabled = $true
                        }
                    } else {
                        # Default depends on OS version and patch level
                        $mappingMode = 'Not configured (check default)'
                    }
                } catch {
                    $mappingMode = 'Unable to check'
                }
                break
            }
        }

        if ($Data.CertificateTemplates) {
            foreach ($template in $Data.CertificateTemplates) {
                $templateName = $template.Name
                if (-not $templateName) { $templateName = $template.DisplayName }

                $msPKIEnrollmentFlag = $template.'msPKI-Enrollment-Flag'
                $msPKICertificateNameFlag = $template.'msPKI-Certificate-Name-Flag'

                # Check for CT_FLAG_NO_SECURITY_EXTENSION
                if ($msPKIEnrollmentFlag -band $noSecurityExtFlag) {

                    # Check if this template allows client authentication
                    $ekus = $template.'pKIExtendedKeyUsage'
                    $hasClientAuth = $false
                    if ($ekus) {
                        # Client Authentication = 1.3.6.1.5.5.7.3.2
                        # Smart Card Logon = 1.3.6.1.4.1.311.20.2.2
                        # PKINIT = 1.3.6.1.5.2.3.4
                        # Any Purpose = 2.5.29.37.0
                        $hasClientAuth = $ekus -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|1\.3\.6\.1\.5\.2\.3\.4|2\.5\.29\.37\.0'
                    }

                    if (-not $hasClientAuth -and -not $ekus) {
                        # No EKU = Any Purpose
                        $hasClientAuth = $true
                    }

                    $riskLevel = 'Medium'
                    $attackPath = 'Template lacks security extension'

                    if ($hasClientAuth) {
                        $riskLevel = 'High'
                        $attackPath = 'Template allows client auth without security extension'

                        if ($weakMappingEnabled) {
                            $riskLevel = 'Critical'
                            $attackPath = 'ESC9: Weak certificate mapping + no security extension = account takeover'
                        }
                    }

                    $findings += [PSCustomObject]@{
                        TemplateName            = $templateName
                        HasNoSecurityExtension  = $true
                        HasClientAuth           = $hasClientAuth
                        WeakMappingEnabled      = $weakMappingEnabled
                        MappingMode             = $mappingMode
                        RiskLevel               = $riskLevel
                        AttackPath              = $attackPath
                        EnrollmentFlag          = "0x$($msPKIEnrollmentFlag.ToString('X'))"
                        DistinguishedName       = $template.DistinguishedName
                    }
                }
            }
        }

        # Also report weak mapping as a finding if any templates are affected
        if ($weakMappingEnabled -and $findings.Count -gt 0) {
            $findings += [PSCustomObject]@{
                TemplateName            = 'DOMAIN CONFIGURATION'
                HasNoSecurityExtension  = 'N/A'
                HasClientAuth           = 'N/A'
                WeakMappingEnabled      = $true
                MappingMode             = $mappingMode
                RiskLevel               = 'Critical'
                AttackPath              = 'StrongCertificateBindingEnforcement=0 enables ESC9/ESC10 attacks'
                EnrollmentFlag          = 'N/A'
                DistinguishedName       = 'Registry Configuration'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable strong certificate binding enforcement and remove CT_FLAG_NO_SECURITY_EXTENSION from templates where not required.'
        Impact      = 'High - May break certificate-based authentication for existing certificates. Plan migration carefully.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# ESC9 - No Security Extension Remediation
#############################################################################
#
# ESC9 exploits templates with CT_FLAG_NO_SECURITY_EXTENSION combined with
# weak certificate-to-account mapping (StrongCertificateBindingEnforcement=0).
#
# Attack Chain:
# 1. Attacker has GenericWrite on a user account
# 2. Attacker changes victim's userPrincipalName to match target
# 3. Attacker requests certificate (without security extension)
# 4. Attacker restores victim's UPN
# 5. Certificate maps to target account (not victim)
# 6. Attacker authenticates as target
#
# Affected Templates:
$($Finding.Findings | Where-Object { $_.TemplateName -ne 'DOMAIN CONFIGURATION' } | ForEach-Object { "# - $($_.TemplateName): Risk=$($_.RiskLevel)" } | Out-String)

#############################################################################
# Step 1: Enable Strong Certificate Binding Enforcement
#############################################################################

# Check current setting on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    `$setting = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
    }
    Write-Host "`$(`$_.HostName): StrongCertificateBindingEnforcement = `$setting"
}

# Set to Compatibility Mode (1) first to audit
# Then set to Full Enforcement (2) after testing

# Via GPO (recommended):
# Computer Configuration > Policies > Administrative Templates > System > KDC
# "KDC support for PKInit Freshness Extension"
# "Certificate-based authentication settings"

# Via registry (apply to all DCs):
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # 0 = Disabled (VULNERABLE)
        # 1 = Compatibility mode (audit)
        # 2 = Full enforcement (secure)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'StrongCertificateBindingEnforcement' -Value 2 -Type DWord
    }
}

#############################################################################
# Step 2: Remove NO_SECURITY_EXTENSION Flag from Templates
#############################################################################

# List templates with the flag
Import-Module PSPKI -ErrorAction SilentlyContinue

"@

            foreach ($item in $Finding.Findings | Where-Object { $_.TemplateName -ne 'DOMAIN CONFIGURATION' }) {
                $commands += @"

# Template: $($item.TemplateName)
# Current Enrollment Flag: $($item.EnrollmentFlag)
# Remove CT_FLAG_NO_SECURITY_EXTENSION (0x80000)

`$template = Get-ADObject -Filter "Name -eq '$($item.TemplateName)'" `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties 'msPKI-Enrollment-Flag'

`$currentFlag = `$template.'msPKI-Enrollment-Flag'
`$newFlag = `$currentFlag -band (-bnot 0x80000)  # Remove the flag

if (`$newFlag -ne `$currentFlag) {
    Set-ADObject -Identity `$template -Replace @{'msPKI-Enrollment-Flag' = `$newFlag}
    Write-Host "Removed NO_SECURITY_EXTENSION from $($item.TemplateName)" -ForegroundColor Green
}

"@
            }

            $commands += @"

#############################################################################
# Step 3: Audit Before Full Enforcement
#############################################################################

# Enable Compatibility Mode first and monitor for issues
# Event ID 39 in System log indicates certificate mapping failures

# Check for certificates that would fail strong mapping:
Get-WinEvent -FilterHashtable @{LogName='System'; Id=39} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message

#############################################################################
# Step 4: Update Existing Certificates
#############################################################################

# Certificates issued before the fix need to be reissued
# They won't have the security extension

# Identify affected certificates:
# 1. Check certificate issuance dates
# 2. Certificates before KB5014754 need reissuance for strong mapping

# Force users to re-enroll for certificates:
# certreq -enroll -user -q

#############################################################################
# Verification
#############################################################################

# Verify strong binding is enabled:
Get-ADDomainController -Filter * | ForEach-Object {
    Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        `$val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
        Write-Host "`$env:COMPUTERNAME : `$val (should be 2)"
    }
}

# Verify templates no longer have the flag:
Get-ADObject -Filter { ObjectClass -eq 'pKICertificateTemplate' } `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties 'msPKI-Enrollment-Flag' | Where-Object {
        `$_.'msPKI-Enrollment-Flag' -band 0x80000
    } | Select-Object Name, @{N='Flag';E={"0x`$(`$_.'msPKI-Enrollment-Flag'.ToString('X'))"}}

"@
            return $commands
        }
    }
}
