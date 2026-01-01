<#
.SYNOPSIS
    Detects weak certificate-to-account mapping vulnerable to CVE-2022-26923 (Certifried).

.DESCRIPTION
    CVE-2022-26923 (Certifried) exploits weak certificate mapping where the dNSHostName
    attribute can be manipulated to impersonate other accounts. Strong certificate mapping
    prevents this attack.

.NOTES
    Rule ID    : C-ESC10-WeakMapping
    Category   : PKI
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'C-ESC10-WeakMapping'
    Version     = '1.0.0'
    Category    = 'PKI'
    Title       = 'Weak Certificate Mapping (Certifried)'
    Description = 'Identifies environments vulnerable to CVE-2022-26923 (Certifried) due to weak certificate-to-account mapping, allowing privilege escalation via certificate spoofing.'
    Severity    = 'Critical'
    Weight      = 70
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'CVE-2022-26923 (Certifried)'; Url = 'https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4' }
        @{ Title = 'Microsoft Advisory'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923' }
        @{ Title = 'Strong Certificate Mapping'; Url = 'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0006')  # Privilege Escalation, Credential Access
        Techniques = @('T1649', 'T1558')    # Steal or Forge Authentication Certificates, Kerberos Tickets
    }

    CIS   = @('5.2')
    STIG  = @('V-93381')
    ANSSI = @('vuln1_certmap')

    Scoring = @{
        Type    = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check each Domain Controller for strong mapping enforcement
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    # Check registry for strong certificate mapping enforcement
                    $strongMappingResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            StrongCertBindingEnforcement = $null
                            CertificateMappingMethods = $null
                            KBInstalled = $false
                        }

                        # Check Schannel strong mapping (KB5014754)
                        $schannelPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
                        $strongBinding = Get-ItemProperty -Path $schannelPath -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue
                        $result.StrongCertBindingEnforcement = $strongBinding.StrongCertificateBindingEnforcement

                        # Check certificate mapping methods
                        $certMapPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel'
                        $certMapping = Get-ItemProperty -Path $certMapPath -Name 'CertificateMappingMethods' -ErrorAction SilentlyContinue
                        $result.CertificateMappingMethods = $certMapping.CertificateMappingMethods

                        # Check if May 2022 or later security update is installed
                        $hotfixes = Get-HotFix | Where-Object {
                            $_.InstalledOn -ge [DateTime]'2022-05-01' -and
                            $_.Description -match 'Security Update'
                        }
                        $result.KBInstalled = $hotfixes.Count -gt 0

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()
                    $isVulnerable = $false

                    # StrongCertificateBindingEnforcement:
                    # 0 = Disabled (Vulnerable)
                    # 1 = Compatibility mode (Default after May 2022, still allows weak)
                    # 2 = Full enforcement mode (Secure)
                    if ($null -eq $strongMappingResult.StrongCertBindingEnforcement) {
                        $issues += 'StrongCertificateBindingEnforcement not configured (defaults to compatibility mode)'
                        $isVulnerable = $true
                    } elseif ($strongMappingResult.StrongCertBindingEnforcement -eq 0) {
                        $issues += 'StrongCertificateBindingEnforcement = 0 (DISABLED - Highly Vulnerable)'
                        $isVulnerable = $true
                    } elseif ($strongMappingResult.StrongCertBindingEnforcement -eq 1) {
                        $issues += 'StrongCertificateBindingEnforcement = 1 (Compatibility mode - Weak mapping still allowed)'
                        $isVulnerable = $true
                    }
                    # Value 2 = Full enforcement (secure)

                    # Check CertificateMappingMethods
                    # If set to 0x1F (31) or includes weak methods, it's vulnerable
                    if ($strongMappingResult.CertificateMappingMethods) {
                        $methods = $strongMappingResult.CertificateMappingMethods
                        # Bit 0x04 = Subject/Issuer mapping (weak)
                        # Bit 0x08 = S4U2Self mapping (can be weak)
                        # Bit 0x10 = UPN mapping (weak if not combined with strong binding)
                        if ($methods -band 0x04) {
                            $issues += 'Subject/Issuer certificate mapping enabled (weak)'
                            $isVulnerable = $true
                        }
                    }

                    if (-not $strongMappingResult.KBInstalled) {
                        $issues += 'May 2022 security update may not be installed'
                    }

                    if ($isVulnerable) {
                        $findings += [PSCustomObject]@{
                            DomainController        = $dcName
                            StrongBindingEnforcement = if ($null -eq $strongMappingResult.StrongCertBindingEnforcement) { 'Not set' } else { $strongMappingResult.StrongCertBindingEnforcement }
                            CertMappingMethods      = if ($strongMappingResult.CertificateMappingMethods) { "0x$($strongMappingResult.CertificateMappingMethods.ToString('X'))" } else { 'Default' }
                            Issues                  = ($issues -join '; ')
                            CVE                     = 'CVE-2022-26923'
                            RiskLevel               = if ($strongMappingResult.StrongCertBindingEnforcement -eq 0) { 'Critical' } else { 'High' }
                            AttackPath              = 'Attacker modifies computer dNSHostName -> Requests cert -> Impersonates DC'
                            DistinguishedName       = $dc.DistinguishedName
                        }
                    }

                } catch {
                    # Can't check this DC, report as unknown
                    $findings += [PSCustomObject]@{
                        DomainController        = $dcName
                        StrongBindingEnforcement = 'Unknown (check failed)'
                        CertMappingMethods      = 'Unknown'
                        Issues                  = 'Unable to verify strong mapping configuration'
                        CVE                     = 'CVE-2022-26923'
                        RiskLevel               = 'High'
                        AttackPath              = 'Manual verification required'
                        DistinguishedName       = $dc.DistinguishedName
                    }
                }
            }
        }

        # Also check for machine account quota (enables the attack)
        if ($findings.Count -gt 0) {
            try {
                $maq = (Get-ADDomain).DistinguishedName | ForEach-Object {
                    (Get-ADObject -Identity $_ -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
                }
                if ($maq -gt 0) {
                    # Add note about MAQ to findings
                    foreach ($f in $findings) {
                        $f | Add-Member -NotePropertyName 'MachineAccountQuota' -NotePropertyValue $maq -Force
                        $f | Add-Member -NotePropertyName 'Note' -NotePropertyValue 'MAQ > 0 allows users to create machine accounts for this attack' -Force
                    }
                }
            } catch {}
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable strong certificate mapping enforcement and apply May 2022 security updates.'
        Impact      = 'Medium - May break legacy certificate authentication. Test in compatibility mode first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# CVE-2022-26923 (Certifried) Remediation
#############################################################################
#
# The Certifried vulnerability allows privilege escalation by:
# 1. Creating a machine account (if MAQ > 0)
# 2. Modifying its dNSHostName to match a DC
# 3. Requesting a certificate with the spoofed identity
# 4. Using the certificate to authenticate as the DC
#
# Affected DCs:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Install Security Updates
#############################################################################

# Ensure May 2022 (or later) cumulative update is installed on all DCs:
# - Windows Server 2022: KB5013944
# - Windows Server 2019: KB5013941
# - Windows Server 2016: KB5013952

# Check installed updates:
Get-HotFix | Where-Object { `$_.InstalledOn -ge '2022-05-01' } |
    Select-Object HotFixID, InstalledOn, Description

#############################################################################
# Step 2: Configure Strong Certificate Binding (Compatibility Mode First)
#############################################################################

# Start with Compatibility Mode (value 1) to identify issues:
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Enable Compatibility Mode (logs issues but doesn't block)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'StrongCertificateBindingEnforcement' -Value 1 -Type DWord

        Write-Host "Enabled Compatibility Mode on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

# Monitor Event Log for compatibility issues:
# Event ID 39 in System log = Certificate mapping would fail in Full Enforcement mode

Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID = 39
} -MaxEvents 100 | Format-Table TimeCreated, Message -Wrap

#############################################################################
# Step 3: Enable Full Enforcement Mode
#############################################################################

# After verifying no issues in Compatibility Mode, enable Full Enforcement:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Enable Full Enforcement Mode
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'StrongCertificateBindingEnforcement' -Value 2 -Type DWord

        Write-Host "Enabled Full Enforcement on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

# Note: Starting November 2025 (or 2026 TBD), Full Enforcement becomes default

#############################################################################
# Step 4: Reduce Machine Account Quota
#############################################################################

# Reducing MAQ to 0 prevents users from creating machine accounts for this attack:

Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}

# Verify:
(Get-ADDomain).'ms-DS-MachineAccountQuota'

#############################################################################
# Step 5: Restrict dNSHostName Modification
#############################################################################

# By default, computer objects can modify their own dNSHostName
# The May 2022 update adds validation to prevent spoofing

# Additional protection - remove Self permission for dNSHostName:
# (Advanced - may break legitimate functionality)

# `$computerOU = "OU=Computers,DC=domain,DC=com"
# `$acl = Get-Acl "AD:\`$computerOU"
# Remove Self write access to dNSHostName (GUID: 72e39547-7b18-11d1-adef-00c04fd8d5cd)

#############################################################################
# Step 6: Monitor for Attack Attempts
#############################################################################

# Monitor for suspicious certificate requests:
# - Certificates with dNSHostName of DCs requested by non-DC accounts
# - Rapid creation/deletion of computer accounts

# Event ID 4768 - Kerberos TGT request with certificate
# Event ID 4887 - Certificate request received

# Monitor computer account creation:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4741  # Computer account created
} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap

#############################################################################
# Timeline for Microsoft Enforcement
#############################################################################

# Phase 1 (May 2022): Updates released, Disabled mode available
# Phase 2 (Current): Compatibility mode is default
# Phase 3 (Feb 2025): Full Enforcement can no longer be disabled
# Phase 4 (Nov 2025+): Full Enforcement becomes mandatory

# Recommendation: Move to Full Enforcement before it becomes mandatory

"@
            return $commands
        }
    }
}
