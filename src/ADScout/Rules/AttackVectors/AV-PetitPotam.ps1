<#
.SYNOPSIS
    Detects conditions enabling PetitPotam and EFS coercion attacks.

.DESCRIPTION
    PetitPotam exploits the MS-EFSRPC protocol to coerce authentication from
    Domain Controllers. When combined with ADCS HTTP enrollment, this enables
    domain compromise.

.NOTES
    Rule ID    : AV-PetitPotam
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-PetitPotam'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'PetitPotam (EFSRPC) Coercion Attack Conditions'
    Description = 'Detects conditions enabling PetitPotam attacks where EFS coercion combined with ADCS HTTP enrollment enables domain compromise.'
    Severity    = 'Critical'
    Weight      = 85
    DataSource  = 'DomainControllers,CertificateAuthorities'

    References  = @(
        @{ Title = 'PetitPotam Attack'; Url = 'https://github.com/topotam/PetitPotam' }
        @{ Title = 'Microsoft Advisory - PetitPotam'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/ADV210003' }
        @{ Title = 'Mitigating NTLM Relay Attacks on ADCS'; Url = 'https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1187', 'T1557.001')  # Forced Authentication, LLMNR/NBT-NS Poisoning
    }

    CIS   = @('5.3')
    STIG  = @('V-78123')
    ANSSI = @('vuln1_petitpotam')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check for ADCS with HTTP enrollment (ESC8 prerequisite)
        $httpEnrollment = $false
        if ($Data.CertificateAuthorities) {
            foreach ($ca in $Data.CertificateAuthorities) {
                # Check for Web Enrollment
                if ($ca.WebEnrollmentEnabled -or $ca.CertEnrollWebEnabled) {
                    $httpEnrollment = $true

                    # Check if EPA is enabled
                    $epaEnabled = $ca.ExtendedProtectionEnabled -eq $true

                    if (-not $epaEnabled) {
                        $findings += [PSCustomObject]@{
                            Component           = 'Certificate Authority'
                            Target              = $ca.Name
                            Vulnerability       = 'ADCS HTTP Enrollment without EPA'
                            AttackPath          = 'PetitPotam -> Relay to ADCS -> Request certificate as DC -> DCSync'
                            RiskLevel           = 'Critical'
                            Mitigation          = 'Enable Extended Protection for Authentication (EPA) on IIS'
                            DistinguishedName   = $ca.DistinguishedName
                        }
                    }
                }
            }
        }

        # Check DCs for EFS service accessibility
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                # Check if EFS RPC is accessible
                $efsAccessible = $false
                try {
                    # Try to check EFS RPC endpoint
                    $rpc = [System.Net.Sockets.TcpClient]::new()
                    $rpc.Connect($dcName, 445)
                    if ($rpc.Connected) {
                        $efsAccessible = $true
                        $rpc.Close()
                    }
                } catch {
                    # Assume accessible if we can't check
                    $efsAccessible = $true
                }

                if ($efsAccessible) {
                    $severity = if ($httpEnrollment) { 'Critical' } else { 'High' }
                    $attackPath = if ($httpEnrollment) {
                        'PetitPotam coercion -> NTLM relay to ADCS -> Certificate as DC -> DCSync -> Domain Compromise'
                    } else {
                        'PetitPotam coercion -> NTLM relay possible if target found'
                    }

                    $findings += [PSCustomObject]@{
                        Component           = 'Domain Controller'
                        Target              = $dcName
                        Vulnerability       = 'EFS RPC (MS-EFSRPC) accessible'
                        AttackPath          = $attackPath
                        ADCSHTTPEnabled     = $httpEnrollment
                        RiskLevel           = $severity
                        Mitigation          = 'Apply KB5005413, enable EPA, disable NTLM on DCs'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Apply Microsoft patches and enable Extended Protection for Authentication (EPA) on ADCS web services. Consider disabling NTLM on Domain Controllers.'
        Impact      = 'Medium - NTLM restrictions may affect legacy applications. Test before deployment.'
        Script      = {
            param($Finding, $Domain)

            $dcFindings = $Finding.Findings | Where-Object { $_.Component -eq 'Domain Controller' }
            $caFindings = $Finding.Findings | Where-Object { $_.Component -eq 'Certificate Authority' }

            $commands = @"
#############################################################################
# PetitPotam Attack Mitigation
#############################################################################
#
# PetitPotam Attack Chain:
# 1. Attacker uses MS-EFSRPC to coerce DC authentication
# 2. DC authenticates to attacker-controlled server via NTLM
# 3. Attacker relays NTLM to ADCS Web Enrollment
# 4. Attacker obtains certificate as the DC
# 5. Attacker uses certificate to authenticate as DC
# 6. Attacker performs DCSync and compromises entire domain
#
# This attack requires NO credentials - any network access is sufficient!
#
#############################################################################

# Affected Components:
$($Finding.Findings | ForEach-Object { "# - $($_.Component): $($_.Target) - $($_.Vulnerability)" } | Out-String)

#############################################################################
# Step 1: Apply Security Updates (KB5005413)
#############################################################################

# Install the latest Windows security updates
# This includes mitigations for PetitPotam

# Check if patch is installed:
Get-HotFix -Id KB5005413 -ErrorAction SilentlyContinue

# Install via Windows Update or WSUS
# wusa.exe WindowsUpdatePackage.msu /quiet /norestart

#############################################################################
# Step 2: Enable Extended Protection for Authentication (EPA) on ADCS
#############################################################################

"@

            foreach ($ca in $caFindings) {
                $commands += @"

# Enable EPA on CA: $($ca.Target)
# On the ADCS server, configure IIS:

# Using IIS Manager:
# 1. Open IIS Manager
# 2. Navigate to Default Web Site > CertSrv
# 3. Double-click Authentication
# 4. Select Windows Authentication
# 5. Click Advanced Settings
# 6. Set Extended Protection to "Required"

# Using PowerShell/appcmd:
Invoke-Command -ComputerName '$($ca.Target)' -ScriptBlock {
    # Enable Extended Protection on Certificate Enrollment Web Service
    `$appCmd = "`$env:systemroot\system32\inetsrv\appcmd.exe"

    # For CertSrv
    & `$appCmd set config "Default Web Site/CertSrv" `
        -section:system.webServer/security/authentication/windowsAuthentication `
        /extendedProtection.tokenChecking:"Require" `
        /extendedProtection.flags:"None" /commit:apphost

    # Restart IIS
    iisreset /restart
}

"@
            }

            $commands += @"

#############################################################################
# Step 3: Disable NTLM on Domain Controllers (Strongest Protection)
#############################################################################

# WARNING: This may break legacy applications. Test thoroughly!

# GPO Path: Computer Configuration > Policies > Windows Settings >
#   Security Settings > Local Policies > Security Options

# "Network security: Restrict NTLM: Incoming NTLM traffic"
# Set to: "Deny all accounts"

# "Network security: Restrict NTLM: NTLM authentication in this domain"
# Set to: "Deny all"

# Registry (for testing):
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
#     -Name 'RestrictReceivingNTLMTraffic' -Value 2 -Type DWord

#############################################################################
# Step 4: Enable NTLM Auditing First
#############################################################################

# Before blocking NTLM, enable auditing to identify dependencies:

# GPO: "Network security: Restrict NTLM: Audit NTLM authentication in this domain"
# Set to: "Enable all"

# Check Event Viewer for NTLM usage:
# Applications and Services Logs > Microsoft > Windows > NTLM > Operational

Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 100 |
    Select-Object TimeCreated, Message

#############################################################################
# Step 5: Disable Inbound Named Pipes (Alternative)
#############################################################################

# Block MS-EFSRPC specifically via Windows Firewall:

# Block EFS RPC endpoint on DCs:
New-NetFirewallRule -DisplayName "Block PetitPotam EFSRPC" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -RemoteAddress Any -Action Block `
    -Description "Mitigate PetitPotam - Block EFS over SMB"

# Note: This may affect legitimate EFS operations

#############################################################################
# Step 6: Require SMB Signing
#############################################################################

# SMB signing prevents NTLM relay:

# GPO Path: Computer Configuration > Policies > Windows Settings >
#   Security Settings > Local Policies > Security Options

# "Microsoft network server: Digitally sign communications (always)"
# Set to: Enabled

# "Microsoft network client: Digitally sign communications (always)"
# Set to: Enabled

#############################################################################
# Verification
#############################################################################

# Test if PetitPotam is mitigated:
# Use PetitPotam checker or similar tools in a controlled environment

# Verify EPA is enabled:
Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" `
    -Name "extendedProtection.tokenChecking" -PSPath "IIS:\Sites\Default Web Site\CertSrv"

# Verify NTLM restrictions:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' |
    Select-Object RestrictReceivingNTLMTraffic, RestrictSendingNTLMTraffic

"@
            return $commands
        }
    }
}
