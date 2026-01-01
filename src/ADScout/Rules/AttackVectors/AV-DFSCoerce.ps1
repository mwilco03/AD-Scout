<#
.SYNOPSIS
    Detects domain controllers vulnerable to DFSCoerce attack.

.DESCRIPTION
    DFSCoerce abuses the Distributed File System (DFS) MS-DFSNM protocol to coerce
    authentication from domain controllers. Similar to PetitPotam, this can be used
    to relay authentication to ADCS for domain compromise.

.NOTES
    Rule ID    : AV-DFSCoerce
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-DFSCoerce'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'DFSCoerce Attack Vulnerability'
    Description = 'Identifies domain controllers potentially vulnerable to DFSCoerce authentication coercion via the MS-DFSNM protocol, enabling NTLM relay attacks.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'DFSCoerce Attack'; Url = 'https://github.com/Wh04m1001/DFSCoerce' }
        @{ Title = 'MS-DFSNM Protocol'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/' }
        @{ Title = 'Coercion Attack Mitigations'; Url = 'https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1187', 'T1557.001')  # Forced Authentication, LLMNR/NBT-NS Poisoning and Relay
    }

    CIS   = @('5.4')
    STIG  = @('V-36687')
    ANSSI = @('vuln1_dfscoerce')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                $issues = @()
                $mitigations = @()

                # Check if DFS Namespace service is running
                try {
                    $dfsService = Get-Service -ComputerName $dcName -Name 'Dfs' -ErrorAction SilentlyContinue
                    if ($dfsService -and $dfsService.Status -eq 'Running') {
                        $issues += 'DFS Namespace service is running'
                    } else {
                        $mitigations += 'DFS service not running'
                    }
                } catch {
                    # Can't check service, assume vulnerable
                    $issues += 'Unable to verify DFS service status (assume running)'
                }

                # Check for EPA (Extended Protection for Authentication)
                try {
                    $epaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    $epaValue = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue

                    if ($epaValue.LmCompatibilityLevel -ge 5) {
                        $mitigations += 'NTLMv2 only (LmCompatibilityLevel >= 5)'
                    } else {
                        $issues += "LmCompatibilityLevel: $($epaValue.LmCompatibilityLevel) (should be 5)"
                    }
                } catch {
                    # Can't check registry
                }

                # Check if ADCS with Web Enrollment exists (relay target)
                $adcsVulnerable = $false
                try {
                    $webEnrollment = Get-Service -ComputerName $dcName -Name 'CertSvc' -ErrorAction SilentlyContinue
                    if ($webEnrollment -and $webEnrollment.Status -eq 'Running') {
                        $adcsVulnerable = $true
                        $issues += 'ADCS Certificate Services running (potential relay target)'
                    }
                } catch {}

                # Check RPC filter configuration
                try {
                    $rpcFilter = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        netsh rpc filter show filter 2>$null
                    } -ErrorAction SilentlyContinue

                    if ($rpcFilter -match 'MS-DFSNM' -or $rpcFilter -match 'No filters') {
                        if ($rpcFilter -notmatch 'block') {
                            $issues += 'No RPC filter blocking MS-DFSNM'
                        } else {
                            $mitigations += 'RPC filter may block MS-DFSNM'
                        }
                    }
                } catch {
                    $issues += 'Unable to verify RPC filter configuration'
                }

                if ($issues.Count -gt 0 -and $issues.Count -gt $mitigations.Count) {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        DFSServiceRunning   = $issues -match 'DFS.*running'
                        Issues              = ($issues -join '; ')
                        Mitigations         = if ($mitigations.Count -gt 0) { ($mitigations -join '; ') } else { 'None detected' }
                        ADCSPresent         = $adcsVulnerable
                        RiskLevel           = if ($adcsVulnerable) { 'Critical' } else { 'High' }
                        AttackPath          = 'Coerce DC auth -> Relay to ADCS/LDAP -> Domain compromise'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        # If we couldn't check individual DCs, report general vulnerability
        if ($findings.Count -eq 0 -and $Data.DomainControllers.Count -gt 0) {
            # Check if any ADCS exists in domain
            try {
                $cas = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } -SearchBase "CN=Configuration,$($Domain.DistinguishedName)" -ErrorAction SilentlyContinue
                if ($cas) {
                    $findings += [PSCustomObject]@{
                        DomainController    = 'All Domain Controllers'
                        DFSServiceRunning   = 'Assumed (default)'
                        Issues              = 'DFSCoerce vulnerability check requires manual verification'
                        Mitigations         = 'Unknown'
                        ADCSPresent         = $true
                        RiskLevel           = 'High'
                        AttackPath          = 'ADCS present - DFSCoerce could enable relay attack'
                        DistinguishedName   = 'N/A'
                    }
                }
            } catch {}
        }

        return $findings
    }

    Remediation = @{
        Description = 'Mitigate DFSCoerce by implementing NTLM relay protections and RPC filters.'
        Impact      = 'Low - Mitigations protect authentication without affecting DFS functionality.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# DFSCoerce Attack Mitigation
#############################################################################
#
# DFSCoerce uses the MS-DFSNM RPC interface to coerce authentication.
# Combined with NTLM relay, this can compromise ADCS or LDAP.
#
# Attack chain:
# 1. Attacker triggers DFSCoerce on DC
# 2. DC authenticates to attacker's server
# 3. Attacker relays credentials to ADCS Web Enrollment
# 4. Attacker obtains certificate for DC
# 5. Attacker uses certificate to authenticate as DC
#
# Affected DCs:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Enable Extended Protection for Authentication (EPA)
#############################################################################

# On ADCS Web Enrollment servers, enable EPA:
# IIS Manager -> Sites -> Default Web Site -> CertSrv
# -> Authentication -> Windows Authentication -> Advanced Settings
# -> Extended Protection: Required

# PowerShell for IIS:
Import-Module WebAdministration
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' `
    -Name 'extendedProtection.tokenChecking' -Value 'Require' -PSPath 'IIS:' -Location 'Default Web Site/CertSrv'

#############################################################################
# Step 2: Disable NTLM on ADCS
#############################################################################

# Disable NTLM authentication on Certificate Authority web enrollment:
# This forces Kerberos which cannot be relayed as easily

# Or restrict NTLM via GPO:
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options
# -> Network security: Restrict NTLM: Incoming NTLM traffic = Deny all accounts

#############################################################################
# Step 3: Enable LDAP Signing and Channel Binding
#############################################################################

# On Domain Controllers:
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options

# LDAP server signing requirement: Require signing
# LDAP server channel binding token requirements: Always

# Registry method:
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # LDAP Signing
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LDAPServerIntegrity' -Value 2 -Type DWord

        # Channel Binding (2020+ required for full protection)
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord
    }
}

#############################################################################
# Step 4: Configure RPC Filters (Block MS-DFSNM)
#############################################################################

# Create RPC filter to block MS-DFSNM from unauthorized sources
# Note: This may impact legitimate DFS management

# MS-DFSNM UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673

# Create filter rule (run on each DC):
netsh rpc filter add rule layer=um actiontype=block
netsh rpc filter add condition field=if_uuid matchtype=equal data=4fc742e0-4a10-11cf-8273-00aa004ae673
netsh rpc filter add filter

# Verify filters:
netsh rpc filter show filter

#############################################################################
# Step 5: Network Segmentation
#############################################################################

# Block outbound SMB/HTTP from DCs to workstations
# DCs should never initiate connections to client systems

# Windows Firewall rules:
New-NetFirewallRule -DisplayName "Block DC Outbound SMB" -Direction Outbound `
    -Protocol TCP -RemotePort 445 -Action Block -Profile Domain

New-NetFirewallRule -DisplayName "Block DC Outbound HTTP" -Direction Outbound `
    -Protocol TCP -RemotePort 80,443 -Action Block -Profile Domain

# Note: Add exceptions for legitimate DC-to-DC and DC-to-server traffic

#############################################################################
# Step 6: Monitor for Coercion Attempts
#############################################################################

# Enable RPC audit logging:
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

# Monitor for:
# - Event ID 5712: RPC connection attempt
# - Unusual DFS-related traffic from DCs
# - NTLM authentication from DC computer accounts

# Sigma rule for detection:
# title: Potential DFSCoerce Attack
# logsource:
#   product: windows
#   service: security
# detection:
#   selection:
#     EventID: 4624
#     LogonType: 3
#     TargetUserName|endswith: '$'
#     AuthenticationPackageName: 'NTLM'
#   condition: selection

"@
            return $commands
        }
    }
}
