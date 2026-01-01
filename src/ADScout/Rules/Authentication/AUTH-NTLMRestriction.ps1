<#
.SYNOPSIS
    Detects environments without NTLM restrictions.

.DESCRIPTION
    NTLM authentication is vulnerable to relay attacks and credential theft.
    This rule checks for NTLM restriction policies and identifies environments
    that have not implemented NTLM hardening.

.NOTES
    Rule ID    : AUTH-NTLMRestriction
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-NTLMRestriction'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'NTLM Not Restricted'
    Description = 'Identifies environments that have not implemented NTLM restrictions, leaving them vulnerable to relay attacks, pass-the-hash, and credential theft.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'NTLM Auditing and Restricting'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain' }
        @{ Title = 'NTLM Relay Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'Reducing NTLM Usage'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-incoming-ntlm-traffic' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1550.002')  # LLMNR/NBT-NS Poisoning, Pass the Hash
    }

    CIS   = @('2.3.11.6')
    STIG  = @('V-36687')
    ANSSI = @('R28')

    Scoring = @{
        Type    = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check NTLM policies on Domain Controllers
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $ntlmSettings = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            RestrictNTLMInDomain = $null
                            AuditNTLMInDomain = $null
                            RestrictNTLMServer = $null
                            AuditNTLMServer = $null
                            LmCompatibilityLevel = $null
                            ExtendedProtection = $null
                            NTLMMinServerSec = $null
                            NTLMMinClientSec = $null
                        }

                        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                        $msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

                        # LmCompatibilityLevel
                        # 0 = Send LM & NTLM responses
                        # 1 = Send LM & NTLM - use NTLMv2 session security if negotiated
                        # 2 = Send NTLM response only
                        # 3 = Send NTLMv2 response only
                        # 4 = Send NTLMv2 response only. Refuse LM
                        # 5 = Send NTLMv2 response only. Refuse LM & NTLM
                        $lmc = Get-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
                        $result.LmCompatibilityLevel = $lmc.LmCompatibilityLevel

                        # Restrict NTLM in domain
                        $restrictDomain = Get-ItemProperty -Path $msv1Path -Name 'RestrictReceivingNTLMTraffic' -ErrorAction SilentlyContinue
                        $result.RestrictNTLMInDomain = $restrictDomain.RestrictReceivingNTLMTraffic

                        # Audit NTLM
                        $auditDomain = Get-ItemProperty -Path $msv1Path -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue
                        $result.AuditNTLMInDomain = $auditDomain.AuditReceivingNTLMTraffic

                        # Restrict outgoing NTLM
                        $restrictSend = Get-ItemProperty -Path $msv1Path -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue
                        $result.RestrictNTLMServer = $restrictSend.RestrictSendingNTLMTraffic

                        # NTLMMinServerSec / NTLMMinClientSec
                        $minServer = Get-ItemProperty -Path $msv1Path -Name 'NTLMMinServerSec' -ErrorAction SilentlyContinue
                        $result.NTLMMinServerSec = $minServer.NTLMMinServerSec

                        $minClient = Get-ItemProperty -Path $msv1Path -Name 'NTLMMinClientSec' -ErrorAction SilentlyContinue
                        $result.NTLMMinClientSec = $minClient.NTLMMinClientSec

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()
                    $isVulnerable = $false

                    # Check LmCompatibilityLevel (should be 5)
                    if ($null -eq $ntlmSettings.LmCompatibilityLevel -or $ntlmSettings.LmCompatibilityLevel -lt 3) {
                        $issues += "LmCompatibilityLevel = $($ntlmSettings.LmCompatibilityLevel) (should be 5)"
                        $isVulnerable = $true
                    } elseif ($ntlmSettings.LmCompatibilityLevel -lt 5) {
                        $issues += "LmCompatibilityLevel = $($ntlmSettings.LmCompatibilityLevel) (recommend 5)"
                    }

                    # Check NTLM restrictions
                    if ($null -eq $ntlmSettings.RestrictNTLMInDomain -or $ntlmSettings.RestrictNTLMInDomain -eq 0) {
                        $issues += 'Incoming NTLM traffic not restricted'
                        $isVulnerable = $true
                    }

                    # Check NTLM auditing
                    if ($null -eq $ntlmSettings.AuditNTLMInDomain -or $ntlmSettings.AuditNTLMInDomain -eq 0) {
                        $issues += 'NTLM authentication not being audited'
                    }

                    # Check NTLMv2 session security requirements
                    # 0x80000 = Require NTLMv2 session security
                    # 0x20080000 = Require 128-bit encryption + NTLMv2
                    if ($null -eq $ntlmSettings.NTLMMinServerSec -or ($ntlmSettings.NTLMMinServerSec -band 0x80000) -eq 0) {
                        $issues += 'NTLMv2 session security not required'
                    }

                    if ($isVulnerable -or $issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            DomainController    = $dcName
                            LmCompatibilityLevel = $ntlmSettings.LmCompatibilityLevel
                            RestrictNTLM        = $ntlmSettings.RestrictNTLMInDomain
                            AuditNTLM           = $ntlmSettings.AuditNTLMInDomain
                            NTLMMinServerSec    = if ($ntlmSettings.NTLMMinServerSec) { "0x$($ntlmSettings.NTLMMinServerSec.ToString('X'))" } else { 'Not set' }
                            Issues              = ($issues -join '; ')
                            RiskLevel           = if ($isVulnerable) { 'High' } else { 'Medium' }
                            Attacks             = 'NTLM Relay, Pass-the-Hash, Credential Theft'
                            DistinguishedName   = $dc.DistinguishedName
                        }
                    }

                } catch {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        LmCompatibilityLevel = 'Unknown'
                        RestrictNTLM        = 'Unknown'
                        AuditNTLM           = 'Unknown'
                        NTLMMinServerSec    = 'Unknown'
                        Issues              = 'Unable to verify NTLM settings'
                        RiskLevel           = 'Unknown'
                        Attacks             = 'NTLM Relay, Pass-the-Hash, Credential Theft'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Implement NTLM restrictions and auditing to reduce attack surface.'
        Impact      = 'High - NTLM restrictions may break legacy applications. Audit first, then restrict gradually.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# NTLM Restriction and Hardening
#############################################################################
#
# NTLM is vulnerable to:
# - Relay attacks (PetitPotam, PrinterBug, etc.)
# - Pass-the-Hash (stolen hashes used for authentication)
# - Credential theft (hashes exposed in memory)
#
# Current settings:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# PHASED APPROACH - Do Not Skip Steps!
#############################################################################

# Phase 1: Audit (2-4 weeks)
# Phase 2: Test restrictions in limited scope
# Phase 3: Expand restrictions gradually
# Phase 4: Full enforcement

#############################################################################
# Phase 1: Enable NTLM Auditing
#############################################################################

# First, enable auditing to understand NTLM usage:

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

        # Audit all incoming NTLM traffic
        Set-ItemProperty -Path `$msv1Path -Name 'AuditReceivingNTLMTraffic' -Value 2 -Type DWord

        Write-Host "Enabled NTLM auditing on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

# Monitor Event Log for NTLM usage:
# Event ID 8001: NTLM authentication from client
# Event ID 8002: NTLM authentication to remote server
# Event ID 8003: NTLM authentication blocked
# Event ID 8004: NTLM authentication allowed via exception

# Query NTLM events:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-NTLM/Operational'
    ID = 8001,8002
} -MaxEvents 100 | Group-Object { `$_.Message -match 'Client: (.+)$' | Out-Null; `$Matches[1] } |
    Sort-Object Count -Descending

#############################################################################
# Phase 2: Set LmCompatibilityLevel to 5
#############################################################################

# Require NTLMv2 only (deny LM and NTLMv1):

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'LmCompatibilityLevel' -Value 5 -Type DWord

        Write-Host "Set LmCompatibilityLevel=5 on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

# Also set via GPO for all computers:
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options
# -> "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM"

#############################################################################
# Phase 3: Require 128-bit Encryption
#############################################################################

# Require strong NTLM session security:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

        # Require NTLMv2 session security and 128-bit encryption
        # 0x20080000 = Require 128-bit + NTLMv2
        Set-ItemProperty -Path `$msv1Path -Name 'NTLMMinServerSec' -Value 0x20080000 -Type DWord
        Set-ItemProperty -Path `$msv1Path -Name 'NTLMMinClientSec' -Value 0x20080000 -Type DWord

        Write-Host "Set NTLMv2 session security on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Phase 4: Restrict Incoming NTLM (Carefully!)
#############################################################################

# WARNING: This may break applications. Test thoroughly first!

# Options for RestrictReceivingNTLMTraffic:
# 0 = Allow all
# 1 = Deny for domain accounts to domain servers
# 2 = Deny all

# Start with audit + allow:
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

        # Restrict domain accounts (value 1)
        Set-ItemProperty -Path `$msv1Path -Name 'RestrictReceivingNTLMTraffic' -Value 1 -Type DWord

        Write-Host "Restricted NTLM for domain accounts on `$env:COMPUTERNAME" -ForegroundColor Yellow
    }
}

# Add exceptions for known applications that require NTLM:
# Create exception list via GPO:
# Computer Configuration -> Windows Settings -> Security Settings
# -> Local Policies -> Security Options
# -> "Network security: Restrict NTLM: Add server exceptions in this domain"

#############################################################################
# Phase 5: Restrict Outgoing NTLM
#############################################################################

# Prevent computers from sending NTLM to external servers:

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

        # Audit outgoing (1) then Deny all (2)
        Set-ItemProperty -Path `$msv1Path -Name 'RestrictSendingNTLMTraffic' -Value 1 -Type DWord
    }
}

#############################################################################
# Verification
#############################################################################

# Verify settings on all DCs:
foreach (`$dc in `$dcs) {
    `$settings = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        `$msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        @{
            ComputerName = `$env:COMPUTERNAME
            LmCompatLevel = (Get-ItemProperty `$lsaPath -Name 'LmCompatibilityLevel' -EA SilentlyContinue).LmCompatibilityLevel
            AuditNTLM = (Get-ItemProperty `$msv1Path -Name 'AuditReceivingNTLMTraffic' -EA SilentlyContinue).AuditReceivingNTLMTraffic
            RestrictNTLM = (Get-ItemProperty `$msv1Path -Name 'RestrictReceivingNTLMTraffic' -EA SilentlyContinue).RestrictReceivingNTLMTraffic
        }
    }
    Write-Host "`$(`$settings.ComputerName): LmCompat=`$(`$settings.LmCompatLevel), Audit=`$(`$settings.AuditNTLM), Restrict=`$(`$settings.RestrictNTLM)"
}

"@
            return $commands
        }
    }
}
