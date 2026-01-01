@{
    Id          = 'A-SMBSigningNotRequired'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMB Signing Not Required'
    Description = 'Detects when SMB signing is not required on domain controllers or member servers. Without required SMB signing, attackers can perform NTLM relay attacks to authenticate as victims against SMB services, leading to code execution and lateral movement.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'NTLM Relay Attack'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'SMB Relay Attack with ntlmrelayx'; Url = 'https://github.com/SecureAuthCorp/impacket' }
        @{ Title = 'Microsoft - SMB Signing'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1021.002')  # LLMNR/NBT-NS Poisoning, SMB/Windows Admin Shares
    }

    CIS   = @('2.3.9.1', '2.3.9.2')
    STIG  = @('V-220940', 'V-220941')
    ANSSI = @('R37')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $smbSettings = $Data.NetworkSecurity.SMBSigningSettings

        if ($smbSettings) {
            if (-not $smbSettings.ServerSigningRequired) {
                $findings += [PSCustomObject]@{
                    Finding             = 'SMB Server Signing Not Required'
                    CurrentState        = 'SMB signing is not required on servers'
                    ConfiguredViaGPO    = $smbSettings.ConfiguredViaGPO
                    RiskLevel           = 'Critical'
                    AttackTools         = 'ntlmrelayx, Responder, Inveigh'
                    AttackScenario      = @(
                        '1. Attacker captures NTLM authentication (via LLMNR/phishing)',
                        '2. Relays authentication to target server without signing',
                        '3. Executes commands as the victim user',
                        '4. If victim is admin, gains full server control'
                    ) -join ' -> '
                    Vulnerabilities     = ($smbSettings.Vulnerabilities -join '; ')
                    ImpactedSystems     = 'All Windows systems without SMB signing required'
                }
            }

            if (-not $smbSettings.ClientSigningRequired) {
                $findings += [PSCustomObject]@{
                    Finding             = 'SMB Client Signing Not Required'
                    CurrentState        = 'SMB client signing is not required'
                    RiskLevel           = 'High'
                    Impact              = 'Clients can be targeted by rogue SMB servers'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable required SMB signing via Group Policy on all domain controllers and servers.'
        Impact      = 'Low - May slightly increase CPU usage for SMB operations'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: ENABLE REQUIRED SMB SIGNING
# ================================================================
# SMB signing prevents NTLM relay attacks by cryptographically
# signing all SMB packets, preventing tampering.
#
# WITHOUT SMB SIGNING:
# Attacker can relay captured NTLM auth to execute code on servers
#
# Common attack: Responder + ntlmrelayx = Remote code execution

# ================================================================
# DOMAIN CONTROLLERS (HIGHEST PRIORITY)
# ================================================================
# DCs should ALWAYS require SMB signing

# GPO Path:
# Computer Configuration > Policies > Windows Settings >
# Security Settings > Local Policies > Security Options

# Required Settings:
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# "Microsoft network client: Digitally sign communications (always)" = Enabled

# ================================================================
# VIA GROUP POLICY (Recommended)
# ================================================================

# 1. Open GPMC, edit Default Domain Controllers Policy
# 2. Navigate to Security Options (path above)
# 3. Enable both "always" signing options

# ================================================================
# VIA REGISTRY (Immediate Fix)
# ================================================================

# Server signing required:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

# Client signing required:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

# ================================================================
# VIA POWERSHELL
# ================================================================

# Check current status:
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature

# Enable required signing:
Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force

# ================================================================
# VERIFY ALL DOMAIN CONTROLLERS
# ================================================================

`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    Write-Host "Checking `$(`$dc.Name)..."
    Invoke-Command -ComputerName `$dc.Name -ScriptBlock {
        Get-SmbServerConfiguration | Select-Object PSComputerName, RequireSecuritySignature
    }
}

# ================================================================
# FIND SYSTEMS WITHOUT SMB SIGNING
# ================================================================

# Use CrackMapExec or nmap to identify vulnerable systems:
# crackmapexec smb 10.0.0.0/24 --gen-relay-list nosigning.txt
# nmap --script smb-security-mode -p 445 10.0.0.0/24

"@
            return $commands
        }
    }
}
