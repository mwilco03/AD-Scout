<#
.SYNOPSIS
    Detects SMBv1 protocol enabled on domain systems.

.DESCRIPTION
    SMBv1 is a legacy protocol with known vulnerabilities including EternalBlue
    (MS17-010). It should be disabled on all modern systems.

.NOTES
    Rule ID    : A-SMB1Enabled
    Category   : Anomalies
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'A-SMB1Enabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMBv1 Protocol Enabled'
    Description = 'Detects systems with SMBv1 enabled, which is vulnerable to EternalBlue (MS17-010/WannaCry) and other exploits.'
    Severity    = 'Critical'
    Weight      = 70
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'MS17-010 - EternalBlue'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010' }
        @{ Title = 'Disable SMBv1'; Url = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
        @{ Title = 'WannaCry Ransomware'; Url = 'https://www.cisa.gov/news-events/alerts/2017/05/12/wannacry-ransomware' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0002')  # Lateral Movement, Execution
        Techniques = @('T1210', 'T1569.002')  # Exploitation of Remote Services
    }

    CIS   = @('9.1.1')
    STIG  = @('V-73299', 'V-73301')
    ANSSI = @('R56')

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

                $smb1Status = 'Unknown'

                try {
                    # Check SMBv1 status via registry
                    $result = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $smb1Client = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'SMB1' -ErrorAction SilentlyContinue
                        $smb1Server = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol
                        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue

                        @{
                            SMB1Client = $smb1Client.SMB1
                            SMB1Server = $smb1Server.EnableSMB1Protocol
                            SMB1Feature = $smb1Feature.State
                        }
                    } -ErrorAction Stop

                    if ($result) {
                        $smb1Enabled = $false
                        $enabledComponents = @()

                        if ($result.SMB1Server -eq $true) {
                            $smb1Enabled = $true
                            $enabledComponents += 'Server'
                        }
                        if ($result.SMB1Client -ne 0) {
                            $smb1Enabled = $true
                            $enabledComponents += 'Client'
                        }
                        if ($result.SMB1Feature -eq 'Enabled') {
                            $smb1Enabled = $true
                            $enabledComponents += 'Windows Feature'
                        }

                        if ($smb1Enabled) {
                            $findings += [PSCustomObject]@{
                                Computer            = $dcName
                                SMB1Status          = 'Enabled'
                                EnabledComponents   = ($enabledComponents -join ', ')
                                VulnerableTo        = 'MS17-010 (EternalBlue), EternalRomance, WannaCry, NotPetya'
                                RiskLevel           = 'Critical'
                                OperatingSystem     = $dc.OperatingSystem
                                DistinguishedName   = $dc.DistinguishedName
                            }
                        }
                    }
                } catch {
                    # Mark as needing manual check
                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        SMB1Status          = 'Unable to verify'
                        EnabledComponents   = 'Manual check required'
                        VulnerableTo        = 'Potentially MS17-010'
                        RiskLevel           = 'High'
                        OperatingSystem     = $dc.OperatingSystem
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable SMBv1 on all systems. This protocol is obsolete and vulnerable to multiple critical exploits.'
        Impact      = 'Medium - Legacy systems and applications may require SMBv1. Test before deployment.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable SMBv1 - Critical Security Update
#############################################################################
#
# SMBv1 vulnerabilities include:
# - MS17-010 (EternalBlue) - Remote code execution
# - EternalChampion, EternalRomance, EternalSynergy
# - Used by WannaCry, NotPetya, and other ransomware
#
# Microsoft recommends disabling SMBv1 on all systems.
#
# Affected Systems:
$($Finding.Findings | ForEach-Object { "# - $($_.Computer): SMBv1 $($_.SMB1Status) ($($_.EnabledComponents))" } | Out-String)

#############################################################################
# Step 1: Audit SMBv1 Usage Before Disabling
#############################################################################

# Enable SMBv1 audit logging (Windows 8.1/2012 R2 and later)
Set-SmbServerConfiguration -AuditSmb1Access `$true -Force

# Wait 24-48 hours, then check for SMBv1 connections:
# Event Log: Applications and Services Logs > Microsoft > Windows > SMBServer > Audit
# Event ID 3000 - SMBv1 connection attempt

#############################################################################
# Step 2: Disable SMBv1 on Windows Server 2012 R2 and Later
#############################################################################

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

# Disable SMBv1 on $($item.Computer)
Invoke-Command -ComputerName '$($item.Computer)' -ScriptBlock {
    # Disable SMBv1 Server
    Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force

    # Disable SMBv1 Client (Windows 8.1/2012 R2+)
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Client' -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Server' -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction SilentlyContinue

    # Registry method (works on all versions)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Type DWord -Force

    Write-Host "SMBv1 disabled on `$env:COMPUTERNAME. Reboot may be required." -ForegroundColor Green
}

"@
            }

            $commands += @"

#############################################################################
# Step 3: Deploy via Group Policy (Recommended)
#############################################################################

# Create GPO: "Security - Disable SMBv1"
# Link to Domain Controllers OU and all computer OUs

# Computer Configuration > Preferences > Windows Settings > Registry

# Disable SMBv1 Server:
# Key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
# Value: SMB1
# Type: REG_DWORD
# Data: 0

# Alternatively, use PowerShell script via GPO:
# Computer Configuration > Policies > Windows Settings > Scripts > Startup

#############################################################################
# Verification
#############################################################################

# Check SMBv1 status on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    `$status = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
    } -ErrorAction SilentlyContinue
    Write-Host "`$(`$_.HostName): SMBv1 = `$(`$status.EnableSMB1Protocol)" -ForegroundColor `$(
        if (`$status.EnableSMB1Protocol -eq `$false) { 'Green' } else { 'Red' }
    )
}

"@
            return $commands
        }
    }
}
