<#
.SYNOPSIS
    Detects Domain Controllers and critical servers without Credential Guard enabled.

.DESCRIPTION
    Credential Guard uses virtualization-based security to protect credentials from
    extraction via tools like Mimikatz. This rule identifies systems that should have
    Credential Guard enabled but don't.

.NOTES
    Rule ID    : AUTH-CredentialGuardDisabled
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-CredentialGuardDisabled'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'Credential Guard Not Enabled on Critical Systems'
    Description = 'Identifies Domain Controllers and critical servers without Windows Credential Guard enabled, leaving credentials vulnerable to extraction.'
    Severity    = 'High'
    Weight      = 45
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Credential Guard Overview'; Url = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/' }
        @{ Title = 'Credential Guard Requirements'; Url = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements' }
        @{ Title = 'Mimikatz and Credential Extraction'; Url = 'https://attack.mitre.org/techniques/T1003/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.001')  # LSASS Memory
    }

    CIS   = @('18.9.5.1')
    STIG  = @('V-63599')
    ANSSI = @('R38')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                $credGuardStatus = 'Unknown'
                $vbsStatus = 'Unknown'
                $secureBootStatus = 'Unknown'
                $osVersion = $dc.OperatingSystem

                # Check if OS supports Credential Guard (Windows Server 2016+)
                $supportsCredGuard = $osVersion -match '2016|2019|2022|2025'

                if (-not $supportsCredGuard) {
                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        OperatingSystem     = $osVersion
                        CredentialGuard     = 'Not Supported'
                        VBSStatus           = 'N/A'
                        SecureBoot          = 'N/A'
                        Issue               = 'OS does not support Credential Guard'
                        RiskLevel           = 'High'
                        Recommendation      = 'Upgrade to Windows Server 2016 or later'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                    continue
                }

                try {
                    # Check Credential Guard and VBS status via WMI/CIM
                    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ComputerName $dcName -ErrorAction Stop

                    if ($deviceGuard) {
                        # VBS Status
                        $vbsStatus = switch ($deviceGuard.VirtualizationBasedSecurityStatus) {
                            0 { 'Not Configured' }
                            1 { 'Enabled But Not Running' }
                            2 { 'Running' }
                            default { 'Unknown' }
                        }

                        # Credential Guard Status (check SecurityServicesRunning)
                        # 1 = Credential Guard, 2 = HVCI
                        if ($deviceGuard.SecurityServicesRunning -contains 1) {
                            $credGuardStatus = 'Running'
                        } elseif ($deviceGuard.SecurityServicesConfigured -contains 1) {
                            $credGuardStatus = 'Configured But Not Running'
                        } else {
                            $credGuardStatus = 'Not Configured'
                        }

                        # Secure Boot Status
                        if ($deviceGuard.SecureBootEnabled) {
                            $secureBootStatus = 'Enabled'
                        } else {
                            $secureBootStatus = 'Disabled'
                        }
                    }
                } catch {
                    try {
                        # Fallback: Check registry
                        $regResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                            $lsaCfgFlags = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue
                            $deviceGuard = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue

                            @{
                                LsaCfgFlags = $lsaCfgFlags.LsaCfgFlags
                                VBSEnabled = $deviceGuard.EnableVirtualizationBasedSecurity
                            }
                        } -ErrorAction Stop

                        if ($regResult) {
                            $credGuardStatus = if ($regResult.LsaCfgFlags -gt 0) { 'Configured (Registry)' } else { 'Not Configured' }
                            $vbsStatus = if ($regResult.VBSEnabled -eq 1) { 'Configured (Registry)' } else { 'Not Configured' }
                        }
                    } catch {
                        $credGuardStatus = 'Unable to check'
                        $vbsStatus = 'Unable to check'
                    }
                }

                # Report if Credential Guard is not running
                if ($credGuardStatus -ne 'Running') {
                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        OperatingSystem     = $osVersion
                        CredentialGuard     = $credGuardStatus
                        VBSStatus           = $vbsStatus
                        SecureBoot          = $secureBootStatus
                        Issue               = 'Credential Guard not protecting credentials'
                        RiskLevel           = 'High'
                        Recommendation      = 'Enable Credential Guard via GPO or registry'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable Credential Guard on all Domain Controllers and critical servers to protect credentials from extraction.'
        Impact      = 'Medium - Requires VBS-compatible hardware and may affect some applications.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Enable Credential Guard on Domain Controllers
#############################################################################
#
# Credential Guard protects:
# - NTLM password hashes
# - Kerberos Ticket Granting Tickets
# - Application credentials stored by Credential Manager
#
# Without Credential Guard, attackers can use Mimikatz to extract:
# - Clear text passwords (WDigest)
# - NTLM hashes for pass-the-hash
# - Kerberos tickets for pass-the-ticket
#
# Affected Systems:
$($Finding.Findings | ForEach-Object { "# - $($_.Computer): $($_.CredentialGuard) (VBS: $($_.VBSStatus))" } | Out-String)

#############################################################################
# Prerequisites
#############################################################################

# 1. Hardware Requirements:
#    - UEFI firmware (not legacy BIOS)
#    - Secure Boot enabled
#    - TPM 2.0 (recommended)
#    - Virtualization extensions (Intel VT-x, AMD-V)
#    - SLAT (Intel EPT, AMD RVI)

# 2. Software Requirements:
#    - Windows Server 2016 or later
#    - Hyper-V role not required (VBS is different)

# Check hardware compatibility:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object AvailableSecurityProperties, RequiredSecurityProperties,
                  VirtualizationBasedSecurityStatus, SecurityServicesConfigured,
                  SecurityServicesRunning

#############################################################################
# Enable via Group Policy (Recommended)
#############################################################################

# Computer Configuration > Policies > Administrative Templates >
#   System > Device Guard

# Setting: "Turn On Virtualization Based Security"
#   - Enabled
#   - Select Platform Security Level: Secure Boot and DMA Protection
#   - Credential Guard Configuration: Enabled with UEFI lock

# Note: "UEFI lock" prevents disabling via registry - requires firmware access
# Use "Enabled without lock" for testing

#############################################################################
# Enable via Registry (Alternative)
#############################################################################

# Run on each Domain Controller:
`$regCommands = @'
# Enable VBS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f

# Enable Secure Boot for VBS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f

# Enable Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

# Require reboot
shutdown /r /t 60 /c "Enabling Credential Guard - system will restart"
'@

"@

            foreach ($item in $Finding.Findings) {
                if ($item.CredentialGuard -eq 'Not Supported') {
                    $commands += @"

# $($item.Computer) - OS Upgrade Required
# Current OS: $($item.OperatingSystem)
# Credential Guard requires Windows Server 2016 or later

"@
                } else {
                    $commands += @"

# Enable Credential Guard on $($item.Computer)
Invoke-Command -ComputerName '$($item.Computer)' -ScriptBlock {
    # Enable VBS
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord -Force

    # Configure platform security (1 = Secure Boot, 3 = Secure Boot + DMA)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -Name 'RequirePlatformSecurityFeatures' -Value 1 -Type DWord -Force

    # Enable Credential Guard (1 = Enabled with lock, 2 = Enabled without lock)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LsaCfgFlags' -Value 2 -Type DWord -Force

    Write-Host "Credential Guard configured. Reboot required."
}

"@
                }
            }

            $commands += @"

#############################################################################
# Verification After Reboot
#############################################################################

# Check Credential Guard status:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object @{N='VBS Status';E={
        switch (`$_.VirtualizationBasedSecurityStatus) {
            0 { 'Not Configured' }
            1 { 'Enabled But Not Running' }
            2 { 'Running' }
        }
    }}, @{N='Credential Guard';E={
        if (`$_.SecurityServicesRunning -contains 1) { 'Running' }
        elseif (`$_.SecurityServicesConfigured -contains 1) { 'Configured' }
        else { 'Not Configured' }
    }}

# Event Log check:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DeviceGuard/Operational'} -MaxEvents 10

"@
            return $commands
        }
    }
}
