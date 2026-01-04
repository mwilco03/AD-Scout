<#
.SYNOPSIS
    Detects systems without LSA Protection (RunAsPPL) enabled.

.DESCRIPTION
    LSA Protection runs LSASS as a Protected Process Light (PPL), preventing
    unauthorized access to credentials in memory. Without this, tools like
    Mimikatz can easily extract credentials.

.NOTES
    Rule ID    : AUTH-LSAProtectionDisabled
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-LSAProtectionDisabled'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'LSA Protection (RunAsPPL) Not Enabled'
    Description = 'Identifies Domain Controllers and servers without LSA Protection enabled, leaving LSASS vulnerable to credential extraction attacks.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'LSA Protection'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection' }
        @{ Title = 'Credential Guard vs LSA Protection'; Url = 'https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage' }
        @{ Title = 'Bypassing LSA Protection'; Url = 'https://itm4n.github.io/lsass-runasppl/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.001')  # LSASS Memory
    }

    CIS   = @('18.3.1')
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

                $lsaProtectionStatus = 'Unknown'
                $runAsPPL = $null

                try {
                    $regResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        # Check RunAsPPL registry value
                        $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                        $runAsPPL = Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue

                        # Check if LSASS is actually running as PPL
                        $lsassProcess = Get-Process -Name lsass -ErrorAction SilentlyContinue
                        $isPPL = $false
                        if ($lsassProcess) {
                            try {
                                # Check process protection level
                                $isPPL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL -eq 1
                            } catch {
                                Write-Verbose "Could not determine LSASS PPL status: $_"
                            }
                        }

                        @{
                            RunAsPPL = $runAsPPL.RunAsPPL
                            LsassRunning = ($null -ne $lsassProcess)
                        }
                    } -ErrorAction Stop

                    if ($regResult) {
                        $runAsPPL = $regResult.RunAsPPL

                        if ($runAsPPL -eq 1) {
                            $lsaProtectionStatus = 'Enabled'
                        } elseif ($runAsPPL -eq 0) {
                            $lsaProtectionStatus = 'Disabled'
                        } else {
                            $lsaProtectionStatus = 'Not configured (disabled by default)'
                        }
                    }
                } catch {
                    $lsaProtectionStatus = 'Unable to check'
                }

                # Report if not enabled
                if ($lsaProtectionStatus -ne 'Enabled') {
                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        LSAProtection       = $lsaProtectionStatus
                        RunAsPPL            = if ($null -eq $runAsPPL) { 'Not Set' } else { $runAsPPL }
                        RiskLevel           = if ($lsaProtectionStatus -eq 'Disabled') { 'High' } else { 'Medium' }
                        OperatingSystem     = $dc.OperatingSystem
                        Impact              = 'LSASS memory can be dumped for credential extraction'
                        Recommendation      = 'Enable RunAsPPL or deploy Credential Guard'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable LSA Protection (RunAsPPL) on all Domain Controllers and critical servers.'
        Impact      = 'Medium - Some security products may need updates to work with LSA Protection.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Enable LSA Protection (RunAsPPL)
#############################################################################
#
# LSA Protection runs LSASS as a Protected Process Light (PPL).
# This prevents:
# - Process memory dumping (procdump, Task Manager)
# - Code injection into LSASS
# - Mimikatz sekurlsa commands
#
# However, attackers with kernel access can still bypass PPL.
# For stronger protection, use Credential Guard.
#
# Affected Systems:
$($Finding.Findings | ForEach-Object { "# - $($_.Computer): $($_.LSAProtection)" } | Out-String)

#############################################################################
# Step 1: Enable via Registry
#############################################################################

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

        # Enable LSA Protection
        Set-ItemProperty -Path `$lsaPath -Name 'RunAsPPL' -Value 1 -Type DWord

        Write-Host "LSA Protection enabled on `$env:COMPUTERNAME" -ForegroundColor Green
        Write-Host "Reboot required for change to take effect" -ForegroundColor Yellow
    }
}

#############################################################################
# Step 2: Enable via Group Policy (Recommended)
#############################################################################

# Create GPO linked to Domain Controllers OU

# GPO Path: Computer Configuration > Policies > Administrative Templates >
#           System > Local Security Authority

# Setting: "Configure LSASS to run as a protected process"
# Value: "Enabled with UEFI Lock" (most secure)
#        or "Enabled without UEFI Lock" (allows disabling via registry)

# Note: UEFI Lock requires Secure Boot and prevents disabling via registry

#############################################################################
# Step 3: Verify After Reboot
#############################################################################

# Check if LSA Protection is active:
Get-ADDomainController -Filter * | ForEach-Object {
    `$result = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        `$regValue = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL

        # Also check event log for LSA Protection status
        `$event = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Codeintegrity/Operational'
            Id=3033
        } -MaxEvents 1 -ErrorAction SilentlyContinue

        @{
            RunAsPPL = `$regValue
            Event = `$event.Message
        }
    } -ErrorAction SilentlyContinue

    `$status = if (`$result.RunAsPPL -eq 1) { 'Enabled' } else { 'Not Enabled' }
    Write-Host "`$(`$_.HostName): `$status" -ForegroundColor `$(if (`$status -eq 'Enabled') { 'Green' } else { 'Red' })
}

#############################################################################
# Step 4: Handle Incompatible Software
#############################################################################

# Some security software may not work with LSA Protection
# Event ID 3033 indicates a driver was blocked from loading into LSASS

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=3033} `
    -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message

# If legitimate software is blocked, options are:
# 1. Update the software to a compatible version
# 2. Add to LSASS protection exclusion (reduces security)
# 3. Use Credential Guard instead (more compatible)

#############################################################################
# Consider Credential Guard Instead
#############################################################################

# Credential Guard provides stronger protection than LSA Protection:
# - Uses virtualization-based security
# - Isolates credentials in secure enclave
# - Resistant to kernel-level attacks

# Check Credential Guard status:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard |
    Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus

# Enable Credential Guard:
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
#     -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
#     -Name 'LsaCfgFlags' -Value 1 -Type DWord

"@
            return $commands
        }
    }
}
