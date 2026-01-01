<#
.SYNOPSIS
    Detects Domain Controllers with SMBv1 protocol enabled.

.DESCRIPTION
    Uses SMBLibrary for protocol-level detection of SMBv1 support.
    SMBv1 is deprecated and vulnerable to EternalBlue (MS17-010) attacks.

.NOTES
    Rule ID    : DLL-SMB-v1Enabled
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-SMB-v1Enabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMBv1 Protocol Enabled (Protocol-Level Detection)'
    Description = 'SMBv1 protocol is enabled on Domain Controllers. SMBv1 is deprecated and vulnerable to multiple critical attacks including EternalBlue (MS17-010).'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'DomainControllers'

    # DLL Requirements
    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'Stop using SMB1'; Url = 'https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858' }
        @{ Title = 'MS17-010 (EternalBlue)'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010' }
        @{ Title = 'Disable SMBv1'; Url = 'https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0002')  # Lateral Movement, Execution
        Techniques = @('T1210')              # Exploitation of Remote Services
    }

    CIS   = @('9.1.1')
    STIG  = @('V-78057', 'V-73299')
    ANSSI = @('vuln1_smb1')
    NIST  = @('CM-7', 'SI-2')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        # Check DLL availability
        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-SMB-v1Enabled: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SMBDialectScan -ComputerName $dcName -TimeoutMs 5000 -TestSMB1

                if ($scanResult.Status -eq 'Success' -and $scanResult.SMB1Supported) {
                    $findings += [PSCustomObject]@{
                        DomainController  = $dcName
                        OperatingSystem   = $dc.OperatingSystem
                        SMB1Supported     = $true
                        HighestDialect    = $scanResult.HighestDialect
                        AllDialects       = ($scanResult.AllDialects -join ', ')
                        SMB1Only          = $scanResult.SMB1Only
                        RiskLevel         = if ($scanResult.SMB1Only) { 'Critical' } else { 'High' }
                        AttackVector      = 'EternalBlue (MS17-010), WannaCry, NotPetya'
                        DistinguishedName = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-SMB-v1Enabled: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable SMBv1 on all Domain Controllers and domain-joined systems.'
        Impact      = 'Medium - May affect legacy systems that require SMBv1. Test before deployment.'
        Script      = {
            param($Finding, $Domain)

            $dcs = $Finding.Findings.DomainController -join "', '"

            @"
# Disable SMBv1 on Domain Controllers
# Affected DCs: '$dcs'

# Option 1: Disable via PowerShell (Windows Server 2012 R2+)
foreach (`$dc in @('$dcs')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        # Disable SMB1 Server
        Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force

        # Disable SMB1 Client (Optional but recommended)
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

        Write-Host "SMBv1 disabled on `$env:COMPUTERNAME"
    }
}

# Option 2: Disable via Group Policy
# Computer Configuration > Administrative Templates > Network > Lanman Workstation
# "Enable insecure guest logons" = Disabled

# Computer Configuration > Administrative Templates > MS Security Guide
# "Configure SMB v1 server" = Disabled
# "Configure SMB v1 client driver" = Disable driver

# Option 3: Disable via Registry
# HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
# SMB1 = 0 (DWORD)

# Verify SMBv1 is disabled:
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Note: Reboot may be required for changes to take full effect
"@
        }
    }
}
