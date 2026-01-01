<#
.SYNOPSIS
    Detects Domain Controllers where SMB signing is not required at the protocol level.

.DESCRIPTION
    Uses SMBLibrary for protocol-level detection of SMB signing requirements.
    This provides actual verification of signing enforcement rather than
    registry checks which can be misleading.

.NOTES
    Rule ID    : DLL-SMB-SigningNotRequired
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-SMB-SigningNotRequired'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMB Signing Not Required (Protocol-Level Detection)'
    Description = 'SMB signing is not enforced at the protocol level on Domain Controllers. This enables NTLM relay and man-in-the-middle attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'SMB Signing Overview'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing' }
        @{ Title = 'NTLM Relay Attacks'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'SMB Security Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1557.001')
    }

    CIS   = @('2.3.9.1', '2.3.9.2')
    STIG  = @('V-63589')
    ANSSI = @('vuln1_smb_signing')
    NIST  = @('AC-17(2)', 'SC-8(1)', 'SC-23')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-SMB-SigningNotRequired: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SMBSigningScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and -not $scanResult.SigningRequired) {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        OperatingSystem     = $dc.OperatingSystem
                        NegotiatedDialect   = $scanResult.NegotiatedDialect
                        SigningEnabled      = $scanResult.SigningEnabled
                        SigningRequired     = $scanResult.SigningRequired
                        SecurityMode        = $scanResult.SecurityMode
                        RiskLevel           = if (-not $scanResult.SigningEnabled) { 'Critical' } else { 'High' }
                        AttackVector        = 'NTLM Relay, SMB Hijacking, MITM'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-SMB-SigningNotRequired: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable SMB signing requirement on all Domain Controllers via Group Policy.'
        Impact      = 'Low - SMB signing has minimal performance impact on modern systems.'
        Script      = {
            param($Finding, $Domain)

            $dcs = $Finding.Findings.DomainController -join "', '"

            @"
# Enable SMB Signing Requirement
# Affected DCs: '$dcs'

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# Server Settings:
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# "Microsoft network server: Digitally sign communications (if client agrees)" = Enabled

# Client Settings:
# "Microsoft network client: Digitally sign communications (always)" = Enabled
# "Microsoft network client: Digitally sign communications (if server agrees)" = Enabled

# Option 2: Configure via PowerShell (per server)
foreach (`$dc in @('$dcs')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        # Server configuration
        Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
        Set-SmbServerConfiguration -EnableSecuritySignature `$true -Force

        # Client configuration
        Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force
        Set-SmbClientConfiguration -EnableSecuritySignature `$true -Force

        Write-Host "SMB signing required on `$env:COMPUTERNAME"
    }
}

# Option 3: Configure via Registry
# Server (LanmanServer):
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
#     -Name 'RequireSecuritySignature' -Value 1 -Type DWord
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
#     -Name 'EnableSecuritySignature' -Value 1 -Type DWord

# Client (LanmanWorkstation):
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
#     -Name 'RequireSecuritySignature' -Value 1 -Type DWord
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
#     -Name 'EnableSecuritySignature' -Value 1 -Type DWord

# Verify:
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
Get-SmbClientConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
"@
        }
    }
}
