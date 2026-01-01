@{
    Id          = 'A-SMBSigning'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'SMB Signing Not Required'
    Description = 'SMB signing is not enforced on Domain Controllers, enabling NTLM relay attacks. Attackers can intercept SMB authentication and relay it to other systems to gain unauthorized access.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'SMB Signing Overview'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing' }
        @{ Title = 'NTLM Relay Attack'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'SMB Security Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001')          # LLMNR/NBT-NS Poisoning and SMB Relay
    }

    CIS   = @('2.3.9.1', '2.3.9.2')
    STIG  = @('V-63589')
    ANSSI = @('vuln1_smb_signing')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            try {
                $requireSecuritySignature = $null
                $enableSecuritySignature = $null

                # Check registry values for SMB signing
                if ($dc.Name -ne $env:COMPUTERNAME) {
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.Name)

                        # Server settings
                        $serverKey = $reg.OpenSubKey('System\CurrentControlSet\Services\LanmanServer\Parameters')
                        if ($serverKey) {
                            $requireSecuritySignature = $serverKey.GetValue('RequireSecuritySignature')
                            $enableSecuritySignature = $serverKey.GetValue('EnableSecuritySignature')
                            $serverKey.Close()
                        }
                        $reg.Close()
                    } catch {
                        $requireSecuritySignature = $null
                    }
                } else {
                    # Local check
                    $regPath = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
                    $requireSecuritySignature = Get-ItemProperty -Path $regPath -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue |
                                                Select-Object -ExpandProperty RequireSecuritySignature
                    $enableSecuritySignature = Get-ItemProperty -Path $regPath -Name 'EnableSecuritySignature' -ErrorAction SilentlyContinue |
                                               Select-Object -ExpandProperty EnableSecuritySignature
                }

                # Check if SMB signing is required
                # RequireSecuritySignature: 0 = Not Required, 1 = Required
                $signingRequired = $requireSecuritySignature -eq 1
                $signingEnabled = $enableSecuritySignature -eq 1

                $status = if ($signingRequired) {
                    'Required (Secure)'
                } elseif ($signingEnabled) {
                    'Enabled but Not Required (Vulnerable to downgrade)'
                } else {
                    'Not Enabled (Vulnerable)'
                }

                if (-not $signingRequired) {
                    $findings += [PSCustomObject]@{
                        DomainController         = $dc.Name
                        OperatingSystem          = $dc.OperatingSystem
                        RequireSecuritySignature = $requireSecuritySignature
                        EnableSecuritySignature  = $enableSecuritySignature
                        SigningStatus            = $status
                        RiskLevel                = if (-not $signingEnabled) { 'Critical' } else { 'High' }
                        AttackVector             = 'NTLM Relay attacks, SMB authentication interception'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController         = $dc.Name
                    OperatingSystem          = $dc.OperatingSystem
                    RequireSecuritySignature = 'Unable to determine'
                    EnableSecuritySignature  = 'Unable to determine'
                    SigningStatus            = 'Requires manual verification'
                    RiskLevel                = 'Unknown'
                    AttackVector             = 'NTLM Relay attacks if not properly configured'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure Domain Controllers and all systems to require SMB signing via Group Policy.'
        Impact      = 'Low - SMB signing has minimal performance impact on modern systems. Legacy systems may need updates.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Configure SMB Signing Requirements
# Affected DCs: $($Finding.Findings.DomainController -join ', ')

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# For Domain Controllers:
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# "Microsoft network client: Digitally sign communications (always)" = Enabled

# Option 2: Configure via Registry (per DC)

foreach (`$dc in @('$($Finding.Findings.DomainController -join "','")')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        # Server (LanmanServer) - Require signing
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' `
            -Name 'RequireSecuritySignature' -Value 1 -Type DWord
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' `
            -Name 'EnableSecuritySignature' -Value 1 -Type DWord

        # Client (LanmanWorkstation) - Require signing
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
            -Name 'RequireSecuritySignature' -Value 1 -Type DWord
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
            -Name 'EnableSecuritySignature' -Value 1 -Type DWord

        Write-Host "SMB signing requirements configured on `$env:COMPUTERNAME"
    }
}

# Verify the changes:
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' |
    Select-Object RequireSecuritySignature, EnableSecuritySignature

# Test SMB connectivity:
# Get-SmbConnection | Select-Object ServerName, SigningStatus

"@
            return $commands
        }
    }
}
