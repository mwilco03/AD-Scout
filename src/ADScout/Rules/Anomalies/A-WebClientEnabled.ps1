@{
    Id          = 'A-WebClientEnabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'WebClient Service Enabled - Coercion Risk'
    Description = 'Detects systems with the WebClient service enabled or running. WebClient enables WebDAV which can be abused for NTLM coercion attacks (PetitPotam, DFSCoerce) forcing systems to authenticate to attacker-controlled servers for credential relay attacks.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'PetitPotam NTLM Relay Attack'; Url = 'https://github.com/topotam/PetitPotam' }
        @{ Title = 'WebDAV Coercion Attacks'; Url = 'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient' }
        @{ Title = 'Microsoft - Mitigating NTLM Relay'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/ADV210003' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1187', 'T1557.001')  # Forced Authentication, LLMNR/NBT-NS Poisoning
    }

    CIS   = @('5.5.2')
    STIG  = @('V-220945')
    ANSSI = @('R46')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check Domain Controllers first (critical)
        foreach ($dc in $Data.DomainControllers) {
            try {
                $webClientStatus = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                    Get-Service -Name WebClient -ErrorAction SilentlyContinue |
                        Select-Object Status, StartType
                } -ErrorAction SilentlyContinue

                if ($webClientStatus -and ($webClientStatus.Status -eq 'Running' -or $webClientStatus.StartType -ne 'Disabled')) {
                    $findings += [PSCustomObject]@{
                        ComputerName        = $dc.Name
                        ComputerType        = 'Domain Controller'
                        WebClientStatus     = $webClientStatus.Status
                        WebClientStartType  = $webClientStatus.StartType
                        RiskLevel           = 'Critical'
                        Impact              = 'DC can be coerced to authenticate to attacker'
                        AttackTools         = 'PetitPotam, DFSCoerce, ShadowCoerce, PrinterBug'
                    }
                }
            }
            catch {
                # Continue
            }
        }

        # Check other servers (high risk)
        foreach ($computer in $Data.Computers) {
            if ($computer.OperatingSystem -notmatch 'Server') { continue }
            if ($computer.Name -in $Data.DomainControllers.Name) { continue }

            try {
                $webClientStatus = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                    Get-Service -Name WebClient -ErrorAction SilentlyContinue |
                        Select-Object Status, StartType
                } -ErrorAction SilentlyContinue

                if ($webClientStatus -and $webClientStatus.Status -eq 'Running') {
                    $findings += [PSCustomObject]@{
                        ComputerName        = $computer.Name
                        ComputerType        = 'Server'
                        OperatingSystem     = $computer.OperatingSystem
                        WebClientStatus     = $webClientStatus.Status
                        WebClientStartType  = $webClientStatus.StartType
                        RiskLevel           = 'High'
                        Impact              = 'Server can be coerced for credential relay'
                    }
                }
            }
            catch {
                # Continue
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the WebClient service on servers, especially Domain Controllers. WebDAV is rarely needed on servers.'
        Impact      = 'Low - May affect WebDAV-based file access from server'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# DISABLE WEBCLIENT SERVICE (WebDAV)
# ================================================================
# WebClient enables WebDAV which is abused for coercion attacks:
# - PetitPotam (MS-EFSRPC)
# - DFSCoerce (MS-DFSNM)
# - ShadowCoerce (MS-FSRVP)
#
# These attacks force target systems to authenticate to
# attacker-controlled servers for NTLM relay.

# ================================================================
# DISABLE ON ALL DOMAIN CONTROLLERS
# ================================================================

`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    Write-Host "Disabling WebClient on `$(`$dc.Name)..."

    Invoke-Command -ComputerName `$dc.Name -ScriptBlock {
        Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue
        Set-Service -Name WebClient -StartupType Disabled
    }
}

# ================================================================
# DISABLE ON SERVERS VIA GPO
# ================================================================

# 1. Create GPO for servers
# 2. Computer Configuration > Policies > Windows Settings >
#    Security Settings > System Services
# 3. WebClient > Disabled

# ================================================================
# AFFECTED SYSTEMS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"
# $($item.ComputerName) ($($item.ComputerType))
# Status: $($item.WebClientStatus), StartType: $($item.WebClientStartType)
Invoke-Command -ComputerName '$($item.ComputerName)' -ScriptBlock {
    Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue
    Set-Service -Name WebClient -StartupType Disabled
}

"@
            }

            $commands += @"

# ================================================================
# ADDITIONAL MITIGATIONS
# ================================================================

# 1. Enable Extended Protection for Authentication (EPA)
# 2. Require SMB signing (blocks some relay attacks)
# 3. Require LDAP signing (blocks LDAP relay)
# 4. Add privileged accounts to Protected Users group

"@
            return $commands
        }
    }
}
