@{
    Id          = 'A-PrintSpoolerOnDC'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Print Spooler Service Enabled on Domain Controllers'
    Description = 'Detects Domain Controllers with the Print Spooler service enabled. The Print Spooler has been the source of multiple critical vulnerabilities (PrintNightmare CVE-2021-34527, CVE-2021-1675) and enables coercion attacks (SpoolSample) that can lead to credential theft and domain compromise.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'PrintNightmare CVE-2021-34527'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527' }
        @{ Title = 'SpoolSample Coercion Attack'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'Microsoft - Disable Print Spooler on DCs'; Url = 'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-print-spooler' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008', 'TA0006')  # Privilege Escalation, Lateral Movement, Credential Access
        Techniques = @('T1547.012', 'T1557.001')      # Print Processors, LLMNR/NBT-NS Poisoning
    }

    CIS   = @('5.5.1')
    STIG  = @('V-220944')
    ANSSI = @('R45')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data.DomainControllers) {
            # Check if Print Spooler is running
            $spoolerStatus = $null
            try {
                $spoolerStatus = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                    Get-Service -Name Spooler -ErrorAction SilentlyContinue |
                        Select-Object Status, StartType
                } -ErrorAction SilentlyContinue
            }
            catch {
                # Try WMI as fallback
                try {
                    $spoolerStatus = Get-WmiObject -Class Win32_Service -ComputerName $dc.Name -Filter "Name='Spooler'" -ErrorAction SilentlyContinue |
                        Select-Object @{N='Status';E={$_.State}}, @{N='StartType';E={$_.StartMode}}
                }
                catch {
                    # Cannot determine status
                }
            }

            if ($spoolerStatus -and $spoolerStatus.Status -eq 'Running') {
                $findings += [PSCustomObject]@{
                    DCName              = $dc.Name
                    HostName            = $dc.HostName
                    IPv4Address         = $dc.IPv4Address
                    OperatingSystem     = $dc.OperatingSystem
                    SpoolerStatus       = $spoolerStatus.Status
                    SpoolerStartType    = $spoolerStatus.StartType
                    RiskLevel           = 'Critical'
                    Vulnerabilities     = @(
                        'CVE-2021-34527 (PrintNightmare) - Remote Code Execution',
                        'CVE-2021-1675 - Local Privilege Escalation',
                        'SpoolSample - NTLM Coercion Attack',
                        'PrinterBug - Force DC Authentication'
                    ) -join '; '
                    AttackScenario      = @(
                        '1. Attacker triggers RpcRemoteFindFirstPrinterChangeNotification',
                        '2. DC authenticates back to attacker-controlled server',
                        '3. Attacker captures DC machine account NTLM hash',
                        '4. Relays to another DC or ADCS for privilege escalation'
                    ) -join ' -> '
                    AttackTools         = 'SpoolSample, Printerbug, dementor.py, PetitPotam'
                }
            }
            elseif (-not $spoolerStatus) {
                # Could not determine - flag for manual review
                $findings += [PSCustomObject]@{
                    DCName              = $dc.Name
                    HostName            = $dc.HostName
                    IPv4Address         = $dc.IPv4Address
                    OperatingSystem     = $dc.OperatingSystem
                    SpoolerStatus       = 'Unknown - Manual check required'
                    RiskLevel           = 'Medium'
                    Note                = 'Could not remotely query service status'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the Print Spooler service on all Domain Controllers. DCs should never need to print.'
        Impact      = 'None - DCs should not be used for printing'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: DISABLE PRINT SPOOLER ON DOMAIN CONTROLLERS
# ================================================================
# The Print Spooler service on DCs enables:
# - PrintNightmare (CVE-2021-34527) - Remote Code Execution
# - SpoolSample/PrinterBug - Coercion attacks for credential theft
# - Multiple other privilege escalation vulnerabilities

# There is NO legitimate reason for Print Spooler on a DC!

# ================================================================
# DISABLE ON ALL DOMAIN CONTROLLERS
# ================================================================

`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    Write-Host "Disabling Print Spooler on `$(`$dc.Name)..."

    Invoke-Command -ComputerName `$dc.Name -ScriptBlock {
        # Stop the service
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

        # Disable the service
        Set-Service -Name Spooler -StartupType Disabled

        # Verify
        Get-Service -Name Spooler | Select-Object Name, Status, StartType
    }
}

# ================================================================
# ALTERNATIVE: VIA GROUP POLICY
# ================================================================

# 1. Create new GPO linked to Domain Controllers OU
# 2. Computer Configuration > Policies > Windows Settings >
#    Security Settings > System Services
# 3. Find "Print Spooler" > Set to "Disabled"

# ================================================================
# VERIFY REMEDIATION
# ================================================================

`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    `$status = Invoke-Command -ComputerName `$dc.Name -ScriptBlock {
        Get-Service -Name Spooler | Select-Object Status, StartType
    }
    Write-Host "`$(`$dc.Name): Status=`$(`$status.Status), StartType=`$(`$status.StartType)"
}

# ================================================================
# ALSO CONSIDER: Disable MS-RPRN RPC interface
# ================================================================

# Block the RPC interface used for coercion:
# netsh rpc filter add rule layer=um actiontype=block
# netsh rpc filter add condition field=if_uuid matchtype=equal data=12345678-1234-abcd-ef00-0123456789ab
# netsh rpc filter add filter

"@
            return $commands
        }
    }
}
