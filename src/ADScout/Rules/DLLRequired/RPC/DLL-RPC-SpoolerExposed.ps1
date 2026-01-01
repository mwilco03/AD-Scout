<#
.SYNOPSIS
    Detects Domain Controllers with Print Spooler service accessible remotely.

.DESCRIPTION
    Uses SMBLibrary to detect if Print Spooler (MS-RPRN) is remotely accessible.
    This enables PrinterBug coercion and PrintNightmare exploitation.

.NOTES
    Rule ID    : DLL-RPC-SpoolerExposed
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-RPC-SpoolerExposed'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'Print Spooler Remotely Accessible on Domain Controllers'
    Description = 'Print Spooler service is remotely accessible on Domain Controllers, enabling PrinterBug coercion attacks and PrintNightmare exploitation.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'PrinterBug Attack'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'PrintNightmare'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527' }
        @{ Title = 'Disable Spooler on DCs'; Url = 'https://adsecurity.org/?p=4056' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1187', 'T1210')  # Forced Authentication, Exploitation
    }

    CIS   = @('5.2')
    STIG  = @('V-73401')
    ANSSI = @('vuln1_spooler')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-RPC-SpoolerExposed: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SpoolerScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.SpoolerAccessible) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        SpoolerAccessible     = $true
                        PrinterBugExploitable = $scanResult.PrinterBugExploitable
                        PrintNightmareRisk    = $scanResult.PrintNightmareRisk
                        AnonymousAccess       = $scanResult.AnonymousAccess
                        RiskLevel             = 'High'
                        AttackVector          = 'PrinterBug (coercion), PrintNightmare (RCE)'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-RPC-SpoolerExposed: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable Print Spooler service on Domain Controllers.'
        Impact      = 'Low - DCs do not need print services.'
        Script      = {
            param($Finding, $Domain)

            $dcs = $Finding.Findings.DomainController -join "', '"

            @"
# Disable Print Spooler on Domain Controllers
# Affected DCs: '$dcs'

# Print Spooler is NOT needed on Domain Controllers and exposes them to:
# 1. PrinterBug - Forces DC to authenticate to attacker
# 2. PrintNightmare (CVE-2021-34527) - Remote Code Execution

# Option 1: Disable via PowerShell (Immediate)
foreach (`$dc in @('$dcs')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
        Write-Host "Print Spooler disabled on `$env:COMPUTERNAME"
    }
}

# Option 2: Disable via Group Policy (Recommended for persistence)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > System Services
# "Print Spooler" = Disabled

# Option 3: Block remote access without disabling
# If spooler must remain enabled, block remote RPC access:
# Add firewall rule to block port 445 from non-admin sources
# Or use RPCFilters to block MS-RPRN

# Verify Spooler is disabled:
foreach (`$dc in @('$dcs')) {
    Get-Service -Name Spooler -ComputerName `$dc |
        Select-Object MachineName, Name, Status, StartType
}

# Note: Some monitoring solutions may require Print Spooler.
# Consider using Point and Print restrictions as alternative.
"@
        }
    }
}
