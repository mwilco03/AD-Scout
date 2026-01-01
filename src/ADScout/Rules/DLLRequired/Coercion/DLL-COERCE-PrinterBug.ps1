<#
.SYNOPSIS
    Detects PrinterBug (MS-RPRN) coercion vulnerability on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary to detect if Print Spooler is accessible for coercion.
    PrinterBug enables authentication coercion via MS-RPRN protocol.

.NOTES
    Rule ID    : DLL-COERCE-PrinterBug
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-COERCE-PrinterBug'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'PrinterBug (MS-RPRN) Coercion Vulnerable'
    Description = 'Print Spooler is accessible on Domain Controllers, enabling PrinterBug coercion attacks that can lead to domain compromise via NTLM relay.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'SpoolSample (PrinterBug)'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'Printer Bug to Domain Admin'; Url = 'https://www.slideshare.net/harmj0y/derbycon-2018-the-unintended-risks-of-trusting-active-directory' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')
        Techniques = @('T1187', 'T1557.001')
    }

    CIS   = @('5.2')
    ANSSI = @('vuln1_printerbug')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-COERCE-PrinterBug: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SpoolerScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.PrinterBugExploitable) {
                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        SpoolerAccessible     = $scanResult.SpoolerAccessible
                        PrinterBugExploitable = $true
                        AnonymousAccess       = $scanResult.AnonymousAccess
                        RiskLevel             = 'High'
                        AttackVector          = 'PrinterBug -> NTLM Relay -> Unconstrained Delegation/ADCS'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-COERCE-PrinterBug: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable Print Spooler service on Domain Controllers.'
        Impact      = 'Low - DCs do not need print services.'
        Script      = {
            param($Finding, $Domain)

            @"
# Disable Print Spooler to Prevent PrinterBug

# PrinterBug Attack:
# 1. Attacker calls RpcRemoteFindFirstPrinterChangeNotification(Ex)
# 2. DC attempts to authenticate to attacker-controlled host
# 3. Attacker relays NTLM to another service (ADCS, LDAP, etc.)
# 4. Attacker gains elevated access

# DISABLE SPOOLER ON ALL DCS:
foreach (`$dc in @($($Finding.Findings.DomainController | ForEach-Object { "'$_'" } -join ', '))) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
        Write-Host "Spooler disabled on `$env:COMPUTERNAME"
    }
}

# VERIFY:
foreach (`$dc in @($($Finding.Findings.DomainController | ForEach-Object { "'$_'" } -join ', '))) {
    Get-Service -Name Spooler -ComputerName `$dc |
        Select-Object MachineName, Status, StartType
}

# ALTERNATIVE: Use Group Policy
# Computer Configuration > Policies > Windows Settings > Security Settings
# > System Services > Print Spooler = Disabled
"@
        }
    }
}
