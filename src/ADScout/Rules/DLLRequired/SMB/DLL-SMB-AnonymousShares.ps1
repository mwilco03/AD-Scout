<#
.SYNOPSIS
    Detects Domain Controllers that allow anonymous share enumeration.

.DESCRIPTION
    Uses SMBLibrary to detect if shares can be enumerated via null session.
    Anonymous share enumeration aids attackers in reconnaissance.

.NOTES
    Rule ID    : DLL-SMB-AnonymousShares
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-SMB-AnonymousShares'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Anonymous Share Enumeration Allowed'
    Description = 'Domain Controllers allow anonymous enumeration of SMB shares, aiding attacker reconnaissance.'
    Severity    = 'Medium'
    Weight      = 15
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'Restrict Anonymous Access'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares' }
        @{ Title = 'SMB Share Enumeration'; Url = 'https://attack.mitre.org/techniques/T1135/' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1135')   # Network Share Discovery
    }

    CIS   = @('2.3.10.3')
    STIG  = @('V-73673')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
        Maximum = 50
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-SMB-AnonymousShares: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SMBShareScan -ComputerName $dcName -TimeoutMs 5000 -TestAnonymous

                if ($scanResult.Status -eq 'Success' -and $scanResult.NullSessionShares) {
                    $sensitiveShares = $scanResult.SensitiveShares -join ', '
                    $allShares = ($scanResult.Shares | Where-Object { $_.AccessMethod -eq 'Anonymous' }).Name -join ', '

                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        AnonymousAccess       = $true
                        ShareEnumeration      = $true
                        EnumeratedShares      = $allShares
                        SensitiveShares       = $sensitiveShares
                        TotalShares           = $scanResult.TotalShares
                        RiskLevel             = if ($sensitiveShares) { 'High' } else { 'Medium' }
                        AttackVector          = 'Reconnaissance, Lateral movement planning'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-SMB-AnonymousShares: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict anonymous share enumeration via Group Policy.'
        Impact      = 'Low - Legitimate users should authenticate.'
        Script      = {
            param($Finding, $Domain)

            @"
# Restrict Anonymous Share Enumeration

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled

# Option 2: Configure via Registry
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymous' -Value 1 -Type DWord

# Also clear any null session shares:
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'NullSessionShares' -Value @() -Type MultiString

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object RestrictAnonymous

Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' |
    Select-Object NullSessionShares
"@
        }
    }
}
