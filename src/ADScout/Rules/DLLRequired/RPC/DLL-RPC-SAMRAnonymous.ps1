<#
.SYNOPSIS
    Detects anonymous SAMR enumeration access on Domain Controllers.

.DESCRIPTION
    Uses SMBLibrary and RPC to detect if anonymous users can enumerate
    domain users and groups via the SAMR interface.

.NOTES
    Rule ID    : DLL-RPC-SAMRAnonymous
    Category   : DLLRequired
    Requires   : SMBLibrary.dll, RPCForSMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-RPC-SAMRAnonymous'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Anonymous SAMR Enumeration Allowed'
    Description = 'Anonymous users can enumerate domain accounts via SAMR RPC interface, enabling reconnaissance and password attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll', 'RPCForSMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'SAMR Enumeration'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
        @{ Title = 'Restrict Anonymous Access'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1087.002', 'T1069.002')
    }

    CIS   = @('2.3.10.1', '2.3.10.2')
    STIG  = @('V-73671')
    ANSSI = @('vuln1_samr')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-RPC-SAMRAnonymous: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SAMRScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.Vulnerable) {
                    $findings += [PSCustomObject]@{
                        DomainController       = $dcName
                        OperatingSystem        = $dc.OperatingSystem
                        SAMRAccessible         = $scanResult.SAMRPipeAccessible
                        UserEnumeration        = $scanResult.UserEnumeration
                        GroupEnumeration       = $scanResult.GroupEnumeration
                        PasswordPolicyAccess   = $scanResult.PasswordPolicyAccess
                        RIDCyclingPossible     = $scanResult.RIDCyclingPossible
                        EnumeratedUserCount    = ($scanResult.EnumeratedUsers | Measure-Object).Count
                        RiskLevel              = if ($scanResult.UserEnumeration) { 'High' } else { 'Medium' }
                        AttackVector           = 'User enumeration, RID cycling, Password spraying'
                        DistinguishedName      = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-RPC-SAMRAnonymous: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict anonymous SAM enumeration via Group Policy.'
        Impact      = 'Low - Legitimate applications should use authenticated access.'
        Script      = {
            param($Finding, $Domain)

            @"
# Restrict Anonymous SAM Enumeration
# This prevents anonymous users from enumerating domain users and groups

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled

# Option 2: Configure via Registry
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord

# Also restrict general anonymous enumeration
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymous' -Value 2 -Type DWord

# Note: RestrictAnonymous = 2 provides maximum restriction but may affect
# some legacy applications. Test with RestrictAnonymous = 1 first.

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object RestrictAnonymous, RestrictAnonymousSAM
"@
        }
    }
}
