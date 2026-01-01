<#
.SYNOPSIS
    Detects Domain Controllers that allow null session access.

.DESCRIPTION
    Uses SMBLibrary for protocol-level testing of null session capabilities.
    Null sessions allow anonymous enumeration of users, groups, and shares.

.NOTES
    Rule ID    : DLL-SMB-NullSessionAllowed
    Category   : DLLRequired
    Requires   : SMBLibrary.dll
    Author     : AD-Scout Contributors
#>

@{
    Id          = 'DLL-SMB-NullSessionAllowed'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Null Session Access Allowed (Protocol-Level Detection)'
    Description = 'Null session access is permitted on Domain Controllers, allowing anonymous enumeration of users, groups, and shares.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    RequiresDLL     = $true
    DLLNames        = @('SMBLibrary.dll')
    FallbackBehavior = 'Skip'

    References  = @(
        @{ Title = 'Restricting Null Session Access'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares' }
        @{ Title = 'Null Session Attacks'; Url = 'https://attack.mitre.org/techniques/T1087/' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1087.002', 'T1069.002')  # Domain Account/Group Discovery
    }

    CIS   = @('2.3.10.2', '2.3.10.3')
    STIG  = @('V-73671', 'V-73673')
    ANSSI = @('vuln1_null_session')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
        Maximum = 100
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Initialize-ADScoutSMBLibrary)) {
            Write-Warning "DLL-SMB-NullSessionAllowed: SMBLibrary not available, skipping"
            return @()
        }

        $findings = @()

        foreach ($dc in $Data) {
            $dcName = $dc.Name
            if (-not $dcName) { $dcName = $dc.DnsHostName }
            if (-not $dcName) { continue }

            try {
                $scanResult = Invoke-SMBNullSessionScan -ComputerName $dcName -TimeoutMs 5000

                if ($scanResult.Status -eq 'Success' -and $scanResult.Vulnerable) {
                    $vulnerabilities = @()
                    if ($scanResult.NullSessionAllowed) { $vulnerabilities += 'Anonymous Login' }
                    if ($scanResult.IPCAccess) { $vulnerabilities += 'IPC$ Access' }
                    if ($scanResult.ShareEnumeration) { $vulnerabilities += 'Share Enumeration' }
                    if ($scanResult.UserEnumeration) { $vulnerabilities += 'User Enumeration' }
                    if ($scanResult.GroupEnumeration) { $vulnerabilities += 'Group Enumeration' }

                    $findings += [PSCustomObject]@{
                        DomainController      = $dcName
                        OperatingSystem       = $dc.OperatingSystem
                        NullSessionAllowed    = $scanResult.NullSessionAllowed
                        AnonymousIPCAccess    = $scanResult.IPCAccess
                        ShareEnumeration      = $scanResult.ShareEnumeration
                        UserEnumeration       = $scanResult.UserEnumeration
                        GroupEnumeration      = $scanResult.GroupEnumeration
                        EnumeratedShares      = ($scanResult.EnumeratedShares -join ', ')
                        Vulnerabilities       = ($vulnerabilities -join ', ')
                        RiskLevel             = if ($scanResult.UserEnumeration) { 'Critical' } else { 'High' }
                        AttackVector          = 'User enumeration, Password spraying, Reconnaissance'
                        DistinguishedName     = $dc.DistinguishedName
                    }
                }
            } catch {
                Write-Verbose "DLL-SMB-NullSessionAllowed: Error scanning $dcName - $($_.Exception.Message)"
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Restrict null session access via Group Policy and registry settings.'
        Impact      = 'Low to Medium - May affect legacy applications using anonymous access.'
        Script      = {
            param($Finding, $Domain)

            $dcs = $Finding.Findings.DomainController -join "', '"

            @"
# Restrict Null Session Access
# Affected DCs: '$dcs'

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled
# "Network access: Let Everyone permissions apply to anonymous users" = Disabled

# Option 2: Configure via Registry
foreach (`$dc in @('$dcs')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        # Restrict anonymous enumeration of SAM accounts
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'RestrictAnonymous' -Value 1 -Type DWord

        # Restrict anonymous enumeration of SAM accounts and shares
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord

        # Restrict anonymous access to named pipes and shares
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
            -Name 'RestrictNullSessAccess' -Value 1 -Type DWord

        # Don't let Everyone permissions apply to anonymous users
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord

        # Clear named pipes accessible to anonymous
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
            -Name 'NullSessionPipes' -Value @() -Type MultiString

        Write-Host "Null session access restricted on `$env:COMPUTERNAME"
    }
}

# Verify:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous
"@
        }
    }
}
