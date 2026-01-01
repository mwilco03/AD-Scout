@{
    Id          = 'A-DsHeuristicsAnonymous'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Anonymous LDAP Access Enabled via dsHeuristics'
    Description = 'Detects when the dsHeuristics attribute is configured to allow anonymous LDAP access (fAnonymousListDisabled or fAllowAnonymousAccess). This enables reconnaissance without authentication.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'dsHeuristics Attribute'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5' }
        @{ Title = 'Anonymous LDAP Queries'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
        @{ Title = 'PingCastle Rule A-DsHeuristicsAnonymous'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0007', 'TA0043')  # Discovery, Reconnaissance
        Techniques = @('T1087.002', 'T1590.001')  # Account Discovery: Domain, Gather Victim Network Info
    }

    CIS   = @('5.3.2')
    STIG  = @('V-63367')
    ANSSI = @('vuln1_anonymous_ldap')
    NIST  = @('AC-3', 'AC-14')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        <#
        dsHeuristics is a string where each character position controls a different setting:
        Position 7 (index 6): fDoListObject - List object mode
        Position 8 (index 7): fDoNotElevate - Don't elevate during install
        Position 9 (index 8): fAllowAnonymousAccess - Allow anonymous access to LDAP
        Position 10 (index 9): fLDAPBlockAnonOps - Block anonymous operations

        A value of '2' at position 7 enables anonymous LDAP access (fAllowAnonymousAccess)
        #>

        try {
            # Get the Directory Service object
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            $dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            $dsService = [ADSI]"LDAP://$dsServiceDN"

            $dsHeuristics = $dsService.dsHeuristics

            if ($dsHeuristics) {
                $heuristicsValue = $dsHeuristics.ToString()

                # Check position 7 (index 6) - fDoListObject
                # This can affect enumeration behavior
                if ($heuristicsValue.Length -ge 7) {
                    $doListObject = $heuristicsValue[6]
                    # Values: 0 = default, 1 = enabled, 2 = enabled with special behavior
                }

                # Check position 9 (index 8) - Anonymous access related
                if ($heuristicsValue.Length -ge 9) {
                    $anonAccess = $heuristicsValue[8]
                    if ($anonAccess -eq '2') {
                        $findings += [PSCustomObject]@{
                            DsHeuristics        = $heuristicsValue
                            Position            = '9 (fAllowAnonymousAccess)'
                            Value               = $anonAccess
                            Setting             = 'Anonymous LDAP access enabled'
                            Severity            = 'High'
                            Risk                = 'Anonymous users can query LDAP'
                            Impact              = 'Domain enumeration without authentication'
                            AttackScenario      = 'Attacker can enumerate users, groups, computers without credentials'
                        }
                    }
                }

                # Check for any non-default dsHeuristics values that affect security
                if ($heuristicsValue.Length -gt 0 -and $heuristicsValue -ne '0000000') {
                    # Report the current configuration for awareness
                    $configuredSettings = @()

                    # Analyze each known position
                    $positions = @{
                        1 = 'fSupFirstLastANR'
                        2 = 'fSupLastFirstANR'
                        3 = 'fDoListObject (legacy)'
                        4 = 'fLDAPBlockAnonOps'
                        5 = 'Reserved'
                        6 = 'fUserPwdSupport'
                        7 = 'fDoListObject'
                        8 = 'Reserved'
                        9 = 'fAllowAnonymousAccess'
                    }

                    for ($i = 0; $i -lt [Math]::Min($heuristicsValue.Length, 20); $i++) {
                        $char = $heuristicsValue[$i]
                        if ($char -ne '0' -and $char -ne ' ') {
                            $posName = if ($positions.ContainsKey($i + 1)) { $positions[$i + 1] } else { "Position $($i + 1)" }
                            $configuredSettings += "$posName = $char"
                        }
                    }

                    if ($configuredSettings.Count -gt 0 -and $findings.Count -eq 0) {
                        $findings += [PSCustomObject]@{
                            DsHeuristics        = $heuristicsValue
                            ConfiguredSettings  = $configuredSettings -join '; '
                            Severity            = 'Low'
                            Risk                = 'Non-default dsHeuristics configuration'
                            Impact              = 'May affect security behavior - review settings'
                            Recommendation      = 'Verify each setting is intentional'
                        }
                    }
                }
            }

            # Also check for anonymous access via other methods
            # Check RestrictAnonymous registry settings
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $anonSettings = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
                        return @{
                            RestrictAnonymous = $lsa.RestrictAnonymous
                            RestrictAnonymousSAM = $lsa.RestrictAnonymousSAM
                            EveryoneIncludesAnonymous = $lsa.EveryoneIncludesAnonymous
                        }
                    } -ErrorAction SilentlyContinue

                    if ($anonSettings) {
                        if ($anonSettings.RestrictAnonymous -eq 0) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Name
                                Setting             = 'RestrictAnonymous'
                                Value               = 0
                                Severity            = 'High'
                                Risk                = 'Anonymous SID/Name translation allowed'
                                RegistryPath        = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                            }
                        }

                        if ($anonSettings.EveryoneIncludesAnonymous -eq 1) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Name
                                Setting             = 'EveryoneIncludesAnonymous'
                                Value               = 1
                                Severity            = 'Critical'
                                Risk                = 'Anonymous users have Everyone access'
                                RegistryPath        = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                            }
                        }
                    }
                } catch { }
            }

        } catch {
            Write-Verbose "A-DsHeuristicsAnonymous: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reset dsHeuristics to disable anonymous LDAP access. Configure RestrictAnonymous registry settings appropriately.'
        Impact      = 'Low - Disabling anonymous access is recommended. May break legacy applications relying on anonymous queries.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Anonymous LDAP Access Remediation
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.Setting): Value = $($_.Value)" } | Out-String)

# STEP 1: Check current dsHeuristics value
`$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
`$dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,`$configNC"
`$dsService = [ADSI]"LDAP://`$dsServiceDN"
Write-Host "Current dsHeuristics: `$(`$dsService.dsHeuristics)"

# STEP 2: Reset dsHeuristics position 9 to disable anonymous access
# The value should be '0' or not set for position 9

`$currentValue = `$dsService.dsHeuristics.ToString()
if (`$currentValue.Length -ge 9) {
    # Replace character at position 9 (index 8) with '0'
    `$chars = `$currentValue.ToCharArray()
    `$chars[8] = '0'
    `$newValue = [string]::new(`$chars)

    `$dsService.Put("dsHeuristics", `$newValue)
    `$dsService.SetInfo()
    Write-Host "Updated dsHeuristics to: `$newValue"
}

# STEP 3: Configure RestrictAnonymous via GPO
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options

# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
# "Network access: Allow anonymous SID/Name translation" = Disabled
# "Network access: Let Everyone permissions apply to anonymous users" = Disabled

# Via registry on each DC:
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

        # RestrictAnonymous: 0 = None, 1 = No enum without auth, 2 = No access without auth
        Set-ItemProperty -Path `$lsaPath -Name 'RestrictAnonymous' -Value 1 -Type DWord

        # RestrictAnonymousSAM: 1 = Don't allow anonymous SAM enum
        Set-ItemProperty -Path `$lsaPath -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord

        # EveryoneIncludesAnonymous: 0 = Anonymous not in Everyone
        Set-ItemProperty -Path `$lsaPath -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord

        Write-Host "Configured anonymous restrictions on `$env:COMPUTERNAME"
    }
}

# STEP 4: Verify anonymous access is blocked
# From a non-domain machine, test:
# rpcclient -U "" -N <DC-IP> -c "enumdomusers"
# Should return ACCESS_DENIED

# STEP 5: Force GPO update
`$dcs | ForEach-Object {
    Invoke-Command -ComputerName `$_.HostName -ScriptBlock { gpupdate /force }
}

"@
            return $commands
        }
    }
}
