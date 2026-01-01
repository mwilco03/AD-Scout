@{
    Id          = 'A-NullSession'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Null Session Access Enabled'
    Description = 'Anonymous/null sessions can access domain information without authentication. This allows attackers to enumerate users, groups, shares, and other sensitive information without any credentials.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Restrict Anonymous Access'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares' }
        @{ Title = 'Anonymous Enumeration'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
        @{ Title = 'Hardening AD Against Null Sessions'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled' }
    )

    MITRE = @{
        Tactics    = @('TA0007')  # Discovery
        Techniques = @('T1087.002', 'T1135')  # Account Discovery: Domain, Network Share Discovery
    }

    CIS   = @('2.3.10.5', '2.3.10.6', '2.3.10.7')
    STIG  = @('V-63761', 'V-63767')
    ANSSI = @('vuln1_anonymous_access')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($dc in $Data) {
            try {
                $restrictAnonymous = $null
                $restrictAnonymousSAM = $null
                $everyoneIncludesAnonymous = $null

                if ($dc.Name -ne $env:COMPUTERNAME) {
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.Name)

                        $lsaKey = $reg.OpenSubKey('System\CurrentControlSet\Control\Lsa')
                        if ($lsaKey) {
                            $restrictAnonymous = $lsaKey.GetValue('RestrictAnonymous')
                            $restrictAnonymousSAM = $lsaKey.GetValue('RestrictAnonymousSAM')
                            $everyoneIncludesAnonymous = $lsaKey.GetValue('EveryoneIncludesAnonymous')
                            $lsaKey.Close()
                        }
                        $reg.Close()
                    } catch {
                        $restrictAnonymous = $null
                    }
                } else {
                    $regPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
                    $restrictAnonymous = Get-ItemProperty -Path $regPath -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue |
                                         Select-Object -ExpandProperty RestrictAnonymous
                    $restrictAnonymousSAM = Get-ItemProperty -Path $regPath -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue |
                                            Select-Object -ExpandProperty RestrictAnonymousSAM
                    $everyoneIncludesAnonymous = Get-ItemProperty -Path $regPath -Name 'EveryoneIncludesAnonymous' -ErrorAction SilentlyContinue |
                                                 Select-Object -ExpandProperty EveryoneIncludesAnonymous
                }

                # RestrictAnonymous: 0 = None, 1 = Do not allow enumeration of SAM accounts, 2 = No access without permissions
                # RestrictAnonymousSAM: 1 = Restricted (secure)
                # EveryoneIncludesAnonymous: 0 = Secure (Anonymous not in Everyone group)

                $issues = @()

                if ($null -eq $restrictAnonymous -or $restrictAnonymous -eq 0) {
                    $issues += "RestrictAnonymous not set (anonymous enumeration allowed)"
                }
                if ($null -eq $restrictAnonymousSAM -or $restrictAnonymousSAM -ne 1) {
                    $issues += "RestrictAnonymousSAM not set (SAM enumeration allowed)"
                }
                if ($everyoneIncludesAnonymous -eq 1) {
                    $issues += "EveryoneIncludesAnonymous enabled (Anonymous has Everyone permissions)"
                }

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        DomainController             = $dc.Name
                        OperatingSystem              = $dc.OperatingSystem
                        RestrictAnonymous            = $restrictAnonymous
                        RestrictAnonymousSAM         = $restrictAnonymousSAM
                        EveryoneIncludesAnonymous    = $everyoneIncludesAnonymous
                        Issues                       = $issues -join '; '
                        RiskLevel                    = 'High'
                        AttackVector                 = 'Unauthenticated enumeration of AD objects, users, groups, shares'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController             = $dc.Name
                    OperatingSystem              = $dc.OperatingSystem
                    RestrictAnonymous            = 'Unable to determine'
                    RestrictAnonymousSAM         = 'Unable to determine'
                    EveryoneIncludesAnonymous    = 'Unable to determine'
                    Issues                       = 'Unable to check registry - requires manual verification'
                    RiskLevel                    = 'Unknown'
                    AttackVector                 = 'Unauthenticated enumeration if not properly configured'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure Domain Controllers to restrict anonymous access via Group Policy or registry settings.'
        Impact      = 'Low - May affect very old applications that rely on anonymous enumeration. Test before enforcing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Restrict Anonymous/Null Session Access
# Affected DCs: $($Finding.Findings.DomainController -join ', ')

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options

# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
# "Network access: Let Everyone permissions apply to anonymous users" = Disabled
# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled

# Option 2: Configure via Registry (per DC)

foreach (`$dc in @('$($Finding.Findings.DomainController -join "','")')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        `$regPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'

        # Restrict anonymous enumeration
        Set-ItemProperty -Path `$regPath -Name 'RestrictAnonymous' -Value 1 -Type DWord
        Set-ItemProperty -Path `$regPath -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord
        Set-ItemProperty -Path `$regPath -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord

        Write-Host "Anonymous access restrictions configured on `$env:COMPUTERNAME"
    }
}

# Verify the changes:
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' |
    Select-Object RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous

# Test anonymous access (should fail after hardening):
# net use \\`$dc\IPC`$ "" /user:""

"@
            return $commands
        }
    }
}
