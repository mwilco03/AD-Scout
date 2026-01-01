@{
    Id          = 'A-DCRefuseComputerPwdChange'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Domain Controller Refuses Computer Password Changes'
    Description = 'Detects when Domain Controllers are configured to refuse computer account password changes. This prevents automatic machine password rotation, weakening security and enabling pass-the-hash attacks with stale credentials.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Machine Account Password Process'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-refuse-machine-account-password-changes' }
        @{ Title = 'PingCastle Rule A-DCRefuseComputerPwdChange'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1003.001', 'T1078.002')  # LSASS Memory, Domain Accounts
    }

    CIS   = @('2.3.6.1')
    STIG  = @('V-63597')
    ANSSI = @('vuln2_refuse_computer_pwd')
    NIST  = @('IA-5', 'SC-28')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Registry path: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
        # Value: RefusePasswordChange = 1 means password changes are refused

        try {
            # Check GPOs for the setting
            foreach ($gpo in $Data.GPOs) {
                if ($gpo.RegistrySettings) {
                    foreach ($regSetting in $gpo.RegistrySettings) {
                        if ($regSetting.KeyPath -match 'Services\\Netlogon\\Parameters' -and
                            $regSetting.ValueName -eq 'RefusePasswordChange' -and
                            $regSetting.Value -eq 1) {

                            $findings += [PSCustomObject]@{
                                GPOName             = $gpo.DisplayName
                                Setting             = 'RefusePasswordChange'
                                Value               = 1
                                RegistryPath        = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                                Severity            = 'High'
                                Risk                = 'Computer accounts cannot rotate passwords'
                                Impact              = 'Stale machine credentials persist indefinitely'
                                AttackScenario      = 'Compromised machine credentials remain valid for pass-the-hash'
                            }
                        }
                    }
                }

                # Also check via Computer Configuration policies
                if ($gpo.ComputerConfiguration -and $gpo.ComputerConfiguration.SecuritySettings) {
                    $securityOptions = $gpo.ComputerConfiguration.SecuritySettings.SecurityOptions
                    if ($securityOptions) {
                        $refuseSetting = $securityOptions | Where-Object {
                            $_.Name -match 'RefusePasswordChange' -or
                            $_.KeyName -match 'RefusePasswordChange'
                        }
                        if ($refuseSetting -and $refuseSetting.Value -eq 1) {
                            $findings += [PSCustomObject]@{
                                GPOName             = $gpo.DisplayName
                                Setting             = 'Domain controller: Refuse machine account password changes'
                                Value               = 'Enabled'
                                Severity            = 'High'
                                Risk                = 'Computer accounts cannot rotate passwords'
                            }
                        }
                    }
                }
            }

            # Check Default Domain Controllers Policy specifically
            $ddcpGPO = $Data.GPOs | Where-Object {
                $_.DisplayName -match 'Default Domain Controllers Policy'
            } | Select-Object -First 1

            if ($ddcpGPO -and -not $findings) {
                # If we couldn't find the setting in GPO data, check DCs directly
                foreach ($dc in $Data.DomainControllers) {
                    try {
                        $regValue = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RefusePasswordChange' -ErrorAction SilentlyContinue
                        } -ErrorAction SilentlyContinue

                        if ($regValue -and $regValue.RefusePasswordChange -eq 1) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Name
                                HostName            = $dc.DNSHostName
                                Setting             = 'RefusePasswordChange'
                                Value               = 1
                                Source              = 'Registry'
                                Severity            = 'High'
                                Risk                = 'This DC refuses computer password changes'
                            }
                        }
                    } catch {
                        # Cannot check remotely
                    }
                }
            }

        } catch {
            Write-Verbose "A-DCRefuseComputerPwdChange: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove or disable the RefusePasswordChange setting to allow normal computer account password rotation.'
        Impact      = 'Low - This restores default secure behavior. No negative impact expected.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Domain Controller Refuse Computer Password Change Remediation
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.GPOName): $($_.Setting) = $($_.Value)" } | Out-String)

# Computer accounts normally change their passwords every 30 days.
# Refusing this creates a security risk as compromised machine
# credentials remain valid indefinitely.

# STEP 1: Check the current setting via GPO
Get-GPResultantSetOfPolicy -Computer (Get-ADDomainController).HostName -ReportType Html -Path "`$env:TEMP\RSOP_DC.html"
Start-Process "`$env:TEMP\RSOP_DC.html"

# STEP 2: Modify the Default Domain Controllers Policy
`$gpoName = "Default Domain Controllers Policy"

# Open in Group Policy Editor:
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
# "Domain controller: Refuse machine account password changes" = Disabled

# STEP 3: Or remove via registry on each DC
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        `$current = Get-ItemProperty -Path `$path -Name 'RefusePasswordChange' -ErrorAction SilentlyContinue
        if (`$current.RefusePasswordChange -eq 1) {
            Set-ItemProperty -Path `$path -Name 'RefusePasswordChange' -Value 0
            Write-Host "Disabled RefusePasswordChange on `$env:COMPUTERNAME"
        } else {
            Write-Host "RefusePasswordChange already disabled on `$env:COMPUTERNAME"
        }
    }
}

# STEP 4: Force GPO refresh
`$dcs | ForEach-Object {
    Invoke-Command -ComputerName `$_.HostName -ScriptBlock { gpupdate /force }
}

# STEP 5: Verify the setting
`$dcs | ForEach-Object {
    Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        `$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RefusePasswordChange' -ErrorAction SilentlyContinue).RefusePasswordChange
        Write-Host "`$env:COMPUTERNAME - RefusePasswordChange: `$val"
    }
}

"@
            return $commands
        }
    }
}
