@{
    Id          = 'A-LMHashNotDisabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LM Hash Storage Not Disabled'
    Description = 'Detects when LAN Manager (LM) hash storage is not disabled. LM hashes are cryptographically weak and can be cracked almost instantly, exposing passwords.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Microsoft - Do not store LAN Manager hash'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change' }
        @{ Title = 'MITRE ATT&CK - Password Cracking'; Url = 'https://attack.mitre.org/techniques/T1110/002/' }
        @{ Title = 'STIG Viewer - NoLMHash'; Url = 'https://stigviewer.com/stigs/microsoft_windows_server_2022' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1110.002')  # Brute Force: Password Cracking
    }

    CIS   = @('2.3.11.5')  # Verified - Network security: Do not store LAN Manager hash
    STIG  = @('V-205655')  # Windows Server 2019/2022 - NoLMHash
    ANSSI = @()  # No direct ANSSI mapping verified
    NIST  = @('IA-5')  # Authenticator Management

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Registry setting to check:
        # HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash
        # Should be 1 (enabled = do not store LM hash)
        $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        $registryValue = 'NoLMHash'
        $expectedValue = 1

        $lmHashDisabled = $false
        $configuredInGPO = $false
        $gpoSettings = @()

        try {
            # Check GPOs for the setting
            foreach ($gpo in $Data.GPOs) {
                $gpoName = $gpo.DisplayName
                $gpoPath = $gpo.Path

                if (-not $gpoPath) { continue }

                # Check registry.pol or GptTmpl.inf
                $securityInfPath = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $securityInfPath -ErrorAction SilentlyContinue) {
                    $content = Get-Content $securityInfPath -Raw -ErrorAction SilentlyContinue

                    # Look for NoLMHash setting in various forms
                    if ($content -match 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLmHash\s*=\s*(\d+),(\d+)') {
                        $type = $Matches[1]
                        $value = [int]$Matches[2]
                        $configuredInGPO = $true

                        $gpoSettings += @{
                            GPO = $gpoName
                            Value = $value
                            Enabled = ($value -eq 1)
                        }

                        if ($value -eq 1) {
                            $lmHashDisabled = $true
                        }
                    }
                }

                # Check Registry.pol
                $regPolPath = "$gpoPath\Machine\Registry.pol"
                if (Test-Path $regPolPath -ErrorAction SilentlyContinue) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($regPolPath)
                        $content = [System.Text.Encoding]::Unicode.GetString($bytes)

                        if ($content -match 'NoLMHash') {
                            $configuredInGPO = $true
                            # If it's in the pol file, assume it's being set
                            $gpoSettings += @{
                                GPO = $gpoName
                                Source = 'Registry.pol'
                            }
                        }
                    } catch { }
                }
            }

            # Check DCs directly
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $dcValue = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue

                    if ($dcValue) {
                        if ($dcValue.NoLMHash -eq 1) {
                            $lmHashDisabled = $true
                        } else {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Name
                                RegistryPath        = "$registryPath\$registryValue"
                                CurrentValue        = $dcValue.NoLMHash
                                ExpectedValue       = 1
                                Severity            = 'Medium'
                                Risk                = 'LM hash storage enabled on Domain Controller'
                                Impact              = 'New passwords will have weak LM hash stored'
                            }
                        }
                    } else {
                        # Key doesn't exist - LM hash may be stored
                        $findings += [PSCustomObject]@{
                            DCName              = $dc.Name
                            RegistryPath        = "$registryPath\$registryValue"
                            CurrentValue        = 'Not Configured'
                            ExpectedValue       = 1
                            Severity            = 'Medium'
                            Risk                = 'NoLMHash not configured on Domain Controller'
                            Impact              = 'Default behavior may store LM hashes'
                        }
                    }
                } catch {
                    Write-Verbose "A-LMHashNotDisabled: Cannot check DC $($dc.Name) - $_"
                }
            }

            # If no GPO configures this and no DC findings yet
            if (-not $configuredInGPO -and $findings.Count -eq 0) {
                $findings += [PSCustomObject]@{
                    Issue               = 'No GPO configures LM hash storage policy'
                    RegistrySetting     = "$registryPath\$registryValue"
                    ExpectedValue       = '1 (Enabled)'
                    Severity            = 'Medium'
                    Risk                = 'LM hash storage policy not enforced via GPO'
                    Impact              = 'Passwords may be stored with weak LM hash'
                    Recommendation      = 'Create GPO to disable LM hash storage'
                }
            }

        } catch {
            Write-Verbose "A-LMHashNotDisabled: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Enable "Do not store LAN Manager hash value on next password change" via GPO. Users must change passwords for the setting to take effect.'
        Impact      = 'Low - Only affects new passwords. Very old systems (pre-Vista) may have compatibility issues.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# LM Hash Storage Remediation
#
# Issues found:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): $($_.Risk)" } | Out-String)

# LM (LAN Manager) hashes are:
# - Split into two 7-character chunks
# - Uppercase only
# - No salt
# - DES-based
# Result: Crackable in seconds with modern tools

# STEP 1: Create or edit GPO
`$gpoName = "Security-NoLMHash"

# Check if GPO exists
`$gpo = Get-GPO -Name `$gpoName -ErrorAction SilentlyContinue
if (-not `$gpo) {
    `$gpo = New-GPO -Name `$gpoName -Comment "Disable LM hash storage"
    Write-Host "Created GPO: `$gpoName" -ForegroundColor Green
}

# STEP 2: Set the registry value via GPO
# Path: HKLM\SYSTEM\CurrentControlSet\Control\Lsa
# Value: NoLMHash = 1 (REG_DWORD)

Set-GPRegistryValue -Name `$gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "NoLMHash" -Type DWord -Value 1

Write-Host "Configured NoLMHash=1" -ForegroundColor Green

# STEP 3: Link GPO to Domain Controllers and domain root
`$dcOU = "OU=Domain Controllers," + (Get-ADDomain).DistinguishedName
`$domainDN = (Get-ADDomain).DistinguishedName

New-GPLink -Name `$gpoName -Target `$dcOU -ErrorAction SilentlyContinue
New-GPLink -Name `$gpoName -Target `$domainDN -ErrorAction SilentlyContinue

Write-Host "Linked GPO to Domain Controllers and domain root" -ForegroundColor Green

# STEP 4: Also set via security policy (belt and suspenders)
# In GPMC, navigate to:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# "Network security: Do not store LAN Manager hash value on next password change" = Enabled

# STEP 5: Force GP update
gpupdate /force

# STEP 6: Verify the setting on DCs
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    `$value = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue).NoLMHash
    }
    if (`$value -eq 1) {
        Write-Host "`$(`$dc.Name): NoLMHash = 1 (OK)" -ForegroundColor Green
    } else {
        Write-Host "`$(`$dc.Name): NoLMHash = `$value (NEEDS ATTENTION)" -ForegroundColor Yellow
    }
}

# STEP 7: Force password changes to clear existing LM hashes
# All users should change passwords for this to take effect
# For privileged accounts, consider forced reset:
#
# Get-ADUser -Filter {AdminCount -eq 1} | ForEach-Object {
#     Set-ADUser -Identity `$_ -ChangePasswordAtLogon `$true
# }

# STEP 8: Verify no LM hashes exist
# Export and check the ntds.dit (requires DC reboot or shadow copy)
# Or use mimikatz/DSInternals to check (in authorized testing only)

Write-Host @"

IMPORTANT: Existing LM hashes remain until users change passwords.
Consider:
1. Forcing password changes for all users
2. Setting minimum password age to 0 temporarily
3. Enabling fine-grained password policies

"@ -ForegroundColor Yellow

"@
            return $commands
        }
    }
}
