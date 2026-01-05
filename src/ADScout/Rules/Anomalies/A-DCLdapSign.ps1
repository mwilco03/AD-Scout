@{
    Id          = 'A-DCLdapSign'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LDAP Signing Not Required on Domain Controllers'
    Description = 'LDAP signing is not enforced on Domain Controllers, allowing LDAP relay attacks. Checks both DC registry configuration AND GPO enforcement to ensure consistent domain-wide protection.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'DomainControllers,GPOs'

    References  = @(
        @{ Title = 'LDAP Signing Requirements'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server' }
        @{ Title = 'CVE-2017-8563 LDAP Relay'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-8563' }
        @{ Title = 'LDAP Channel Binding and Signing'; Url = 'https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001')          # LLMNR/NBT-NS Poisoning and SMB Relay
    }

    CIS   = @('5.2')
    STIG  = @('V-63581')
    ANSSI = @('vuln1_ldap_signing')
    NIST  = @('AC-17(2)', 'CM-2', 'CM-6', 'SC-8(1)', 'SC-23')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $dcs = if ($Data.DomainControllers) { $Data.DomainControllers } else { $Data }

        # ========================================================================
        # BELT: Check GPO enforcement for LDAP signing
        # ========================================================================
        $gpoEnforcesLdapSigning = $false

        if ($Data.GPOs) {
            foreach ($gpo in $Data.GPOs) {
                try {
                    # Check if GPO contains LDAP signing policy
                    # This is in: Computer Configuration > Policies > Windows Settings > Security Settings
                    #             > Local Policies > Security Options
                    # "Domain controller: LDAP server signing requirements"
                    $gpoPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                    if (Test-Path $gpoPath -ErrorAction SilentlyContinue) {
                        $content = Get-Content $gpoPath -Raw -ErrorAction SilentlyContinue
                        # LDAPServerIntegrity = 2 means Require signing
                        if ($content -match 'LDAPServerIntegrity\s*=\s*2') {
                            $gpoEnforcesLdapSigning = $true
                            break
                        }
                    }
                } catch {
                    Write-Verbose "A-DCLdapSign: Could not check GPO $($gpo.DisplayName): $_"
                }
            }
        }

        if (-not $gpoEnforcesLdapSigning) {
            $findings += [PSCustomObject]@{
                ObjectType           = 'GPO Policy'
                DomainController     = 'Domain-wide'
                OperatingSystem      = 'N/A'
                LDAPServerIntegrity  = 'Not Enforced'
                SigningStatus        = 'No GPO requires LDAP signing'
                RiskLevel            = 'High'
                AttackVector         = 'DC configurations may drift - no policy enforcement'
                ConfigSource         = 'Missing GPO'
            }
        }

        # ========================================================================
        # SUSPENDERS: Check each Domain Controller's actual configuration
        # ========================================================================
        foreach ($dc in $dcs) {
            $ldapSigningStatus = 'Unknown'
            $registryValue = $null

            try {
                # Try to query the registry value on the DC
                # LDAPServerIntegrity: 0 = None, 1 = Negotiate Signing, 2 = Require Signing
                $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"

                # For remote check, use Invoke-Command if available
                if ($dc.Name -ne $env:COMPUTERNAME) {
                    # Try WMI/CIM for remote registry access
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.Name)
                        $key = $reg.OpenSubKey('System\CurrentControlSet\Services\NTDS\Parameters')
                        if ($key) {
                            $registryValue = $key.GetValue('LDAPServerIntegrity')
                            $key.Close()
                        }
                        $reg.Close()
                    } catch {
                        # Remote registry access failed
                        $registryValue = $null
                    }
                } else {
                    # Local check
                    $registryValue = Get-ItemProperty -Path $regPath -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue |
                                     Select-Object -ExpandProperty LDAPServerIntegrity
                }

                # Interpret the value
                $ldapSigningStatus = switch ($registryValue) {
                    0 { 'None (Vulnerable)' }
                    1 { 'Negotiate Signing' }
                    2 { 'Require Signing (Secure)' }
                    default { 'Not Configured (Default: Negotiate)' }
                }

                # Flag if not requiring signing (0, 1, or not configured)
                if ($registryValue -ne 2) {
                    $findings += [PSCustomObject]@{
                        ObjectType           = 'DC Configuration'
                        DomainController     = $dc.Name
                        OperatingSystem      = $dc.OperatingSystem
                        LDAPServerIntegrity  = $registryValue
                        SigningStatus        = $ldapSigningStatus
                        RiskLevel            = if ($registryValue -eq 0) { 'Critical' } else { 'High' }
                        AttackVector         = 'LDAP Relay attacks, credential interception'
                        ConfigSource         = 'Registry'
                    }
                }
            } catch {
                # Unable to check - flag for manual review
                $findings += [PSCustomObject]@{
                    ObjectType           = 'DC Configuration'
                    DomainController     = $dc.Name
                    OperatingSystem      = $dc.OperatingSystem
                    LDAPServerIntegrity  = 'Unable to determine'
                    SigningStatus        = 'Requires manual verification'
                    RiskLevel            = 'Unknown'
                    AttackVector         = 'LDAP Relay attacks if not properly configured'
                    ConfigSource         = 'Unknown'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure Domain Controllers to require LDAP signing via Group Policy or registry settings.'
        Impact      = 'Medium - Clients not configured for LDAP signing may experience connectivity issues. Test thoroughly before enforcing.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Configure LDAP Signing Requirements on Domain Controllers
# Affected DCs: $($Finding.Findings.DomainController -join ', ')

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Local Policies > Security Options
# "Domain controller: LDAP server signing requirements" = "Require signing"

# Option 2: Configure via Registry (per DC)
# Set LDAPServerIntegrity to 2 (Require Signing)

foreach (`$dc in @('$($Finding.Findings.DomainController -join "','")')) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' `
            -Name 'LDAPServerIntegrity' -Value 2 -Type DWord
        Write-Host "LDAP signing requirement configured on `$env:COMPUTERNAME"
    }
}

# Also configure clients to negotiate LDAP signing:
# HKLM:\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity = 1 (Negotiate) or 2 (Require)

# Verify the change:
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'

# Test LDAP connectivity after changes:
# ldp.exe -> Connect -> check "SSL" or test with signing-aware client

"@
            return $commands
        }
    }
}
