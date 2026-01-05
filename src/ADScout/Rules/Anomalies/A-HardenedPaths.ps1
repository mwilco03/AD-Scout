@{
    Id          = 'A-HardenedPaths'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Hardened UNC Paths Not Configured'
    Description = 'Detects when Hardened UNC Paths are not configured for SYSVOL and NETLOGON shares. Checks both GPO enforcement AND DC registry settings. Without this configuration, attackers can perform man-in-the-middle attacks to modify Group Policy or logon scripts in transit.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs,DomainControllers'

    References  = @(
        @{ Title = 'MS15-011 / MS15-014'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-011' }
        @{ Title = 'Hardened UNC Paths'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/yournetwork/use-hardened-unc-paths' }
        @{ Title = 'PingCastle Rule A-HardenedPaths'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0040')  # Credential Access, Impact
        Techniques = @('T1557.001', 'T1187')  # LLMNR/NBT-NS Poisoning, Forced Authentication
    }

    CIS   = @()  # Hardened UNC Paths covered in OS-specific CIS benchmarks
    STIG  = @()  # UNC path hardening STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('SC-8', 'SC-23')  # Transmission Confidentiality, Session Authenticity

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Required hardened paths
        $requiredPaths = @(
            @{
                Path = '\\*\SYSVOL'
                RequireMutualAuthentication = 1
                RequireIntegrity = 1
                RequirePrivacy = 0  # Optional but recommended
            }
            @{
                Path = '\\*\NETLOGON'
                RequireMutualAuthentication = 1
                RequireIntegrity = 1
                RequirePrivacy = 0
            }
        )

        # ========================================================================
        # BELT: Check GPO enforcement for Hardened UNC Paths
        # ========================================================================
        $gpoEnforcesHardenedPaths = $false
        $gpoPartialConfiguration = $false

        try {
            # Check GPOs for hardened path configuration
            foreach ($gpo in $Data.GPOs) {
                # Look for the registry settings in Computer Configuration
                # Path: Computer Configuration\Administrative Templates\Network\Network Provider\Hardened UNC Paths

                if ($gpo.RegistrySettings) {
                    foreach ($regSetting in $gpo.RegistrySettings) {
                        if ($regSetting.KeyPath -match 'Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') {
                            $gpoEnforcesHardenedPaths = $true

                            # Check if SYSVOL and NETLOGON are properly configured
                            foreach ($req in $requiredPaths) {
                                $pathPattern = $req.Path -replace '\\\*', '.*'
                                $found = $gpo.RegistrySettings | Where-Object {
                                    $_.ValueName -match $pathPattern
                                }

                                if (-not $found) {
                                    $gpoPartialConfiguration = $true
                                }
                            }
                        }
                    }
                }

                # Also check via GPP registry if available
                if ($gpo.ComputerConfiguration -and $gpo.ComputerConfiguration.Policies) {
                    $networkProvider = $gpo.ComputerConfiguration.Policies |
                        Where-Object { $_.Name -match 'NetworkProvider|HardenedPaths' }

                    if ($networkProvider) {
                        $gpoEnforcesHardenedPaths = $true
                    }
                }
            }

            # Report missing GPO enforcement
            if (-not $gpoEnforcesHardenedPaths) {
                $findings += [PSCustomObject]@{
                    ObjectType          = 'GPO Policy'
                    Setting             = 'Hardened UNC Paths'
                    Source              = 'Domain-wide'
                    Status              = 'No GPO Enforces Hardened Paths'
                    RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                    RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                    Severity            = 'High'
                    Risk                = 'SMB relay attacks can modify Group Policy in transit'
                    Impact              = 'Attacker can inject malicious settings into GPO during download'
                    CVE                 = 'MS15-011, MS15-014'
                    ConfigSource        = 'Missing GPO'
                }
            } elseif ($gpoPartialConfiguration) {
                $findings += [PSCustomObject]@{
                    ObjectType          = 'GPO Policy'
                    Setting             = 'Hardened UNC Paths'
                    Source              = 'Domain-wide'
                    Status              = 'Partially Configured in GPO'
                    RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                    RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                    Severity            = 'Medium'
                    Risk                = 'Some UNC paths may not be protected'
                    Impact              = 'Incomplete protection against SMB relay'
                    ConfigSource        = 'Partial GPO'
                }
            }

        } catch {
            Write-Verbose "A-HardenedPaths: Error checking GPO configuration - $_"
        }

        # ========================================================================
        # SUSPENDERS: Check actual DC registry for Hardened UNC Paths
        # ========================================================================
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $hardenedPathSettings = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            HasHardenedPaths = $false
                            SYSVOLConfigured = $false
                            NETLOGONConfigured = $false
                            SYSVOLValue = $null
                            NETLOGONValue = $null
                        }

                        $hardenedPathsKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'

                        if (Test-Path $hardenedPathsKey) {
                            $result.HasHardenedPaths = $true
                            $values = Get-ItemProperty -Path $hardenedPathsKey -ErrorAction SilentlyContinue

                            # Check SYSVOL
                            $sysvolValue = $values.PSObject.Properties | Where-Object { $_.Name -like '*SYSVOL*' }
                            if ($sysvolValue) {
                                $result.SYSVOLValue = $sysvolValue.Value
                                if ($sysvolValue.Value -match 'RequireMutualAuthentication=1' -and
                                    $sysvolValue.Value -match 'RequireIntegrity=1') {
                                    $result.SYSVOLConfigured = $true
                                }
                            }

                            # Check NETLOGON
                            $netlogonValue = $values.PSObject.Properties | Where-Object { $_.Name -like '*NETLOGON*' }
                            if ($netlogonValue) {
                                $result.NETLOGONValue = $netlogonValue.Value
                                if ($netlogonValue.Value -match 'RequireMutualAuthentication=1' -and
                                    $netlogonValue.Value -match 'RequireIntegrity=1') {
                                    $result.NETLOGONConfigured = $true
                                }
                            }
                        }

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()

                    if (-not $hardenedPathSettings.HasHardenedPaths) {
                        $issues += 'Hardened UNC Paths registry key not present'
                    } else {
                        if (-not $hardenedPathSettings.SYSVOLConfigured) {
                            $issues += "SYSVOL not properly hardened (Value: $($hardenedPathSettings.SYSVOLValue))"
                        }
                        if (-not $hardenedPathSettings.NETLOGONConfigured) {
                            $issues += "NETLOGON not properly hardened (Value: $($hardenedPathSettings.NETLOGONValue))"
                        }
                    }

                    if ($issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = 'DC Configuration'
                            Setting             = 'Hardened UNC Paths'
                            Source              = $dcName
                            Status              = 'Not Properly Configured'
                            RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                            RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                            Severity            = 'High'
                            Risk                = ($issues -join '; ')
                            Impact              = 'SMB relay attacks possible against this DC'
                            CVE                 = 'MS15-011, MS15-014'
                            ConfigSource        = 'Registry'
                            DistinguishedName   = $dc.DistinguishedName
                        }
                    }

                } catch {
                    Write-Verbose "A-HardenedPaths: Could not check DC $dcName - $_"
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure Hardened UNC Paths via Group Policy to require mutual authentication and integrity for SYSVOL and NETLOGON shares.'
        Impact      = 'Low - Improves security without affecting normal operations. May require update on clients (MS15-011).'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Hardened UNC Paths Configuration
#
# Current status: $($Finding.Findings[0].Status)

# This setting protects against MS15-011 / MS15-014 SMB relay attacks
# that can modify Group Policy in transit

# STEP 1: Verify clients have MS15-011 update installed
# Windows 7/8/8.1/2008 R2/2012/2012 R2 need KB3000483
# Windows 10/2016+ include this by default

# STEP 2: Configure via Group Policy
# Path: Computer Configuration > Administrative Templates > Network > Network Provider > Hardened UNC Paths

# STEP 3: Configure SYSVOL
# Setting Name: \\*\SYSVOL
# Value: RequireMutualAuthentication=1, RequireIntegrity=1

# STEP 4: Configure NETLOGON
# Setting Name: \\*\NETLOGON
# Value: RequireMutualAuthentication=1, RequireIntegrity=1

# STEP 5: Apply via registry (alternative to GPO)
# Run on all domain-joined computers:

`$hardenedPathsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

# Create the key if it doesn't exist
if (-not (Test-Path `$hardenedPathsKey)) {
    New-Item -Path `$hardenedPathsKey -Force | Out-Null
}

# Configure SYSVOL
Set-ItemProperty -Path `$hardenedPathsKey -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String

# Configure NETLOGON
Set-ItemProperty -Path `$hardenedPathsKey -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String

Write-Host "Hardened UNC Paths configured successfully"

# STEP 6: Optional - Also require privacy (encryption)
# Set-ItemProperty -Path `$hardenedPathsKey -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" -Type String

# STEP 7: Deploy via GPO (recommended)
# 1. Open Group Policy Management Console
# 2. Edit Default Domain Policy (or create new policy)
# 3. Navigate to: Computer Configuration > Policies > Administrative Templates > Network > Network Provider
# 4. Enable "Hardened UNC Paths"
# 5. Click "Show..." and add:
#    Value name: \\*\SYSVOL
#    Value: RequireMutualAuthentication=1, RequireIntegrity=1
#    Value name: \\*\NETLOGON
#    Value: RequireMutualAuthentication=1, RequireIntegrity=1

# STEP 8: Verify configuration
Get-ItemProperty -Path `$hardenedPathsKey -ErrorAction SilentlyContinue |
    Select-Object -Property *SYSVOL*, *NETLOGON*

# STEP 9: Test GPO download with integrity
# From a workstation:
gpupdate /force
# Should complete without errors

"@
            return $commands
        }
    }
}
