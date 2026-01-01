@{
    Id          = 'A-HardenedPaths'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Hardened UNC Paths Not Configured'
    Description = 'Detects when Hardened UNC Paths are not configured for SYSVOL and NETLOGON shares. Without this configuration, attackers can perform man-in-the-middle attacks to modify Group Policy or logon scripts in transit.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'MS15-011 / MS15-014'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-011' }
        @{ Title = 'Hardened UNC Paths'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/yournetwork/use-hardened-unc-paths' }
        @{ Title = 'PingCastle Rule A-HardenedPaths'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0040')  # Credential Access, Impact
        Techniques = @('T1557.001', 'T1187')  # LLMNR/NBT-NS Poisoning, Forced Authentication
    }

    CIS   = @('18.6.14.1')
    STIG  = @('V-63577')
    ANSSI = @('vuln2_hardened_unc')
    NIST  = @('SC-8', 'SC-23')

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

        $hardenedPathsConfigured = $false
        $partialConfiguration = $false

        try {
            # Check GPOs for hardened path configuration
            foreach ($gpo in $Data.GPOs) {
                # Look for the registry settings in Computer Configuration
                # Path: Computer Configuration\Administrative Templates\Network\Network Provider\Hardened UNC Paths

                if ($gpo.RegistrySettings) {
                    foreach ($regSetting in $gpo.RegistrySettings) {
                        if ($regSetting.KeyPath -match 'Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') {
                            $hardenedPathsConfigured = $true

                            # Check if SYSVOL and NETLOGON are properly configured
                            foreach ($req in $requiredPaths) {
                                $pathPattern = $req.Path -replace '\\\*', '.*'
                                $found = $gpo.RegistrySettings | Where-Object {
                                    $_.ValueName -match $pathPattern
                                }

                                if (-not $found) {
                                    $partialConfiguration = $true
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
                        $hardenedPathsConfigured = $true
                    }
                }
            }

            # If not found via GPO data, check registry directly on DCs (if available)
            if (-not $hardenedPathsConfigured) {
                # This would require remote registry access
                # For now, report as not configured if not found in GPO data

                $findings += [PSCustomObject]@{
                    Setting             = 'Hardened UNC Paths'
                    Status              = 'Not Configured'
                    RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                    RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                    Severity            = 'High'
                    Risk                = 'SMB relay attacks can modify Group Policy in transit'
                    Impact              = 'Attacker can inject malicious settings into GPO during download'
                    CVE                 = 'MS15-011, MS15-014'
                }
            } elseif ($partialConfiguration) {
                $findings += [PSCustomObject]@{
                    Setting             = 'Hardened UNC Paths'
                    Status              = 'Partially Configured'
                    RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                    RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                    Severity            = 'Medium'
                    Risk                = 'Some UNC paths may not be protected'
                    Impact              = 'Incomplete protection against SMB relay'
                }
            }

        } catch {
            Write-Verbose "A-HardenedPaths: Error checking GPO configuration - $_"
        }

        # If we couldn't determine configuration, report as unknown
        if ($findings.Count -eq 0 -and -not $hardenedPathsConfigured) {
            $findings += [PSCustomObject]@{
                Setting             = 'Hardened UNC Paths'
                Status              = 'Not Detected in GPO'
                RequiredPaths       = '\\*\SYSVOL, \\*\NETLOGON'
                RequiredSettings    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                Severity            = 'High'
                Risk                = 'Configuration not found - manual verification required'
                Impact              = 'SMB relay attacks may be possible against SYSVOL/NETLOGON'
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
