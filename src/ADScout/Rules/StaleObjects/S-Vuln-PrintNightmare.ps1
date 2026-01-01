<#
.SYNOPSIS
    Detects systems vulnerable to PrintNightmare (CVE-2021-34527/CVE-2021-1675).

.DESCRIPTION
    PrintNightmare exploits the Windows Print Spooler service to achieve remote code
    execution and privilege escalation. Domain Controllers are especially high-value
    targets. This rule checks for vulnerable configurations.

.NOTES
    Rule ID    : S-Vuln-PrintNightmare
    Category   : StaleObjects
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'S-Vuln-PrintNightmare'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'PrintNightmare Vulnerability (CVE-2021-34527)'
    Description = 'Identifies domain controllers and servers vulnerable to PrintNightmare, a critical RCE/LPE vulnerability in the Windows Print Spooler service.'
    Severity    = 'Critical'
    Weight      = 85
    DataSource  = 'DomainControllers,Computers'

    References  = @(
        @{ Title = 'CVE-2021-34527'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527' }
        @{ Title = 'CVE-2021-1675'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675' }
        @{ Title = 'PrintNightmare Guidance'; Url = 'https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1068', 'T1210')    # Exploitation for Privilege Escalation, Exploitation of Remote Services
    }

    CIS   = @('18.9.52.1')
    STIG  = @('V-254447')
    ANSSI = @('vuln1_printnightmare')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check Domain Controllers first (highest priority)
        $systemsToCheck = @()
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $systemsToCheck += @{
                    Name = if ($dc.Name) { $dc.Name } else { $dc.DnsHostName }
                    Type = 'DomainController'
                    DN = $dc.DistinguishedName
                }
            }
        }

        foreach ($system in $systemsToCheck) {
            if (-not $system.Name) { continue }

            try {
                $vulnStatus = Invoke-Command -ComputerName $system.Name -ScriptBlock {
                    $result = @{
                        ComputerName = $env:COMPUTERNAME
                        SpoolerRunning = $false
                        SpoolerStartType = $null
                        PointAndPrintRestricted = $false
                        NoWarningNoElevation = $false
                        PackagePointAndPrintOnly = $false
                        RestrictDriverInstall = $false
                        Patched = $false
                    }

                    # Check Print Spooler service
                    $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
                    if ($spooler) {
                        $result.SpoolerRunning = $spooler.Status -eq 'Running'
                        $result.SpoolerStartType = $spooler.StartType.ToString()
                    }

                    # Check Point and Print restrictions (GPO settings)
                    $ppPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'

                    # NoWarningNoElevationOnInstall - should be 0 (require elevation)
                    $noWarn = Get-ItemProperty -Path $ppPath -Name 'NoWarningNoElevationOnInstall' -ErrorAction SilentlyContinue
                    $result.NoWarningNoElevation = $noWarn.NoWarningNoElevationOnInstall -eq 1

                    # UpdatePromptSettings - should be 0 (show warning and elevation)
                    $updatePrompt = Get-ItemProperty -Path $ppPath -Name 'UpdatePromptSettings' -ErrorAction SilentlyContinue

                    # RestrictDriverInstallationToAdministrators - should be 1
                    $restrictPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
                    $restrict = Get-ItemProperty -Path $restrictPath -Name 'RestrictDriverInstallationToAdministrators' -ErrorAction SilentlyContinue
                    $result.RestrictDriverInstall = $restrict.RestrictDriverInstallationToAdministrators -eq 1

                    # PackagePointAndPrintOnly - should be 1
                    $packagePP = Get-ItemProperty -Path $ppPath -Name 'PackagePointAndPrintOnly' -ErrorAction SilentlyContinue
                    $result.PackagePointAndPrintOnly = $packagePP.PackagePointAndPrintOnly -eq 1

                    # Check for July 2021 or later patches
                    $patches = Get-HotFix | Where-Object {
                        $_.InstalledOn -ge [DateTime]'2021-07-06'
                    }
                    $result.Patched = $patches.Count -gt 0

                    return $result
                } -ErrorAction SilentlyContinue

                $issues = @()
                $isVulnerable = $false

                # Check if Spooler is running
                if ($vulnStatus.SpoolerRunning) {
                    $issues += 'Print Spooler service is RUNNING'

                    # Spooler running + not patched = Critical
                    if (-not $vulnStatus.Patched) {
                        $issues += 'Missing July 2021 security updates'
                        $isVulnerable = $true
                    }

                    # Spooler running + insecure Point and Print = Vulnerable
                    if ($vulnStatus.NoWarningNoElevation) {
                        $issues += 'NoWarningNoElevationOnInstall = 1 (insecure)'
                        $isVulnerable = $true
                    }

                    if (-not $vulnStatus.RestrictDriverInstall) {
                        $issues += 'Driver installation not restricted to admins'
                        $isVulnerable = $true
                    }

                    if (-not $vulnStatus.PackagePointAndPrintOnly) {
                        $issues += 'PackagePointAndPrintOnly not enabled'
                        $isVulnerable = $true
                    }
                }

                # Even if patched, Spooler on DC is a risk
                if ($system.Type -eq 'DomainController' -and $vulnStatus.SpoolerRunning) {
                    $issues += 'Print Spooler should be DISABLED on Domain Controllers'
                    $isVulnerable = $true
                }

                if ($isVulnerable) {
                    $findings += [PSCustomObject]@{
                        ComputerName          = $system.Name
                        SystemType            = $system.Type
                        SpoolerStatus         = if ($vulnStatus.SpoolerRunning) { 'Running' } else { 'Stopped' }
                        SpoolerStartType      = $vulnStatus.SpoolerStartType
                        Patched               = $vulnStatus.Patched
                        RestrictDriverInstall = $vulnStatus.RestrictDriverInstall
                        Issues                = ($issues -join '; ')
                        CVEs                  = 'CVE-2021-34527, CVE-2021-1675'
                        RiskLevel             = if (-not $vulnStatus.Patched) { 'Critical' } else { 'High' }
                        DistinguishedName     = $system.DN
                    }
                }

            } catch {
                # Report check failure
                $findings += [PSCustomObject]@{
                    ComputerName          = $system.Name
                    SystemType            = $system.Type
                    SpoolerStatus         = 'Unknown (check failed)'
                    SpoolerStartType      = 'Unknown'
                    Patched               = 'Unknown'
                    RestrictDriverInstall = 'Unknown'
                    Issues                = 'Unable to verify PrintNightmare status'
                    CVEs                  = 'CVE-2021-34527, CVE-2021-1675'
                    RiskLevel             = 'High'
                    DistinguishedName     = $system.DN
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable Print Spooler on DCs and apply security updates with Point and Print restrictions.'
        Impact      = 'Medium - Disabling Spooler prevents print functionality, which is rarely needed on DCs.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# PrintNightmare (CVE-2021-34527) Remediation
#############################################################################
#
# PrintNightmare allows remote code execution via the Print Spooler service.
# Attackers can use this to:
# - Execute code as SYSTEM on vulnerable servers
# - Compromise Domain Controllers
# - Move laterally across the network
#
# Vulnerable systems:
$($Finding.Findings | ForEach-Object { "# - $($_.ComputerName) ($($_.SystemType)): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Disable Print Spooler on Domain Controllers (CRITICAL)
#############################################################################

# Domain Controllers should NEVER run the Print Spooler service
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Stop-Service -Name 'Spooler' -Force -ErrorAction SilentlyContinue
        Set-Service -Name 'Spooler' -StartupType Disabled

        Write-Host "Disabled Print Spooler on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 2: Install Security Updates
#############################################################################

# Ensure July 2021 (or later) security updates are installed:
# - KB5004945 (Windows Server 2019)
# - KB5004947 (Windows Server 2016)
# - KB5004954 (Windows Server 2012 R2)
# - KB5004946 (Windows Server 2022)

# Verify patches:
foreach (`$dc in `$dcs) {
    `$patches = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Get-HotFix | Where-Object { `$_.InstalledOn -ge '2021-07-06' } |
            Select-Object HotFixID, InstalledOn
    }
    Write-Host "`$(`$dc.HostName):" -ForegroundColor Cyan
    `$patches
}

#############################################################################
# Step 3: Configure Point and Print Restrictions via GPO
#############################################################################

# Create a GPO for print security settings:
# Computer Configuration -> Administrative Templates -> Printers

# 1. "Point and Print Restrictions"
#    - Enabled
#    - "Users can only point and print to these servers": (list trusted print servers)
#    - "When installing drivers for a new connection": Show warning and elevation prompt
#    - "When updating drivers for an existing connection": Show warning and elevation prompt

# 2. "Limits print driver installation to Administrators"
#    - Enabled

# 3. "Only use Package Point and Print"
#    - Enabled

# Registry settings (apply via GPO or directly):
`$registrySettings = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' = @{
        'RestrictDriverInstallationToAdministrators' = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' = @{
        'Restricted' = 1
        'NoWarningNoElevationOnInstall' = 0
        'UpdatePromptSettings' = 0
        'PackagePointAndPrintOnly' = 1
    }
}

foreach (`$path in `$registrySettings.Keys) {
    if (-not (Test-Path `$path)) {
        New-Item -Path `$path -Force | Out-Null
    }
    foreach (`$name in `$registrySettings[`$path].Keys) {
        Set-ItemProperty -Path `$path -Name `$name -Value `$registrySettings[`$path][`$name] -Type DWord
    }
}

#############################################################################
# Step 4: Verify Remediation
#############################################################################

# Check all DCs:
foreach (`$dc in `$dcs) {
    `$status = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        @{
            ComputerName = `$env:COMPUTERNAME
            SpoolerStatus = `$spooler.Status
            SpoolerStartType = `$spooler.StartType
            Secure = (`$spooler.Status -ne 'Running' -and `$spooler.StartType -eq 'Disabled')
        }
    }

    `$color = if (`$status.Secure) { 'Green' } else { 'Red' }
    Write-Host "`$(`$status.ComputerName): Spooler=`$(`$status.SpoolerStatus), StartType=`$(`$status.SpoolerStartType)" -ForegroundColor `$color
}

#############################################################################
# Additional Hardening
#############################################################################

# For servers that MUST run Print Spooler:
# 1. Use Windows Defender Credential Guard
# 2. Block inbound RPC traffic from untrusted networks
# 3. Monitor for suspicious driver installations
# 4. Use printer isolation/sandboxing if available

# Firewall rule to block Spooler RPC (if spooler must be enabled):
# New-NetFirewallRule -DisplayName "Block Print Spooler RPC" `
#     -Direction Inbound -Protocol TCP -LocalPort 445 `
#     -RemoteAddress "0.0.0.0/0" -Action Block

"@
            return $commands
        }
    }
}
