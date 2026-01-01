@{
    Id          = 'S-PatchCompliance'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Systems Missing Critical Security Patches'
    Description = 'Domain computers have not been updated recently and may be missing critical security patches. Unpatched systems are vulnerable to known exploits and represent significant security risks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'NIST SI-2 Flaw Remediation'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'Windows Update'; Url = 'https://learn.microsoft.com/en-us/windows/deployment/update/' }
        @{ Title = 'CISA Known Exploited Vulnerabilities'; Url = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0004')  # Initial Access, Privilege Escalation
        Techniques = @('T1190', 'T1068')    # Exploit Public-Facing Application, Exploitation for Privilege Escalation
    }

    CIS   = @('7.1', '7.2')
    STIG  = @('V-63335', 'V-63339')
    ANSSI = @('vuln1_patch')
    NIST  = @('SI-2', 'SI-2(2)', 'SI-2(3)')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $criticalPatchAgeDays = 30   # Critical if no updates in 30 days
        $warningPatchAgeDays = 14    # Warning if no updates in 14 days

        foreach ($computer in $Data) {
            # Skip disabled computers
            if (-not $computer.Enabled) { continue }

            # Skip if no last logon (computer may not be in use)
            if (-not $computer.LastLogonDate) { continue }

            # Check if recently active (within 30 days)
            $daysSinceLogon = ((Get-Date) - $computer.LastLogonDate).Days
            if ($daysSinceLogon -gt 30) { continue }

            $patchIssues = @()
            $lastPatchDate = $null
            $daysSincePatch = $null

            # Try to determine last patch date
            # Option 1: Check OperatingSystemVersion (build number indicates patch level)
            # Option 2: Check WMI/CIM for last update time (requires connectivity)

            if ($computer.Name -eq $env:COMPUTERNAME) {
                try {
                    # Local machine - check Windows Update history
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $searcher = $session.CreateUpdateSearcher()
                    $historyCount = $searcher.GetTotalHistoryCount()

                    if ($historyCount -gt 0) {
                        $history = $searcher.QueryHistory(0, 1)
                        if ($history.Count -gt 0) {
                            $lastPatchDate = $history.Item(0).Date
                            $daysSincePatch = ((Get-Date) - $lastPatchDate).Days
                        }
                    }
                } catch {
                    # Unable to check update history
                }
            }

            # If we couldn't get specific patch info, use heuristics
            if (-not $lastPatchDate) {
                # Check OS version/build - very old builds indicate missing patches
                $osVersion = $computer.OperatingSystemVersion

                # Flag servers that are likely unpatched based on OS version patterns
                if ($computer.OperatingSystem -match 'Server') {
                    # Check if DC (more critical)
                    $isDC = $computer.DistinguishedName -match 'Domain Controllers'

                    # Estimate based on build/version if available
                    if ($osVersion) {
                        # Build numbers below certain thresholds indicate old patches
                        # This is a heuristic - actual patch verification requires direct access
                        $patchIssues += [PSCustomObject]@{
                            Issue           = 'Patch status requires verification'
                            CurrentBuild    = $osVersion
                            Recommendation  = 'Verify Windows Update status'
                        }
                    }
                }
            }

            # If we have specific patch age information
            if ($daysSincePatch -ne $null) {
                $riskLevel = 'Low'
                if ($daysSincePatch -gt $criticalPatchAgeDays) {
                    $riskLevel = 'Critical'
                    $patchIssues += [PSCustomObject]@{
                        Issue           = "No updates in $daysSincePatch days"
                        LastPatchDate   = $lastPatchDate.ToString('yyyy-MM-dd')
                        Recommendation  = 'Apply security updates immediately'
                    }
                } elseif ($daysSincePatch -gt $warningPatchAgeDays) {
                    $riskLevel = 'High'
                    $patchIssues += [PSCustomObject]@{
                        Issue           = "Updates $daysSincePatch days old"
                        LastPatchDate   = $lastPatchDate.ToString('yyyy-MM-dd')
                        Recommendation  = 'Review and apply pending updates'
                    }
                }
            }

            # Additional check: OS end of support
            $eolOS = @(
                'Windows Server 2008',
                'Windows Server 2003',
                'Windows Server 2012',   # Extended support ended
                'Windows 7',
                'Windows XP',
                'Windows Vista'
            )

            foreach ($eol in $eolOS) {
                if ($computer.OperatingSystem -match [regex]::Escape($eol)) {
                    $patchIssues += [PSCustomObject]@{
                        Issue           = 'End-of-Life Operating System'
                        CurrentOS       = $computer.OperatingSystem
                        Recommendation  = 'Upgrade to supported OS version'
                    }
                    break
                }
            }

            if ($patchIssues.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    ComputerName        = $computer.Name
                    OperatingSystem     = $computer.OperatingSystem
                    OSVersion           = $computer.OperatingSystemVersion
                    LastLogon           = $computer.LastLogonDate
                    DaysSincePatch      = $daysSincePatch
                    PatchIssues         = $patchIssues
                    IsDomainController  = $computer.DistinguishedName -match 'Domain Controllers'
                    RiskLevel           = if ($patchIssues | Where-Object { $_.Issue -match 'End-of-Life' }) { 'Critical' }
                                         elseif ($daysSincePatch -gt $criticalPatchAgeDays) { 'Critical' }
                                         else { 'High' }
                    NISTControl         = 'SI-2 Flaw Remediation'
                    AttackVector        = 'Known vulnerabilities, public exploits, ransomware'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Implement a comprehensive patch management program to ensure all systems receive security updates within defined timeframes.'
        Impact      = 'Medium - Patches may require reboots and could affect application compatibility.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Patch Management Remediation
# Systems requiring attention: $($Finding.Findings.Count)

# NIST SI-2 Requirements:
# - Identify and remediate system flaws
# - Install security patches within defined timeframe
# - Test patches before production deployment
# - Centrally manage patch status

# === IMMEDIATE ACTIONS ===

# 1. Check Windows Update status on affected systems:
$($Finding.Findings | ForEach-Object { "# - $($_.ComputerName) ($($_.OperatingSystem))" } | Out-String)

# Trigger Windows Update scan:
`$updateSession = New-Object -ComObject Microsoft.Update.Session
`$updateSearcher = `$updateSession.CreateUpdateSearcher()
`$searchResult = `$updateSearcher.Search("IsInstalled=0 and Type='Software'")

Write-Host "Pending updates: `$(`$searchResult.Updates.Count)"
foreach (`$update in `$searchResult.Updates) {
    Write-Host "  - `$(`$update.Title)"
}

# === INSTALL UPDATES ===
# Via PowerShell (Windows 10/Server 2016+):
Install-WindowsUpdate -AcceptAll -AutoReboot

# Via Windows Update command line:
# wuauclt /detectnow /updatenow

# Via PowerShell module:
Install-Module -Name PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll

# === WSUS/SCCM VERIFICATION ===
# If using WSUS, check client registration:
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' |
    Select-Object WUServer, WUStatusServer

# Force WSUS check:
wuauclt /reportnow /detectnow

# === CRITICAL: END-OF-LIFE SYSTEMS ===
# Systems on unsupported OS versions require immediate upgrade:
# - Windows Server 2008/2008 R2: Upgrade to 2019 or 2022
# - Windows Server 2012/2012 R2: Upgrade to 2019 or 2022
# - Windows 7: Upgrade to Windows 10/11
# - Isolate EOL systems that cannot be upgraded

# === AUTOMATED PATCH MANAGEMENT ===
# 1. Configure WSUS or SCCM for centralized management
# 2. Create patch deployment rings (test > pilot > production)
# 3. Set maintenance windows for automatic installation
# 4. Configure GPO for Windows Update settings:

# GPO Path: Computer Configuration > Administrative Templates
# > Windows Components > Windows Update
# - Configure Automatic Updates: Enabled
# - Schedule install day/time
# - Allow immediate installation of definition updates

# === MONITORING ===
# Create report of patch compliance:
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion |
    Select-Object Name, OperatingSystem, OperatingSystemVersion |
    Export-Csv -Path C:\PatchCompliance.csv -NoTypeInformation

"@
            return $commands
        }
    }
}
