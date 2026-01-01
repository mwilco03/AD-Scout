@{
    Id          = 'S-ObsoleteOS'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Obsolete Operating Systems in Domain'
    Description = 'Computers in the domain are running end-of-life operating systems that no longer receive security updates. These systems are vulnerable to known exploits and may serve as entry points for attackers.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Microsoft Lifecycle Policy'; Url = 'https://learn.microsoft.com/en-us/lifecycle/products/' }
        @{ Title = 'End of Support for Windows'; Url = 'https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info' }
        @{ Title = 'EternalBlue (MS17-010)'; Url = 'https://attack.mitre.org/techniques/T1210/' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1210')  # Exploitation of Remote Services
    }

    CIS   = @('5.1')
    STIG  = @('V-63357')
    ANSSI = @('vuln1_obsolete_os')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 5
        MaxPoints = 100
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Define obsolete OS patterns with their EOL dates and severity
        $obsoleteOS = @{
            'Windows XP'            = @{ EndDate = '2014-04-08'; Severity = 'Critical'; CVEs = 'EternalBlue, BlueKeep variants' }
            'Windows Vista'         = @{ EndDate = '2017-04-11'; Severity = 'Critical'; CVEs = 'Multiple unpatched' }
            'Windows 7'             = @{ EndDate = '2020-01-14'; Severity = 'High'; CVEs = 'BlueKeep, PrintNightmare' }
            'Windows 8'             = @{ EndDate = '2016-01-12'; Severity = 'Critical'; CVEs = 'Multiple unpatched' }
            'Windows 8.1'           = @{ EndDate = '2023-01-10'; Severity = 'High'; CVEs = 'Limited' }
            'Windows Server 2003'   = @{ EndDate = '2015-07-14'; Severity = 'Critical'; CVEs = 'MS17-010, MS08-067' }
            'Windows Server 2008'   = @{ EndDate = '2020-01-14'; Severity = 'Critical'; CVEs = 'BlueKeep, EternalBlue' }
            '2008 R2'               = @{ EndDate = '2020-01-14'; Severity = 'Critical'; CVEs = 'BlueKeep, EternalBlue' }
            'Windows Server 2012 R2' = @{ EndDate = '2023-10-10'; Severity = 'High'; CVEs = 'PrintNightmare, PetitPotam' }
            'Windows Server 2012'   = @{ EndDate = '2023-10-10'; Severity = 'High'; CVEs = 'PrintNightmare, PetitPotam' }
        }

        foreach ($computer in $Data) {
            # Skip disabled computers
            if ($computer.Enabled -eq $false) { continue }

            $os = $computer.OperatingSystem
            if (-not $os) { continue }

            foreach ($pattern in $obsoleteOS.Keys) {
                if ($os -match [regex]::Escape($pattern)) {
                    $osInfo = $obsoleteOS[$pattern]

                    # Check if system has been active recently (last 90 days)
                    $lastLogon = $computer.LastLogonDate
                    $isActive = $lastLogon -gt (Get-Date).AddDays(-90)

                    $findings += [PSCustomObject]@{
                        ComputerName        = $computer.Name
                        OperatingSystem     = $os
                        OperatingSystemVersion = $computer.OperatingSystemVersion
                        EndOfLifeDate       = $osInfo.EndDate
                        Severity            = $osInfo.Severity
                        KnownVulnerabilities = $osInfo.CVEs
                        LastLogon           = $lastLogon
                        IsActive            = $isActive
                        DistinguishedName   = $computer.DistinguishedName
                        RiskLevel           = if ($isActive) { $osInfo.Severity } else { 'Medium' }
                        AttackVector        = 'Unpatched vulnerabilities, remote code execution'
                    }
                    break  # Found a match, no need to check other patterns
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Upgrade or decommission systems running obsolete operating systems. If systems cannot be upgraded immediately, isolate them from the network.'
        Impact      = 'High - Upgrading OS requires planning, testing, and may involve application compatibility work.'
        Script      = {
            param($Finding, $Domain)

            $criticalCount = ($Finding.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            $activeCount = ($Finding.Findings | Where-Object { $_.IsActive }).Count

            $commands = @"
# Obsolete Operating Systems Remediation
# Total Found: $($Finding.Findings.Count)
# Critical Severity: $criticalCount
# Active Systems (logged in last 90 days): $activeCount

# Affected Systems by Severity:

# CRITICAL (Immediate action required):
$($Finding.Findings | Where-Object { $_.Severity -eq 'Critical' } | ForEach-Object { "# - $($_.ComputerName): $($_.OperatingSystem) (EOL: $($_.EndOfLifeDate))" } | Out-String)

# HIGH (Plan remediation):
$($Finding.Findings | Where-Object { $_.Severity -eq 'High' } | ForEach-Object { "# - $($_.ComputerName): $($_.OperatingSystem) (EOL: $($_.EndOfLifeDate))" } | Out-String)

# Immediate Mitigation Options:

# 1. Network Isolation (temporary)
# Place obsolete systems in isolated VLAN with restricted access

# 2. Disable if not needed
`$inactiveOldSystems = Get-ADComputer -Filter 'OperatingSystem -like "*2003*" -or OperatingSystem -like "*2008*" -or OperatingSystem -like "*XP*"' |
    Where-Object { `$_.LastLogonDate -lt (Get-Date).AddDays(-90) }

foreach (`$computer in `$inactiveOldSystems) {
    # Disable inactive obsolete systems
    # Disable-ADAccount -Identity `$computer.DistinguishedName
    Write-Host "Consider disabling: `$(`$computer.Name) - Last logon: `$(`$computer.LastLogonDate)"
}

# 3. Upgrade Planning
# For Windows 7/2008 R2: Upgrade to Windows 10/11 or Server 2019/2022
# For Windows Server 2012: Upgrade to Server 2019 or 2022

# 4. Export detailed report for planning:
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate |
    Where-Object { `$_.OperatingSystem -match '2003|2008|2012|XP|Vista|Windows 7|Windows 8' } |
    Export-Csv -Path "ObsoleteOS_Report.csv" -NoTypeInformation

"@
            return $commands
        }
    }
}
