<#
.SYNOPSIS
    Detects computers running unsupported or end-of-life operating systems.

.DESCRIPTION
    Unsupported operating systems no longer receive security updates, making them
    vulnerable to known exploits and a risk to the entire environment.

.NOTES
    Rule ID    : S-OS-Unsupported
    Category   : StaleObjects
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'S-OS-Unsupported'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Unsupported Operating Systems'
    Description = 'Identifies computers running end-of-life operating systems that no longer receive security updates, including Windows 7, Server 2008, Server 2012, and older.'
    Severity    = 'Critical'
    Weight      = 60
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Windows Lifecycle Fact Sheet'; Url = 'https://learn.microsoft.com/en-us/lifecycle/products/' }
        @{ Title = 'Windows Server End of Support'; Url = 'https://docs.microsoft.com/en-us/windows-server/get-started/windows-server-release-info' }
        @{ Title = 'EternalBlue and Legacy Systems'; Url = 'https://www.cisa.gov/news-events/cybersecurity-advisories' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1190', 'T1210')   # Exploit Public-Facing Application, Exploitation of Remote Services
    }

    CIS   = @('2.1')
    STIG  = @('V-73229')
    ANSSI = @('R44')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Define unsupported OS patterns and their EOL dates
        $unsupportedOS = @{
            # Desktop OS
            'Windows 2000'       = @{ EOL = '2010-07-13'; Severity = 'Critical'; CVEs = 'MS08-067, MS17-010, and hundreds more' }
            'Windows XP'         = @{ EOL = '2014-04-08'; Severity = 'Critical'; CVEs = 'MS08-067, MS17-010, and hundreds more' }
            'Windows Vista'      = @{ EOL = '2017-04-11'; Severity = 'Critical'; CVEs = 'MS17-010, numerous unpatched' }
            'Windows 7'          = @{ EOL = '2020-01-14'; Severity = 'High'; CVEs = 'MS17-010, PrintNightmare (if unpatched), many others' }
            'Windows 8 '         = @{ EOL = '2016-01-12'; Severity = 'Critical'; CVEs = 'Multiple critical unpatched' }  # Space to distinguish from 8.1
            'Windows 8.1'        = @{ EOL = '2023-01-10'; Severity = 'High'; CVEs = 'No longer receiving updates' }

            # Server OS
            'Windows 2000 Server' = @{ EOL = '2010-07-13'; Severity = 'Critical'; CVEs = 'MS08-067, countless critical' }
            'Server 2003'        = @{ EOL = '2015-07-14'; Severity = 'Critical'; CVEs = 'MS17-010, MS08-067, hundreds' }
            'Server 2008'        = @{ EOL = '2020-01-14'; Severity = 'High'; CVEs = 'MS17-010, PrintNightmare, Zerologon' }
            'Server 2008 R2'     = @{ EOL = '2020-01-14'; Severity = 'High'; CVEs = 'MS17-010, PrintNightmare, Zerologon' }
            'Server 2012'        = @{ EOL = '2023-10-10'; Severity = 'High'; CVEs = 'No longer receiving updates' }
            'Server 2012 R2'     = @{ EOL = '2023-10-10'; Severity = 'High'; CVEs = 'No longer receiving updates' }
        }

        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                $os = $computer.OperatingSystem
                if (-not $os) { continue }

                # Skip if not enabled (stale computer check handles these)
                if ($computer.Enabled -eq $false) { continue }

                foreach ($pattern in $unsupportedOS.Keys) {
                    if ($os -like "*$pattern*") {
                        $eolInfo = $unsupportedOS[$pattern]

                        # Determine if this is a DC (extra critical)
                        $isDC = $computer.PrimaryGroupID -eq 516 -or
                                $computer.DistinguishedName -match 'Domain Controllers'

                        $severity = $eolInfo.Severity
                        if ($isDC -and $severity -eq 'High') { $severity = 'Critical' }

                        $findings += [PSCustomObject]@{
                            ComputerName        = $computer.Name
                            OperatingSystem     = $os
                            OSVersion           = $computer.OperatingSystemVersion
                            EndOfLifeDate       = $eolInfo.EOL
                            DaysSinceEOL        = ((Get-Date) - [DateTime]$eolInfo.EOL).Days
                            IsDomainController  = $isDC
                            KnownVulnerabilities = $eolInfo.CVEs
                            RiskLevel           = $severity
                            Enabled             = $computer.Enabled
                            LastLogonDate       = $computer.LastLogonDate
                            DistinguishedName   = $computer.DistinguishedName
                        }
                        break  # Found match, no need to check other patterns
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Upgrade or decommission systems running unsupported operating systems. If immediate upgrade is not possible, isolate these systems.'
        Impact      = 'High - Requires system upgrades or replacements. Plan migration carefully.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Unsupported Operating System Remediation
#############################################################################
#
# Systems running unsupported operating systems:
# - Do NOT receive security patches
# - Contain known, exploitable vulnerabilities
# - Are frequently targeted by ransomware and APTs
# - May not support modern security features
#
# These systems pose significant risk to the entire environment.
#
#############################################################################

# Affected Systems by Severity:

## CRITICAL - Immediate Action Required:
$($Finding.Findings | Where-Object { $_.RiskLevel -eq 'Critical' } | ForEach-Object { "# - $($_.ComputerName): $($_.OperatingSystem) (EOL: $($_.EndOfLifeDate))" } | Out-String)

## HIGH - Plan Upgrade/Retirement:
$($Finding.Findings | Where-Object { $_.RiskLevel -eq 'High' } | ForEach-Object { "# - $($_.ComputerName): $($_.OperatingSystem) (EOL: $($_.EndOfLifeDate))" } | Out-String)

#############################################################################
# Immediate Mitigation Steps (If Upgrade Not Immediately Possible)
#############################################################################

# 1. Network Isolation
#    - Move to separate VLAN
#    - Apply strict firewall rules
#    - Block SMB (445), RDP (3389) from untrusted sources

# 2. Enhanced Monitoring
#    - Deploy EDR/AV with behavioral detection
#    - Forward all security logs to SIEM
#    - Create alerts for unusual activity

# 3. Access Restrictions
#    - Remove from domain if possible
#    - Use local accounts only
#    - Disable unnecessary services

# 4. Application Compatibility
#    - Document applications requiring legacy OS
#    - Identify upgrade path for each application
#    - Consider application virtualization

#############################################################################
# Upgrade Planning
#############################################################################

# For Windows Server 2008/2012:
# -> Upgrade to Windows Server 2019 or 2022
# -> In-place upgrade may be possible for 2012 R2 -> 2019

# For Windows 7/8.1:
# -> Deploy Windows 10 (21H2 LTSC for long-term) or Windows 11
# -> Use USMT for user data migration

# Check upgrade paths:
# https://docs.microsoft.com/en-us/windows-server/get-started/supported-upgrade-paths

#############################################################################
# Disable or Remove From Domain
#############################################################################

# Option 1: Disable the computer account
# Get-ADComputer -Identity 'OLDSERVER01' | Disable-ADAccount

# Option 2: Move to isolated OU with restrictive GPOs
# Move-ADObject -Identity 'CN=OLDSERVER01,OU=Computers,DC=domain,DC=com' `
#     -TargetPath 'OU=Legacy,OU=Quarantine,DC=domain,DC=com'

# Option 3: Remove from domain entirely (for non-essential systems)
# Note: This must be done from the system itself
# Remove-Computer -UnjoinDomaincredential domain\admin -Force

#############################################################################
# Extended Security Updates (ESU) - Temporary Solution
#############################################################################

# Microsoft offers paid ESU for:
# - Windows Server 2008/2008 R2 (until 2023)
# - Windows Server 2012/2012 R2 (until 2026)
# - Windows 7 (until 2023)

# ESU provides critical security updates only
# This is a bridge solution, not a permanent fix

# Azure-hosted VMs receive free ESU

#############################################################################
# Verification
#############################################################################

# List all computers by OS version:
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate |
    Group-Object OperatingSystem |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table

# Export detailed inventory:
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, IPv4Address |
    Export-Csv -Path "AD_Computer_Inventory_`$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

"@
            return $commands
        }
    }
}
