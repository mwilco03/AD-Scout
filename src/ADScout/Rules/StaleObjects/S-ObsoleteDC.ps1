@{
    Id          = 'S-ObsoleteDC'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Obsolete Operating System on Domain Controllers'
    Description = 'Domain controllers running unsupported or end-of-life Windows Server versions. These systems no longer receive security updates and are vulnerable to known exploits.'
    Severity    = 'Critical'
    Weight      = 100
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Windows Server Lifecycle'; Url = 'https://learn.microsoft.com/en-us/lifecycle/products/?products=windows-server' }
        @{ Title = 'EternalBlue/MS17-010'; Url = 'https://attack.mitre.org/techniques/T1210/' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0008')  # Initial Access, Lateral Movement
        Techniques = @('T1210')              # Exploitation of Remote Services
    }

    CIS   = @('5.22')
    STIG  = @('V-36452')
    ANSSI = @('vuln1_obsolete_dc')
    NIST  = @('CM-8', 'SI-2')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Define obsolete OS patterns and their end-of-support dates
        $obsoletePatterns = @{
            'Windows 2000'       = @{ EndDate = '2010-07-13'; Severity = 'Critical' }
            'Windows Server 2003' = @{ EndDate = '2015-07-14'; Severity = 'Critical' }
            'Server 2003'        = @{ EndDate = '2015-07-14'; Severity = 'Critical' }
            'Windows Server 2008 R2' = @{ EndDate = '2020-01-14'; Severity = 'Critical' }
            'Windows Server 2008'    = @{ EndDate = '2020-01-14'; Severity = 'Critical' }
            'Server 2008'        = @{ EndDate = '2020-01-14'; Severity = 'Critical' }
            'Windows Server 2012 R2' = @{ EndDate = '2023-10-10'; Severity = 'High' }
            'Windows Server 2012'    = @{ EndDate = '2023-10-10'; Severity = 'High' }
            'Server 2012'        = @{ EndDate = '2023-10-10'; Severity = 'High' }
        }

        foreach ($computer in $Data) {
            # Check if this is a Domain Controller
            $isDC = $false
            if ($computer.MemberOf) {
                foreach ($group in $computer.MemberOf) {
                    if ($group -match 'Domain Controllers') {
                        $isDC = $true
                        break
                    }
                }
            }

            if ($isDC -and $computer.OperatingSystem) {
                foreach ($pattern in $obsoletePatterns.Keys) {
                    if ($computer.OperatingSystem -match $pattern) {
                        $osInfo = $obsoletePatterns[$pattern]
                        $findings += [PSCustomObject]@{
                            Name              = $computer.Name
                            DNSHostName       = $computer.DNSHostName
                            OperatingSystem   = $computer.OperatingSystem
                            OSVersion         = $computer.OperatingSystemVersion
                            EndOfSupportDate  = $osInfo.EndDate
                            Severity          = $osInfo.Severity
                            DaysSinceEOL      = ((Get-Date) - [datetime]$osInfo.EndDate).Days
                            Enabled           = $computer.Enabled
                            DistinguishedName = $computer.DistinguishedName
                            Risk              = 'No security patches available - known exploits exist'
                        }
                        break
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Upgrade Domain Controllers to a supported Windows Server version. Plan migration carefully to avoid service disruption.'
        Impact      = 'High - Requires DC demotion/promotion cycle'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: Obsolete Domain Controllers detected
# These systems are vulnerable to known exploits (EternalBlue, ZeroLogon, etc.)

# Recommended upgrade path:
# 1. Build new DCs on supported Windows Server (2019 or 2022)
# 2. Promote new DCs and transfer FSMO roles
# 3. Demote old DCs
# 4. Raise domain/forest functional level if appropriate

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# DC: $($item.Name)
# Current OS: $($item.OperatingSystem)
# End of Support: $($item.EndOfSupportDate) ($($item.DaysSinceEOL) days ago)

# Check FSMO role holders:
netdom query fsmo

# Transfer FSMO roles from old DC to new DC:
# Move-ADDirectoryServerOperationMasterRole -Identity NewDC -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster

# Demote old DC (after FSMO transfer and replication):
# Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartition

"@
            }
            return $commands
        }
    }
}
