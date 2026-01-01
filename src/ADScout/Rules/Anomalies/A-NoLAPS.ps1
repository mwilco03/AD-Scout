@{
    Id          = 'A-NoLAPS'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LAPS Not Deployed'
    Description = 'Local Administrator Password Solution (LAPS) is not deployed or not widely used. Without LAPS, local administrator passwords are often shared across systems, enabling lateral movement.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'LAPS Overview'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview' }
        @{ Title = 'Local Admin Password Reuse'; Url = 'https://attack.mitre.org/techniques/T1078/003/' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0006')  # Lateral Movement, Credential Access
        Techniques = @('T1078.003')          # Valid Accounts: Local Accounts
    }

    CIS   = @('5.23')
    STIG  = @('V-36457')
    ANSSI = @('vuln2_no_laps')

    Scoring = @{
        Type       = 'TriggerOnThreshold'
        Threshold  = 50  # Flag if more than 50% of computers lack LAPS
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $totalComputers = 0
        $computersWithLAPS = 0
        $computersWithoutLAPS = @()

        foreach ($computer in $Data) {
            # Skip Domain Controllers
            if ($computer.DistinguishedName -match 'Domain Controllers') { continue }

            # Skip disabled computers
            if (-not $computer.Enabled) { continue }

            $totalComputers++

            # Check for LAPS attributes (ms-Mcs-AdmPwd for legacy LAPS, msLAPS-Password for Windows LAPS)
            $hasLAPS = $false
            if ($computer.'ms-Mcs-AdmPwd' -or $computer.'msLAPS-Password' -or $computer.'msLAPS-PasswordExpirationTime') {
                $hasLAPS = $true
                $computersWithLAPS++
            }

            if (-not $hasLAPS) {
                $computersWithoutLAPS += [PSCustomObject]@{
                    Name              = $computer.Name
                    DNSHostName       = $computer.DNSHostName
                    OperatingSystem   = $computer.OperatingSystem
                    LastLogon         = $computer.LastLogonDate
                    DistinguishedName = $computer.DistinguishedName
                }
            }
        }

        if ($totalComputers -gt 0) {
            $percentWithoutLAPS = [math]::Round(($computersWithoutLAPS.Count / $totalComputers) * 100, 1)

            if ($percentWithoutLAPS -gt 50) {
                $findings += [PSCustomObject]@{
                    TotalComputers      = $totalComputers
                    ComputersWithLAPS   = $computersWithLAPS
                    ComputersWithoutLAPS = $computersWithoutLAPS.Count
                    PercentWithoutLAPS  = $percentWithoutLAPS
                    SampleMissing       = $computersWithoutLAPS | Select-Object -First 10
                    Risk                = 'Shared local admin passwords enable lateral movement'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy LAPS (Local Administrator Password Solution) to manage local administrator passwords. Windows LAPS is built into Windows Server 2019+ and Windows 10/11.'
        Impact      = 'Low - Automatic password management with no user impact'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# LAPS not deployed on $($Finding.Findings[0].ComputersWithoutLAPS) of $($Finding.Findings[0].TotalComputers) computers
# This enables lateral movement via shared local admin passwords

# For Windows LAPS (built-in to modern Windows):

# Step 1: Update Schema (requires Schema Admin)
Update-LapsADSchema

# Step 2: Grant computers permission to update their passwords
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=com"

# Step 3: Grant admins permission to read passwords
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=domain,DC=com" -AllowedPrincipals "Domain Admins"

# Step 4: Configure via Group Policy
# Computer Configuration > Administrative Templates > System > LAPS
# - Configure password backup directory: Active Directory
# - Password Settings: Complexity, Length, Age

# For Legacy LAPS (if not using Windows LAPS):
# 1. Download from Microsoft
# 2. Run LAPS schema update
# 3. Deploy LAPS CSE via GPO or SCCM

# Sample computers missing LAPS:
"@
            foreach ($comp in $Finding.Findings[0].SampleMissing) {
                $commands += @"

# - $($comp.Name) ($($comp.OperatingSystem))
"@
            }

            $commands += @"


# Verify LAPS deployment:
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd','msLAPS-Password' |
    Where-Object { -not `$_.'ms-Mcs-AdmPwd' -and -not `$_.'msLAPS-Password' } |
    Select-Object Name | Measure-Object

"@
            return $commands
        }
    }
}
