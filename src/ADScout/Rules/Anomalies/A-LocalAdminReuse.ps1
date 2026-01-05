@{
    Id          = 'A-LocalAdminReuse'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Local Administrator Password Reuse Risk'
    Description = 'Detects computers that may have reused local administrator passwords. Without LAPS, organizations often use the same local admin password across many computers, enabling lateral movement via pass-the-hash attacks.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'LAPS'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview' }
        @{ Title = 'Pass-the-Hash'; Url = 'https://attack.mitre.org/techniques/T1550/002/' }
        @{ Title = 'Lateral Movement'; Url = 'https://attack.mitre.org/tactics/TA0008/' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0006')  # Lateral Movement, Credential Access
        Techniques = @('T1550.002', 'T1078.003')  # Pass-the-Hash, Valid Accounts: Local Accounts
    }

    CIS   = @('5.6.2')
    STIG  = @('V-220951')
    ANSSI = @('R53')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Count computers without LAPS
            $computersWithoutLAPS = @()
            $computersWithLAPS = @()

            $computers = Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'OperatingSystem', 'LastLogonDate' -ErrorAction SilentlyContinue

            foreach ($computer in $computers) {
                if ($computer.LastLogonDate -and $computer.LastLogonDate -gt (Get-Date).AddDays(-90)) {
                    # Active computer
                    if ($computer.'ms-Mcs-AdmPwd' -or $computer.'ms-Mcs-AdmPwdExpirationTime') {
                        $computersWithLAPS += $computer
                    } else {
                        $computersWithoutLAPS += $computer
                    }
                }
            }

            $totalActive = $computersWithLAPS.Count + $computersWithoutLAPS.Count
            $lapsPercentage = if ($totalActive -gt 0) { [math]::Round(($computersWithLAPS.Count / $totalActive) * 100, 1) } else { 0 }

            if ($computersWithoutLAPS.Count -gt 0) {
                # Group by OS to show distribution
                $osSummary = $computersWithoutLAPS | Group-Object OperatingSystem | Select-Object Name, Count

                $findings += [PSCustomObject]@{
                    TotalActiveComputers    = $totalActive
                    ComputersWithLAPS       = $computersWithLAPS.Count
                    ComputersWithoutLAPS    = $computersWithoutLAPS.Count
                    LAPSCoverage            = "$lapsPercentage%"
                    OSBreakdown             = ($osSummary | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '; '
                    RiskLevel               = if ($lapsPercentage -lt 50) { 'Critical' } elseif ($lapsPercentage -lt 90) { 'High' } else { 'Medium' }
                    Issue                   = 'Without LAPS, local admin passwords are likely reused'
                    Impact                  = 'Compromise one machine = lateral movement to all with same password'
                }

                # List sample of non-LAPS computers
                $sampleComputers = $computersWithoutLAPS | Select-Object -First 10

                foreach ($computer in $sampleComputers) {
                    $findings += [PSCustomObject]@{
                        ComputerName            = $computer.Name
                        OperatingSystem         = $computer.OperatingSystem
                        LastLogon               = $computer.LastLogonDate
                        LAPSStatus              = 'Not Deployed'
                        RiskLevel               = 'High'
                        Recommendation          = 'Deploy LAPS to this computer'
                    }
                }
            }
        }
        catch {
            # Could not check LAPS status
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy LAPS to all domain-joined Windows computers. Ensure unique local admin passwords.'
        Impact      = 'Medium - Requires LAPS deployment and password retrieval process'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# LOCAL ADMINISTRATOR PASSWORD REUSE
# ================================================================
# Without LAPS, organizations commonly use:
# - Same password for all local admins
# - Predictable patterns (CompanyName2024!)
# - Passwords set once, never changed
#
# Result: Compromise one = compromise all

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            $summary = $Finding.Findings | Where-Object { $_.TotalActiveComputers }
            if ($summary) {
                $commands += @"

# Total Active Computers: $($summary.TotalActiveComputers)
# With LAPS: $($summary.ComputersWithLAPS)
# Without LAPS: $($summary.ComputersWithoutLAPS)
# LAPS Coverage: $($summary.LAPSCoverage)

"@
            }

            $commands += @"

# ================================================================
# SAMPLE NON-LAPS COMPUTERS
# ================================================================

"@
            foreach ($item in $Finding.Findings | Where-Object { $_.ComputerName }) {
                $commands += @"
# $($item.ComputerName) - $($item.OperatingSystem)
"@
            }

            $commands += @"

# ================================================================
# DEPLOY LAPS
# ================================================================

# 1. INSTALL LAPS MANAGEMENT TOOLS
# Download from Microsoft or use Windows 11 built-in LAPS

# PowerShell:
# Install-WindowsFeature GPMC -IncludeManagementTools
# Download LAPS.x64.msi from Microsoft

# 2. EXTEND AD SCHEMA
# Run as Schema Admin:
# Import-Module AdmPwd.PS
# Update-AdmPwdADSchema

# 3. SET PERMISSIONS
# Grant computers the right to update their own passwords:
`$OUs = @(
    "OU=Workstations,DC=domain,DC=com",
    "OU=Servers,DC=domain,DC=com"
)

foreach (`$OU in `$OUs) {
    # Set-AdmPwdComputerSelfPermission -OrgUnit `$OU
}

# 4. GRANT READ PERMISSIONS
# Allow specific groups to read passwords:
# Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Workstations,DC=domain,DC=com" -AllowedPrincipals "DOMAIN\IT Admins"

# 5. CONFIGURE GPO
# Create GPO with LAPS settings:
# - Enable local admin password management
# - Password complexity
# - Password age (30 days recommended)
# - Admin account name (default: Administrator)

# 6. DEPLOY GPO
# Link to computer OUs

# ================================================================
# VERIFY DEPLOYMENT
# ================================================================

# Check LAPS status:
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' |
    Where-Object { `$_.'ms-Mcs-AdmPwd' } |
    Select-Object Name, @{N='PwdExpiration';E={[datetime]::FromFileTime(`$_.'ms-Mcs-AdmPwdExpirationTime')}}

# Retrieve a password:
# Get-AdmPwdPassword -ComputerName "WORKSTATION01"

# ================================================================
# WINDOWS LAPS (WINDOWS 11+)
# ================================================================

# Windows 11 and Server 2022 have LAPS built-in.
# Uses new attributes: msLAPS-Password, etc.

# Check Windows LAPS:
Get-ADComputer -Filter * -Properties 'msLAPS-PasswordExpirationTime' |
    Where-Object { `$_.'msLAPS-PasswordExpirationTime' } |
    Select-Object Name

"@
            return $commands
        }
    }
}
