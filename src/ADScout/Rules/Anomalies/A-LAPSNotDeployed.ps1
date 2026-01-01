@{
    Id          = 'A-LAPSNotDeployed'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LAPS Not Deployed on Computers'
    Description = 'Detects computers that do not have Local Administrator Password Solution (LAPS) deployed. Without LAPS, local administrator passwords are often identical across systems, enabling lateral movement through pass-the-hash attacks.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Microsoft LAPS'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview' }
        @{ Title = 'LAPS Deployment Guide'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-deployment' }
        @{ Title = 'Pass the Hash Attack'; Url = 'https://attack.mitre.org/techniques/T1550/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1550.002', 'T1078.003')  # Pass the Hash, Local Accounts
    }

    CIS   = @('5.6.1')
    STIG  = @('V-220950')
    ANSSI = @('R48')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 5
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $stats = @{
            TotalComputers = 0
            WithLAPS = 0
            WithoutLAPS = 0
            LegacyLAPS = 0
            WindowsLAPS = 0
        }

        foreach ($computer in $Data.Computers) {
            if (-not $computer.Enabled) { continue }
            $stats.TotalComputers++

            $hasLAPS = $false
            $lapsType = 'None'
            $passwordAge = $null

            # Check for Windows LAPS (2023+) - msLAPS-Password attribute
            if ($computer.'msLAPS-Password' -or $computer.'msLAPS-PasswordExpirationTime') {
                $hasLAPS = $true
                $lapsType = 'Windows LAPS'
                $stats.WindowsLAPS++

                if ($computer.'msLAPS-PasswordExpirationTime') {
                    $passwordAge = (New-TimeSpan -Start $computer.'msLAPS-PasswordExpirationTime' -End (Get-Date)).Days * -1
                }
            }
            # Check for Legacy LAPS - ms-Mcs-AdmPwd attribute
            elseif ($computer.'ms-Mcs-AdmPwd' -or $computer.'ms-Mcs-AdmPwdExpirationTime') {
                $hasLAPS = $true
                $lapsType = 'Legacy LAPS'
                $stats.LegacyLAPS++

                if ($computer.'ms-Mcs-AdmPwdExpirationTime') {
                    try {
                        $expirationTime = [DateTime]::FromFileTime([Int64]$computer.'ms-Mcs-AdmPwdExpirationTime')
                        $passwordAge = (New-TimeSpan -Start $expirationTime -End (Get-Date)).Days * -1
                    }
                    catch { }
                }
            }

            if ($hasLAPS) {
                $stats.WithLAPS++
            }
            else {
                $stats.WithoutLAPS++

                # Only flag workstations and member servers (not DCs)
                if ($computer.DistinguishedName -notmatch 'Domain Controllers') {
                    $findings += [PSCustomObject]@{
                        ComputerName        = $computer.Name
                        DNSHostName         = $computer.DNSHostName
                        OperatingSystem     = $computer.OperatingSystem
                        DistinguishedName   = $computer.DistinguishedName
                        LAPSDeployed        = $false
                        LAPSType            = 'None'
                        LastLogon           = $computer.LastLogonDate
                        RiskLevel           = if ($computer.OperatingSystem -match 'Server') { 'High' } else { 'Medium' }
                        Risk                = 'Local admin password may be shared across systems'
                        LateralMovementRisk = 'Compromising one system may grant access to many others'
                    }
                }
            }
        }

        # Add summary finding if significant coverage gap
        if ($stats.TotalComputers -gt 0) {
            $coveragePercent = [math]::Round(($stats.WithLAPS / $stats.TotalComputers) * 100, 1)

            if ($coveragePercent -lt 80) {
                $findings = @([PSCustomObject]@{
                    Finding             = 'LAPS Coverage Summary'
                    TotalComputers      = $stats.TotalComputers
                    WithLAPS            = $stats.WithLAPS
                    WithoutLAPS         = $stats.WithoutLAPS
                    CoveragePercent     = $coveragePercent
                    WindowsLAPS         = $stats.WindowsLAPS
                    LegacyLAPS          = $stats.LegacyLAPS
                    RiskLevel           = if ($coveragePercent -lt 50) { 'Critical' }
                                         elseif ($coveragePercent -lt 70) { 'High' }
                                         else { 'Medium' }
                }) + $findings
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy LAPS (preferably Windows LAPS) to all workstations and member servers. Configure automatic password rotation.'
        Impact      = 'Medium - Requires GPO configuration and may affect scripts using local admin'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# LAPS DEPLOYMENT
# ================================================================
# LAPS randomizes local administrator passwords and stores them
# securely in Active Directory. This prevents:
# - Pass-the-Hash attacks using shared local admin passwords
# - Lateral movement via local admin credentials

# ================================================================
# STEP 1: CHECK CURRENT LAPS STATUS
# ================================================================

# Check schema for LAPS attributes:
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext ``
    -Filter { Name -like 'ms-Mcs-*' -or Name -like 'msLAPS-*' } | ``
    Select-Object Name

# Count computers with/without LAPS:
`$computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', 'msLAPS-Password'
`$withLAPS = `$computers | Where-Object { `$_.'ms-Mcs-AdmPwd' -or `$_.'msLAPS-Password' }
`$withoutLAPS = `$computers | Where-Object { -not `$_.'ms-Mcs-AdmPwd' -and -not `$_.'msLAPS-Password' }

Write-Host "Total Computers: `$(`$computers.Count)"
Write-Host "With LAPS: `$(`$withLAPS.Count)"
Write-Host "Without LAPS: `$(`$withoutLAPS.Count)"

# ================================================================
# STEP 2: DEPLOY WINDOWS LAPS (Recommended - Windows Server 2019+)
# ================================================================

# Update schema (requires Schema Admin):
Update-LapsADSchema

# Configure permissions (on target OUs):
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=com"
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=domain,DC=com"

# Grant read permission to admins:
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=domain,DC=com" -AllowedPrincipals "Domain Admins"

# ================================================================
# STEP 3: CONFIGURE VIA GROUP POLICY
# ================================================================

# Create GPO: "LAPS Configuration"
# Computer Configuration > Policies > Administrative Templates >
#   System > LAPS

# Settings:
# - Configure password backup directory: Active Directory
# - Password Settings:
#   - Password Complexity: Large letters + small letters + numbers + specials
#   - Password Length: 20
#   - Password Age (Days): 30
# - Name of administrator account to manage: (leave default or specify)

# ================================================================
# STEP 4: VERIFY DEPLOYMENT
# ================================================================

# Check specific computer:
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText

# List all computers with LAPS password:
Get-ADComputer -Filter * -Properties msLAPS-PasswordExpirationTime | ``
    Where-Object { `$_.'msLAPS-PasswordExpirationTime' } | ``
    Select-Object Name, @{N='Expires';E={[DateTime]::FromFileTime(`$_.'msLAPS-PasswordExpirationTime')}}

# ================================================================
# LEGACY LAPS (For older systems)
# ================================================================

# If using Legacy LAPS (pre-Windows LAPS):
# 1. Download from Microsoft
# 2. Extend schema: Update-AdmPwdADSchema
# 3. Set permissions: Set-AdmPwdComputerSelfPermission
# 4. Deploy MSI via GPO/SCCM
# 5. Configure via GPO

"@
            return $commands
        }
    }
}
