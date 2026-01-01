<#
.SYNOPSIS
    Detects computers without LAPS (Local Administrator Password Solution) deployed.

.DESCRIPTION
    LAPS provides automatic management of local administrator passwords, preventing
    lateral movement via shared local admin credentials. This rule identifies computers
    that don't have LAPS configured.

.NOTES
    Rule ID    : AUTH-LAPSNotDeployed
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-LAPSNotDeployed'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'LAPS Not Deployed on Computers'
    Description = 'Identifies computers without LAPS (Local Administrator Password Solution) deployed, enabling lateral movement via shared local admin passwords.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'Windows LAPS Overview'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview' }
        @{ Title = 'LAPS Deployment Guide'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-deployment' }
        @{ Title = 'Local Admin Password Reuse Attack'; Url = 'https://attack.mitre.org/techniques/T1078/003/' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0003')  # Lateral Movement, Persistence
        Techniques = @('T1078.003', 'T1021')  # Local Accounts, Remote Services
    }

    CIS   = @('5.5')
    STIG  = @('V-73621', 'V-73623')
    ANSSI = @('R40')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 2
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check if LAPS schema is extended
        $lapsSchemaExists = $false
        $lapsVersion = 'None'

        try {
            # Check for Windows LAPS (new) attributes
            $schemaNC = ([ADSI]"LDAP://RootDSE").schemaNamingContext
            $windowsLapsAttr = [ADSI]"LDAP://CN=ms-LAPS-Password,$schemaNC"
            if ($windowsLapsAttr.Path) {
                $lapsSchemaExists = $true
                $lapsVersion = 'Windows LAPS'
            }
        } catch {
            # Windows LAPS not found
        }

        if (-not $lapsSchemaExists) {
            try {
                # Check for Legacy LAPS attributes
                $schemaNC = ([ADSI]"LDAP://RootDSE").schemaNamingContext
                $legacyLapsAttr = [ADSI]"LDAP://CN=ms-Mcs-AdmPwd,$schemaNC"
                if ($legacyLapsAttr.Path) {
                    $lapsSchemaExists = $true
                    $lapsVersion = 'Legacy LAPS'
                }
            } catch {
                # Legacy LAPS not found
            }
        }

        if (-not $lapsSchemaExists) {
            # LAPS not deployed at all
            $findings += [PSCustomObject]@{
                ComputerName        = 'DOMAIN-WIDE'
                OperatingSystem     = 'N/A'
                Issue               = 'LAPS schema not extended in Active Directory'
                LAPSPassword        = 'Not Available'
                LAPSExpiration      = 'Not Available'
                Enabled             = 'N/A'
                RiskLevel           = 'Critical'
                Recommendation      = 'Deploy Windows LAPS or Legacy LAPS to the domain'
                DistinguishedName   = 'N/A'
            }
            return $findings
        }

        # LAPS is deployed - check which computers have it configured
        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                $computerName = $computer.Name
                if (-not $computerName) { $computerName = $computer.SamAccountName }
                if (-not $computerName) { continue }

                # Skip Domain Controllers - they shouldn't have LAPS
                $isDC = $computer.PrimaryGroupID -eq 516 -or
                        $computer.DistinguishedName -match 'Domain Controllers'
                if ($isDC) { continue }

                # Check for LAPS password
                $hasLAPS = $false
                $lapsExpiration = $null

                # Windows LAPS attributes
                $windowsLapsPwd = $computer.'msLAPS-Password'
                $windowsLapsExp = $computer.'msLAPS-PasswordExpirationTime'

                # Legacy LAPS attributes
                $legacyLapsPwd = $computer.'ms-Mcs-AdmPwd'
                $legacyLapsExp = $computer.'ms-Mcs-AdmPwdExpirationTime'

                if ($windowsLapsPwd -or $legacyLapsPwd) {
                    $hasLAPS = $true
                    $lapsExpiration = if ($windowsLapsExp) { $windowsLapsExp } else { $legacyLapsExp }
                }

                if (-not $hasLAPS -and $computer.Enabled -ne $false) {
                    # Only flag enabled computers without LAPS
                    $os = $computer.OperatingSystem
                    $isServer = $os -match 'Server'
                    $isWorkstation = $os -match 'Windows 10|Windows 11'

                    $findings += [PSCustomObject]@{
                        ComputerName        = $computerName
                        OperatingSystem     = $os
                        Issue               = "No LAPS password configured ($lapsVersion schema exists)"
                        LAPSPassword        = 'Not Set'
                        LAPSExpiration      = 'N/A'
                        Enabled             = $computer.Enabled
                        RiskLevel           = if ($isServer) { 'High' } else { 'Medium' }
                        Recommendation      = 'Deploy LAPS CSE and configure GPO'
                        DistinguishedName   = $computer.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy LAPS to all computers to ensure unique local administrator passwords and prevent lateral movement.'
        Impact      = 'Medium - Requires CSE deployment and may change existing local admin passwords.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# LAPS (Local Administrator Password Solution) Deployment
#############################################################################
#
# Without LAPS, attackers can move laterally by:
# 1. Dumping local admin hash from one machine
# 2. Using pass-the-hash to access other machines with same password
# 3. Compromising entire environment from single workstation
#
# Affected Computers:
$($Finding.Findings | Where-Object { $_.ComputerName -ne 'DOMAIN-WIDE' } | ForEach-Object { "# - $($_.ComputerName): $($_.OperatingSystem)" } | Out-String)

#############################################################################
# Windows LAPS Deployment (Windows Server 2019+, Windows 10/11)
#############################################################################

# Step 1: Update AD Schema (requires Schema Admin rights)
Update-LapsADSchema

# Step 2: Grant computers permission to update their LAPS password
# Run for each OU containing computers:
`$ous = @(
    "OU=Workstations,DC=contoso,DC=com"
    "OU=Servers,DC=contoso,DC=com"
)

foreach (`$ou in `$ous) {
    Set-LapsADComputerSelfPermission -Identity `$ou
}

# Step 3: Grant helpdesk/admins permission to read LAPS passwords
# Example: Allow Helpdesk group to read passwords for workstations
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\Helpdesk"

# Step 4: Configure via Group Policy
# Computer Configuration > Policies > Administrative Templates > System > LAPS

# Key settings:
# - "Configure password backup directory" = Active Directory
# - "Password Settings"
#   - Password Complexity = Large letters + small letters + numbers + specials
#   - Password Length = 20+ characters
#   - Password Age (Days) = 30
# - "Name of administrator account to manage" = (default Administrator or custom)
# - "Post-authentication actions" = Reset password + Logoff

#############################################################################
# Legacy LAPS Deployment (older systems)
#############################################################################

# If using Legacy LAPS for older systems:

# Step 1: Extend schema
Import-Module AdmPwd.PS
Update-AdmPwdADSchema

# Step 2: Grant permissions
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Computers,DC=contoso,DC=com"
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Computers,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\IT Admins"

# Step 3: Deploy CSE via GPO
# Copy AdmPwd.dll to SYSVOL and use GPO to register

# Step 4: Configure via GPO
# Computer Configuration > Policies > Administrative Templates > LAPS
# - Enable local admin password management
# - Password complexity
# - Password length
# - Password age

#############################################################################
# Verification
#############################################################################

# Check LAPS deployment status:
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, `
    msLAPS-Password, msLAPS-PasswordExpirationTime |
    Select-Object Name,
        @{N='LegacyLAPS';E={if (`$_.'ms-Mcs-AdmPwd') {'Yes'} else {'No'}}},
        @{N='WindowsLAPS';E={if (`$_.'msLAPS-Password') {'Yes'} else {'No'}}} |
    Format-Table

# View LAPS password (requires permissions):
Get-LapsADPassword -Identity "COMPUTER01" -AsPlainText

"@
            return $commands
        }
    }
}
