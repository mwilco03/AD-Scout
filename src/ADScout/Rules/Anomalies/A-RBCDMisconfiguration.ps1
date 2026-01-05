@{
    Id          = 'A-RBCDMisconfiguration'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Resource-Based Constrained Delegation (RBCD) Misconfiguration'
    Description = 'Detects computers with msDS-AllowedToActOnBehalfOfOtherIdentity configured, indicating Resource-Based Constrained Delegation. While legitimate, RBCD can be abused if attackers can write to this attribute, enabling impersonation attacks.'
    Severity    = 'High'
    Weight      = 40
    DataSource  = 'Computers'

    References  = @(
        @{ Title = 'RBCD Abuse'; Url = 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-target-kerberos-delegation' }
        @{ Title = 'RBCD Attack'; Url = 'https://attack.mitre.org/techniques/T1550/003/' }
        @{ Title = 'Elad Shamir Research'; Url = 'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0004')  # Lateral Movement, Privilege Escalation
        Techniques = @('T1550.003')  # Use Alternate Authentication Material: Kerberos Tickets
    }

    CIS   = @('5.6.1')
    STIG  = @('V-220950')
    ANSSI = @('R52')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Find computers with RBCD configured
            $computersWithRBCD = Get-ADComputer -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like "*" } -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'PrimaryGroupID', 'OperatingSystem' -ErrorAction SilentlyContinue

            foreach ($computer in $computersWithRBCD) {
                $rbcdValue = $computer.'msDS-AllowedToActOnBehalfOfOtherIdentity'

                if ($rbcdValue) {
                    # Parse the security descriptor to see who can delegate
                    $allowedPrincipals = @()
                    try {
                        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $sd.SetSecurityDescriptorBinaryForm($rbcdValue)

                        foreach ($ace in $sd.Access) {
                            $allowedPrincipals += $ace.IdentityReference.Value
                        }
                    }
                    catch {
                        $allowedPrincipals += 'Unable to parse'
                    }

                    $isDC = $computer.PrimaryGroupID -eq 516

                    $findings += [PSCustomObject]@{
                        ComputerName        = $computer.Name
                        DistinguishedName   = $computer.DistinguishedName
                        OperatingSystem     = $computer.OperatingSystem
                        IsDomainController  = $isDC
                        AllowedPrincipals   = $allowedPrincipals -join '; '
                        RiskLevel           = if ($isDC) { 'Critical' } else { 'High' }
                        Issue               = if ($isDC) {
                            'RBCD on Domain Controller - extremely dangerous'
                        } else {
                            'RBCD configured - verify this is intended'
                        }
                        AttackPath          = 'Principals in AllowedToActOnBehalfOfOtherIdentity can impersonate any user to this computer'
                    }
                }
            }

            # Also check for computers where low-privileged users can write this attribute
            $computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue | Select-Object -First 50

            foreach ($computer in $computers) {
                try {
                    $acl = Get-Acl "AD:$($computer.DistinguishedName)" -ErrorAction SilentlyContinue

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -eq 'Deny') { continue }

                        # Check for write to msDS-AllowedToActOnBehalfOfOtherIdentity
                        # GUID: 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
                        $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'

                        $canWriteRBCD = $false

                        if ($ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite') {
                            $canWriteRBCD = $true
                        }

                        if ($ace.ActiveDirectoryRights -match 'WriteProperty') {
                            if ($ace.ObjectType -eq [Guid]::Empty -or
                                $ace.ObjectType -eq $rbcdGuid) {
                                $canWriteRBCD = $true
                            }
                        }

                        if ($canWriteRBCD) {
                            $principal = $ace.IdentityReference.Value

                            if ($principal -match 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Account Operators|SELF') {
                                continue
                            }

                            # Flag if low-privileged or unexpected
                            if ($principal -match 'Domain Users|Authenticated Users|Everyone|Domain Computers') {
                                $findings += [PSCustomObject]@{
                                    ComputerName        = $computer.Name
                                    DistinguishedName   = $computer.DistinguishedName
                                    Principal           = $principal
                                    Permission          = 'Can write msDS-AllowedToActOnBehalfOfOtherIdentity'
                                    RiskLevel           = 'Critical'
                                    Issue               = 'Low-privileged principal can configure RBCD'
                                    AttackPath          = 'Set RBCD to attacker-controlled account -> impersonate any user'
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            # Could not check RBCD
        }

        return $findings | Sort-Object RiskLevel, ComputerName
    }

    Remediation = @{
        Description = 'Review and remove unnecessary RBCD configurations. Restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity.'
        Impact      = 'Medium - May affect legitimate delegation scenarios'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)
# ================================================================
# RBCD allows principals to impersonate users TO a specific computer.
# Set via msDS-AllowedToActOnBehalfOfOtherIdentity on target.
#
# Attack (if attacker can write this attribute):
# 1. Create or control a computer account (MachineAccountQuota)
# 2. Set RBCD on target to allow controlled account
# 3. Use S4U2Self + S4U2Proxy to get ticket as admin to target
# 4. Full compromise of target computer

# ================================================================
# DETECTED RBCD CONFIGURATIONS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Computer: $($item.ComputerName)
# DN: $($item.DistinguishedName)
# Is DC: $($item.IsDomainController)
# Allowed Principals: $($item.AllowedPrincipals)
# Issue: $($item.Issue)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# CHECK CURRENT RBCD
# ================================================================

# List all computers with RBCD:
Get-ADComputer -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like "*" } -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' |
    ForEach-Object {
        Write-Host "Computer: `$(`$_.Name)"
        `$sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        `$sd.SetSecurityDescriptorBinaryForm(`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity')
        `$sd.Access | ForEach-Object { Write-Host "  - `$(`$_.IdentityReference)" }
    }

# ================================================================
# REMOVE RBCD
# ================================================================

# To clear RBCD from a computer:
# Set-ADComputer -Identity "ComputerName" -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'

# ================================================================
# PREVENT RBCD ATTACKS
# ================================================================

# 1. Set MachineAccountQuota to 0:
Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'='0'}

# 2. Monitor for RBCD changes:
# - Event ID 5136 (Directory Service Changes)
# - Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity

# 3. Restrict who can write to computer objects:
# - Review delegation on computer OUs
# - Account Operators can create/modify computers by default

# ================================================================
# LEGITIMATE RBCD USE CASES
# ================================================================

# RBCD is legitimate for:
# - Allowing specific services to impersonate to specific servers
# - Cross-forest delegation scenarios
#
# If needed, document and audit carefully.

"@
            return $commands
        }
    }
}
