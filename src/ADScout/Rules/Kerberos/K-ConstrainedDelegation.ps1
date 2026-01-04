@{
    Id          = 'K-ConstrainedDelegation'
    Version     = '1.0.0'
    Category    = 'Kerberos'
    Title       = 'Constrained Delegation to Sensitive Services'
    Description = 'Accounts with constrained delegation to sensitive services. Checks both delegation configuration AND whether sensitive accounts have "Account is sensitive and cannot be delegated" protection.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Users,Computers'

    References  = @(
        @{ Title = 'Constrained Delegation Abuse'; Url = 'https://attack.mitre.org/techniques/T1558/003/' }
        @{ Title = 'Kerberos Delegation'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview' }
        @{ Title = 'S4U2Proxy Attack'; Url = 'https://www.thehacker.recipes/a-d/movement/kerberos/delegations/constrained' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1558.003')  # Kerberos Delegation
    }

    CIS   = @('5.8')
    STIG  = @()
    ANSSI = @('vuln1_constrained_delegation')
    NIST  = @('AC-6', 'SC-23')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 15
        MaxPoints = 60
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # ========================================================================
        # BELT: Check if sensitive accounts have "Cannot be delegated" protection
        # ========================================================================
        # NOT_DELEGATED = 0x100000 = 1048576
        $NOT_DELEGATED = 1048576

        try {
            # Check Domain Admins for delegation protection
            $domainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction SilentlyContinue
            $unprotectedAdmins = @()

            foreach ($admin in $domainAdmins) {
                if ($admin.objectClass -eq 'user') {
                    $user = Get-ADUser -Identity $admin.SamAccountName -Properties UserAccountControl -ErrorAction SilentlyContinue
                    if ($user -and -not ($user.UserAccountControl -band $NOT_DELEGATED)) {
                        $unprotectedAdmins += $user.SamAccountName
                    }
                }
            }

            if ($unprotectedAdmins.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    ObjectType          = 'Mitigation Gap'
                    AccountName         = 'Domain Admins without delegation protection'
                    AccountType         = 'Privileged Users'
                    DistinguishedName   = 'Multiple'
                    DelegationTargets   = 'N/A'
                    SensitiveTargets    = 'N/A'
                    DCTargets           = 'N/A'
                    TargetsDCs          = $false
                    RiskLevel           = 'High'
                    AttackPath          = "Unprotected admins: $($unprotectedAdmins -join ', ')"
                    ConfigSource        = 'Account Flag Missing'
                }
            }

            # Check Enterprise Admins
            $enterpriseAdmins = Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive -ErrorAction SilentlyContinue
            $unprotectedEA = @()

            foreach ($admin in $enterpriseAdmins) {
                if ($admin.objectClass -eq 'user') {
                    $user = Get-ADUser -Identity $admin.SamAccountName -Properties UserAccountControl -ErrorAction SilentlyContinue
                    if ($user -and -not ($user.UserAccountControl -band $NOT_DELEGATED)) {
                        $unprotectedEA += $user.SamAccountName
                    }
                }
            }

            if ($unprotectedEA.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    ObjectType          = 'Mitigation Gap'
                    AccountName         = 'Enterprise Admins without delegation protection'
                    AccountType         = 'Privileged Users'
                    DistinguishedName   = 'Multiple'
                    DelegationTargets   = 'N/A'
                    SensitiveTargets    = 'N/A'
                    DCTargets           = 'N/A'
                    TargetsDCs          = $false
                    RiskLevel           = 'Critical'
                    AttackPath          = "Unprotected EA: $($unprotectedEA -join ', ')"
                    ConfigSource        = 'Account Flag Missing'
                }
            }
        } catch {
            Write-Verbose "K-ConstrainedDelegation: Could not check admin delegation protection: $_"
        }

        # ========================================================================
        # SUSPENDERS: Check accounts with constrained delegation to sensitive SPNs
        # ========================================================================

        # Sensitive SPNs that are high-risk for delegation
        $sensitiveServices = @(
            'ldap/',       # LDAP - DCSync potential
            'cifs/',       # File shares - including DC SYSVOL
            'http/',       # Web services
            'host/',       # Computer management
            'wsman/',      # PowerShell remoting
            'rpcss/',      # RPC services
            'krbtgt/',     # Kerberos TGT (should never be delegated to)
            'gc/',         # Global Catalog
            'exchangemdb/', # Exchange
            'msds-allowedtoactonbehalfofotheridentity'  # RBCD
        )

        foreach ($account in $Data) {
            # Check for constrained delegation (msDS-AllowedToDelegateTo)
            $delegateTo = $account.'msDS-AllowedToDelegateTo'
            if (-not $delegateTo) { continue }

            $sensitiveTargets = @()
            $dcTargets = @()

            foreach ($spn in $delegateTo) {
                # Check if SPN is for a sensitive service
                foreach ($sensitive in $sensitiveServices) {
                    if ($spn.ToLower().StartsWith($sensitive)) {
                        $sensitiveTargets += $spn

                        # Check if target is a DC
                        $targetHost = ($spn -split '/')[1]
                        if ($targetHost) {
                            $targetHost = ($targetHost -split ':')[0]  # Remove port if present

                            # Check if this is a DC (simple heuristic)
                            if ($targetHost -match 'dc|domain controller' -or
                                $Data | Where-Object { $_.Name -eq $targetHost -and $_.PrimaryGroupID -eq 516 }) {
                                $dcTargets += $spn
                            }
                        }
                    }
                }
            }

            if ($sensitiveTargets.Count -gt 0) {
                $riskLevel = 'Medium'
                if ($dcTargets.Count -gt 0) { $riskLevel = 'Critical' }
                elseif ($sensitiveTargets | Where-Object { $_ -match 'ldap/' }) { $riskLevel = 'Critical' }
                elseif ($sensitiveTargets | Where-Object { $_ -match 'cifs/|http/' }) { $riskLevel = 'High' }

                $findings += [PSCustomObject]@{
                    AccountName         = $account.SamAccountName
                    AccountType         = if ($account.ObjectClass -eq 'computer') { 'Computer' } else { 'User' }
                    DistinguishedName   = $account.DistinguishedName
                    DelegationTargets   = $delegateTo -join '; '
                    SensitiveTargets    = $sensitiveTargets -join '; '
                    DCTargets           = $dcTargets -join '; '
                    TargetsDCs          = $dcTargets.Count -gt 0
                    RiskLevel           = $riskLevel
                    AttackPath          = 'Compromise account -> S4U2Self -> S4U2Proxy -> Impersonate any user to target service'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review constrained delegation configurations. Remove delegation to sensitive services on DCs. Consider using Resource-Based Constrained Delegation with proper restrictions instead.'
        Impact      = 'High - Removing delegation may break applications. Test thoroughly in non-production first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Review Constrained Delegation to Sensitive Services
# Accounts with Risky Delegation: $($Finding.Findings.Count)

$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.SensitiveTargets)" } | Out-String)

# ATTACK SCENARIO:
# 1. Attacker compromises an account with constrained delegation
# 2. Uses S4U2Self to obtain a forwardable ticket
# 3. Uses S4U2Proxy to request a ticket to the delegated service
# 4. The service ticket is for the impersonated user (e.g., Domain Admin)
# 5. Attacker can access the service as that user

# REMEDIATION OPTIONS:

# Option 1: Remove delegation entirely (if not needed)
foreach (`$account in @('$($Finding.Findings.AccountName -join "','")')) {
    # Clear msDS-AllowedToDelegateTo
    Set-ADObject -Identity `$account -Clear 'msDS-AllowedToDelegateTo'
    Write-Host "Cleared delegation for `$account"
}

# Option 2: Modify to delegate to less sensitive services
# Example: Change from LDAP to only specific app services
# Set-ADObject -Identity `$account -Replace @{
#     'msDS-AllowedToDelegateTo' = @('http/webapp.domain.com')
# }

# Option 3: Use Protocol Transition restriction
# Disable "Use any authentication protocol" (require Kerberos only)
# This limits S4U2Self attacks
# Set-ADAccountControl -Identity `$account -TrustedToAuthForDelegation `$false

# Option 4: Mark sensitive accounts as "not delegatable"
# Protect high-value accounts from being impersonated
`$sensitiveAccounts = Get-ADGroupMember -Identity "Domain Admins" -Recursive
foreach (`$admin in `$sensitiveAccounts) {
    Set-ADAccountControl -Identity `$admin -AccountNotDelegated `$true
    Write-Host "Protected `$(`$admin.SamAccountName) from delegation"
}

# VERIFICATION:
# List all accounts with constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, @{N='DelegatesTo';E={`$_.'msDS-AllowedToDelegateTo' -join ','}}

# Check sensitive accounts are protected
Get-ADUser -Filter {AdminCount -eq 1} -Properties AccountNotDelegated |
    Select-Object SamAccountName, AccountNotDelegated

"@
            return $commands
        }
    }
}
