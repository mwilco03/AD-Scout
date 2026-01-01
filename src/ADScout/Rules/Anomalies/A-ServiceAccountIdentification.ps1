@{
    Id          = 'A-ServiceAccountIdentification'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Undocumented Service Accounts'
    Description = 'Identifies accounts that exhibit service account characteristics (SPNs, naming patterns, no manager, password never expires) but lack proper documentation. Undocumented service accounts are security risks as ownership and purpose are unclear.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'Service Account Security Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
        @{ Title = 'NIST Privileged Account Management'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004')  # Persistence, Privilege Escalation
        Techniques = @('T1078.002', 'T1098')  # Valid Accounts, Account Manipulation
    }

    CIS   = @('5.4', '5.5')
    STIG  = @('V-36433')
    ANSSI = @('R31', 'R68')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Patterns that indicate service accounts
        $namePatterns = @(
            '^svc[-_]', '^service[-_]', '[-_]svc$', '[-_]service$',
            '^sa[-_]', '^app[-_]', '^sys[-_]', '^task[-_]',
            '^batch[-_]', '^sql[-_]', '^iis[-_]', '^ftp[-_]',
            '^backup[-_]', '^scan[-_]', '^auto[-_]', '^job[-_]',
            '^scheduler[-_]', '^agent[-_]', '^sync[-_]', '^repl[-_]'
        )

        foreach ($user in $Data) {
            # Only check enabled accounts
            if (-not $user.Enabled) { continue }

            $serviceScore = 0
            $indicators = @()
            $missingDocumentation = @()

            # Check naming patterns
            foreach ($pattern in $namePatterns) {
                if ($user.SamAccountName -match $pattern) {
                    $serviceScore += 30
                    $indicators += 'Service naming pattern'
                    break
                }
            }

            # Check for SPNs
            if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                $serviceScore += 40
                $indicators += "Has $($user.ServicePrincipalNames.Count) SPN(s)"
            }

            # Check for delegation settings
            if ($user.TrustedForDelegation) {
                $serviceScore += 20
                $indicators += 'Trusted for delegation'
            }
            if ($user.AllowedToDelegateTo -and $user.AllowedToDelegateTo.Count -gt 0) {
                $serviceScore += 15
                $indicators += 'Constrained delegation configured'
            }

            # Check password settings typical of service accounts
            if ($user.PasswordNeverExpires) {
                $serviceScore += 15
                $indicators += 'Password never expires'
            }

            # Check for missing human attributes
            if (-not $user.Manager) {
                $serviceScore += 10
                $missingDocumentation += 'No manager/owner assigned'
            }
            if (-not $user.Department) {
                $serviceScore += 5
                $missingDocumentation += 'No department'
            }
            if (-not $user.Description -or $user.Description.Length -lt 10) {
                $missingDocumentation += 'No/minimal description'
            }
            if (-not $user.Mail -and -not $user.EmailAddress) {
                $missingDocumentation += 'No email address'
            }

            # Only report if service score indicates service account
            if ($serviceScore -ge 30) {
                # Calculate documentation score
                $docScore = 100
                $docScore -= ($missingDocumentation.Count * 20)
                if ($docScore -lt 0) { $docScore = 0 }

                $riskLevel = switch ($true) {
                    { $user.AdminCount -eq 1 } { 'Critical' }
                    { $user.TrustedForDelegation } { 'High' }
                    { $docScore -lt 40 } { 'High' }
                    { $docScore -lt 70 } { 'Medium' }
                    default { 'Low' }
                }

                # Skip if well documented
                if ($docScore -ge 80 -and $riskLevel -eq 'Low') { continue }

                $findings += [PSCustomObject]@{
                    SamAccountName          = $user.SamAccountName
                    DisplayName             = $user.DisplayName
                    UserPrincipalName       = $user.UserPrincipalName
                    DistinguishedName       = $user.DistinguishedName
                    ServiceScore            = $serviceScore
                    ServiceIndicators       = ($indicators -join '; ')
                    DocumentationScore      = $docScore
                    MissingDocumentation    = ($missingDocumentation -join '; ')
                    Description             = $user.Description
                    Manager                 = $user.Manager
                    Department              = $user.Department
                    HasEmail                = [bool]($user.Mail -or $user.EmailAddress)
                    PasswordNeverExpires    = $user.PasswordNeverExpires
                    TrustedForDelegation    = $user.TrustedForDelegation
                    SPNs                    = ($user.ServicePrincipalNames -join '; ')
                    AdminCount              = $user.AdminCount
                    IsPrivileged            = ($user.AdminCount -eq 1)
                    LastLogonDate           = $user.LastLogonDate
                    PasswordLastSet         = $user.PasswordLastSet
                    WhenCreated             = $user.WhenCreated
                    RiskLevel               = $riskLevel
                }
            }
        }

        return $findings | Sort-Object -Property @{E='RiskLevel';D=$true}, ServiceScore -Descending
    }

    Remediation = @{
        Description = 'Document service accounts with owner, purpose, and dependencies. Consider migrating to Group Managed Service Accounts (gMSA) for automatic password management.'
        Impact      = 'Medium - Requires coordination with application owners'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# UNDOCUMENTED SERVICE ACCOUNTS
# ================================================================
# Service accounts require:
# 1. Owner/Manager assignment
# 2. Description of purpose
# 3. Contact email for notifications
# 4. Regular password rotation (or gMSA)

# Export for review:
`$findings | Export-Csv -Path 'UndocumentedServiceAccounts.csv' -NoTypeInformation

"@
            # Group by risk
            $critical = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'Critical' }
            $high = $Finding.Findings | Where-Object { $_.RiskLevel -eq 'High' }

            if ($critical) {
                $commands += @"

# ================================================================
# CRITICAL - PRIVILEGED SERVICE ACCOUNTS
# ================================================================
# These service accounts have admin privileges - HIGHEST PRIORITY

"@
                foreach ($item in $critical) {
                    $commands += @"
# Account: $($item.SamAccountName)
# Service Indicators: $($item.ServiceIndicators)
# Missing: $($item.MissingDocumentation)
# SPNs: $($item.SPNs)

# 1. Document the account:
Set-ADUser -Identity '$($item.SamAccountName)' ``
    -Description 'Service account for <PURPOSE>. Owner: <TEAM>. Dependencies: <APPS>' ``
    -Manager '<owner-dn>' ``
    -EmailAddress 'owner@domain.com'

# 2. Review if admin privileges are needed
# 3. Consider gMSA migration:
# New-ADServiceAccount -Name '$($item.SamAccountName)-gMSA' ``
#     -DNSHostName 'host.domain.com' ``
#     -PrincipalsAllowedToRetrieveManagedPassword 'ServerGroup`$'

"@
                }
            }

            if ($high) {
                $commands += @"

# ================================================================
# HIGH RISK - POORLY DOCUMENTED SERVICE ACCOUNTS
# ================================================================

"@
                foreach ($item in $high) {
                    $commands += @"
# Account: $($item.SamAccountName)
# Service Score: $($item.ServiceScore)
# Documentation Score: $($item.DocumentationScore)
# Missing: $($item.MissingDocumentation)
# Password Age: $((New-TimeSpan -Start $item.PasswordLastSet -End (Get-Date)).Days) days

Set-ADUser -Identity '$($item.SamAccountName)' ``
    -Description 'Service account for <PURPOSE>. Owner: <TEAM>' ``
    -Manager '<owner-dn>'

"@
                }
            }

            $commands += @"

# ================================================================
# BEST PRACTICES
# ================================================================

# 1. Create a service account inventory:
Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties * | ``
    Select-Object SamAccountName, Description, Manager, ServicePrincipalName, PasswordLastSet | ``
    Export-Csv 'ServiceAccountInventory.csv' -NoTypeInformation

# 2. Set up service account OU with proper policies:
# New-ADOrganizationalUnit -Name 'Service Accounts' -Path 'DC=domain,DC=com'

# 3. Apply fine-grained password policy for service accounts:
# New-ADFineGrainedPasswordPolicy -Name 'ServiceAccountPolicy' ...

# 4. Review delegations:
Get-ADUser -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation

"@
            return $commands
        }
    }
}
