@{
    Id          = 'E-ExcessiveDelegation'
    Version     = '1.0.0'
    Category    = 'Email'
    Title       = 'Mailbox with Excessive Delegations'
    Description = 'Detects mailboxes with an unusually high number of delegated permissions. Many delegates increase attack surface and make it difficult to track who accessed the mailbox.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Mailboxes'

    References  = @(
        @{ Title = 'Principle of Least Privilege'; Url = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0003')  # Initial Access, Persistence
        Techniques = @('T1078.002')          # Valid Accounts: Domain Accounts
    }

    CIS   = @('6.3.4')
    STIG  = @('O365-EX-000005')
    ANSSI = @()

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Aggregate all permissions by mailbox
        $allPermissions = @{}

        # Full Access
        foreach ($perm in $Data.MailboxPermissions) {
            $key = $perm.MailboxAddress
            if (-not $allPermissions.ContainsKey($key)) {
                $allPermissions[$key] = @{
                    DisplayName  = $perm.DisplayName
                    FullAccess   = @()
                    SendAs       = @()
                    SendOnBehalf = @()
                }
            }
            $allPermissions[$key].FullAccess += $perm.Trustee
        }

        # Send As
        foreach ($perm in $Data.SendAsPermissions) {
            $key = $perm.MailboxAddress
            if (-not $allPermissions.ContainsKey($key)) {
                $allPermissions[$key] = @{
                    DisplayName  = $perm.DisplayName
                    FullAccess   = @()
                    SendAs       = @()
                    SendOnBehalf = @()
                }
            }
            $allPermissions[$key].SendAs += $perm.Trustee
        }

        # Send on Behalf
        foreach ($perm in $Data.SendOnBehalfPermissions) {
            $key = $perm.MailboxAddress
            if (-not $allPermissions.ContainsKey($key)) {
                $allPermissions[$key] = @{
                    DisplayName  = $perm.DisplayName
                    FullAccess   = @()
                    SendAs       = @()
                    SendOnBehalf = @()
                }
            }
            $allPermissions[$key].SendOnBehalf += $perm.Delegate
        }

        # Threshold for excessive delegations
        $threshold = 5

        foreach ($mailbox in $allPermissions.Keys) {
            $perms = $allPermissions[$mailbox]
            $totalDelegates = (
                ($perms.FullAccess | Select-Object -Unique).Count +
                ($perms.SendAs | Select-Object -Unique).Count +
                ($perms.SendOnBehalf | Select-Object -Unique).Count
            )

            $uniqueDelegates = ($perms.FullAccess + $perms.SendAs + $perms.SendOnBehalf |
                Select-Object -Unique).Count

            if ($uniqueDelegates -gt $threshold) {
                $findings += [PSCustomObject]@{
                    MailboxAddress          = $mailbox
                    MailboxDisplayName      = $perms.DisplayName
                    TotalPermissions        = $totalDelegates
                    UniqueDelegates         = $uniqueDelegates
                    FullAccessDelegates     = ($perms.FullAccess -join '; ')
                    SendAsDelegates         = ($perms.SendAs -join '; ')
                    SendOnBehalfDelegates   = ($perms.SendOnBehalf -join '; ')
                    Threshold               = $threshold
                    ExcessCount             = $uniqueDelegates - $threshold
                    RiskLevel               = if ($uniqueDelegates -gt 10) { 'Critical' }
                                             elseif ($uniqueDelegates -gt 7) { 'High' }
                                             else { 'Medium' }
                }
            }
        }

        return $findings | Sort-Object -Property UniqueDelegates -Descending
    }

    Remediation = @{
        Description = 'Review and consolidate mailbox permissions. Consider using distribution groups or shared mailboxes instead of individual delegations.'
        Impact      = 'Medium - Requires coordination to remove excess permissions'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# EXCESSIVE MAILBOX DELEGATION REVIEW
# ================================================================
# Mailboxes with many delegates are:
# - Hard to audit and monitor
# - Increased attack surface
# - Potential data leak vectors

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# ================================================================
# Mailbox: $($item.MailboxDisplayName) <$($item.MailboxAddress)>
# Unique Delegates: $($item.UniqueDelegates) (Threshold: $($item.Threshold))
# Risk Level: $($item.RiskLevel)
# ================================================================

# Full Access ($( ($item.FullAccessDelegates -split ';').Count ) users):
#   $($item.FullAccessDelegates)

# Send As ($( ($item.SendAsDelegates -split ';').Count ) users):
#   $($item.SendAsDelegates)

# Send on Behalf ($( ($item.SendOnBehalfDelegates -split ';').Count ) users):
#   $($item.SendOnBehalfDelegates)

# RECOMMENDATION: Consider converting to a Shared Mailbox with defined owners
# Convert-Mailbox -Identity '$($item.MailboxAddress)' -Type Shared

"@
            }

            return $commands
        }
    }
}
