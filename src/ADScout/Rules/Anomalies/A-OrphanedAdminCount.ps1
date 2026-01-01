<#
.SYNOPSIS
    Detects accounts with AdminCount=1 that are not in any privileged group.

.DESCRIPTION
    The AdminCount attribute is set to 1 when an account is added to a
    protected group (Domain Admins, Enterprise Admins, etc.). However,
    AdminCount is NOT automatically cleared when the account is removed
    from these groups. This leaves "orphaned" accounts that:
    - Still have SDProp protection (blocking inheritance)
    - May have residual elevated permissions
    - Indicate historical privilege that should be audited

.NOTES
    Rule ID    : A-OrphanedAdminCount
    Category   : Anomalies
    Author     : AD-Scout
    Version    : 1.0.0

    This is a configuration artifact, not a frequency analysis, but fits
    in Anomalies as it detects an abnormal account state.
#>

@{
    # === IDENTITY ===
    Id          = "A-OrphanedAdminCount"
    Name        = "Orphaned AdminCount Attribute"
    Category    = "Anomalies"
    Model       = "ConfigurationAnomaly"
    Version     = "1.0.0"

    # === SCORING ===
    Computation = "PerDiscover"
    Points      = 2
    MaxPoints   = 20
    Threshold   = $null

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")  # Valid Accounts: Domain
    CIS         = @()
    STIG        = @()
    ANSSI       = @()

    # === THE CHECK ===
    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        # Known privileged group patterns (match on DN)
        $privilegedGroupPatterns = @(
            'CN=Domain Admins,',
            'CN=Enterprise Admins,',
            'CN=Schema Admins,',
            'CN=Administrators,CN=Builtin,',
            'CN=Account Operators,',
            'CN=Backup Operators,',
            'CN=Server Operators,',
            'CN=Print Operators,',
            'CN=Replicator,',
            'CN=Domain Controllers,'
        )

        # Find users with AdminCount=1
        $adminCountUsers = @($ADData.Users | Where-Object {
            $_.AdminCount -eq 1 -and $_.Enabled -eq $true
        })

        if ($adminCountUsers.Count -eq 0) {
            Write-Verbose "No users with AdminCount=1 found"
            return @()
        }

        # Check each AdminCount user for current privileged group membership
        $adminCountUsers | Where-Object {
            $memberOf = @($_.MemberOf)

            # Check if user is in ANY privileged group
            $isPrivileged = $false
            foreach ($group in $memberOf) {
                foreach ($pattern in $privilegedGroupPatterns) {
                    if ($group -like "*$pattern*") {
                        $isPrivileged = $true
                        break
                    }
                }
                if ($isPrivileged) { break }
            }

            # Return users who are NOT currently privileged but have AdminCount=1
            -not $isPrivileged
        } | ForEach-Object {
            $groupCount = @($_.MemberOf).Count

            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                DisplayName       = $_.DisplayName
                AdminCount        = $_.AdminCount
                CurrentGroupCount = $groupCount
                WhenChanged       = $_.WhenChanged
                Description       = $_.Description
                Severity          = 'Medium'
            }
        }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "AdminCount", "CurrentGroupCount", "WhenChanged")
    DetailFormat     = "{SamAccountName}: AdminCount=1 but not in privileged groups ({CurrentGroupCount} groups)"

    # === REMEDIATION ===
    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Orphaned AdminCount for: $($Finding.SamAccountName)
# AdminCount is set but user is not in any privileged groups

# STEP 1: Verify user was intentionally removed from privileged groups
# Check security logs or change history

# STEP 2: Clear the AdminCount attribute:
Set-ADUser -Identity '$($Finding.SamAccountName)' -Clear AdminCount

# STEP 3: Reset permissions inheritance (SDProp blocks inheritance):
# Use ADSI Edit or:
`$user = Get-ADUser -Identity '$($Finding.SamAccountName)'
`$acl = Get-Acl "AD:`$(`$user.DistinguishedName)"
`$acl.SetAccessRuleProtection(`$false, `$true)
Set-Acl -Path "AD:`$(`$user.DistinguishedName)" -AclObject `$acl

# STEP 4: Force SDProp to run (optional, will happen within 60 mins):
# On a DC: Invoke-Command { rundll32 dsutils.dll,RunSecurityDiagnosticS }

"@
    }

    # === DOCUMENTATION ===
    Description = "Accounts with AdminCount=1 that are no longer members of any privileged group."

    TechnicalExplanation = @"
The Security Descriptor Propagator (SDProp) process sets AdminCount=1 on
accounts added to protected groups (Domain Admins, Enterprise Admins, etc.).
This also applies special permissions that block inheritance.

The problem: When an account is REMOVED from privileged groups, AdminCount
is NOT automatically cleared. This creates "orphaned" accounts that:

1. Still have AdminCount=1 (indicating historical privilege)
2. Still have SDProp-applied permissions (blocking inheritance)
3. May have residual elevated access from their privileged period
4. Don't receive permission updates that propagate via inheritance

Security implications:
- Historical privilege indicator: These accounts WERE privileged
- Permission drift: May retain access from their privileged period
- Audit trail: Indicates privilege changes that should be reviewed
- Cleanup needed: AdminCount should be manually cleared

This rule finds accounts where AdminCount=1 but they're not currently
in any of the standard protected groups.
"@

    References = @(
        "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
        "https://adsecurity.org/?p=1906"
        "https://blog.youracclaim.com/2019/10/28/understanding-sdprop-admincount-and-adminsdholder/"
    )

    # === PREREQUISITES ===
    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.Users -and $ADData.Users.Count -gt 0
    }

    AppliesTo = @("OnPremises", "Hybrid")
}
