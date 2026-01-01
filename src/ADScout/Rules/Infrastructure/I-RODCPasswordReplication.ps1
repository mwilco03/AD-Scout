<#
.SYNOPSIS
    Detects insecure RODC password replication policies.

.DESCRIPTION
    Read-Only Domain Controllers should not cache passwords for privileged accounts.
    Weak password replication policies can expose admin credentials if an RODC is
    compromised.

.NOTES
    Rule ID    : I-RODCPasswordReplication
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-RODCPasswordReplication'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'RODC Password Replication Policy Weaknesses'
    Description = 'Identifies Read-Only Domain Controllers with password replication policies that may cache privileged account credentials.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'RODC Password Replication'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/rodc-technical-reference' }
        @{ Title = 'RODC Security'; Url = 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc730883(v=ws.10)' }
        @{ Title = 'RODC Attack Surface'; Url = 'https://adsecurity.org/?p=3592' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1003', 'T1558')   # Credential Dumping, Kerberos Tickets
    }

    CIS   = @('5.1')
    STIG  = @('V-36432')
    ANSSI = @('R50')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Groups that should NEVER be in RODC Allowed list
        $prohibitedInAllowed = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Domain Controllers'
            'Account Operators'
            'Backup Operators'
            'Server Operators'
        )

        if ($Data.DomainControllers) {
            $rodcs = $Data.DomainControllers | Where-Object {
                $_.IsReadOnly -eq $true -or
                $_.DistinguishedName -notmatch 'Domain Controllers'  # RODCs are often in different OU
            }

            foreach ($rodc in $rodcs) {
                $rodcName = $rodc.Name
                if (-not $rodcName) { $rodcName = $rodc.DnsHostName }
                if (-not $rodcName) { continue }

                try {
                    # Get RODC's managed-by and password replication policy
                    $rodcObj = Get-ADDomainController -Identity $rodcName -ErrorAction SilentlyContinue

                    if (-not $rodcObj.IsReadOnly) { continue }

                    # Get Password Replication Policy
                    $allowedList = (Get-ADDomainControllerPasswordReplicationPolicy -Identity $rodcName -Allowed -ErrorAction SilentlyContinue).Name
                    $deniedList = (Get-ADDomainControllerPasswordReplicationPolicy -Identity $rodcName -Denied -ErrorAction SilentlyContinue).Name

                    $issues = @()

                    # Check if prohibited groups are in Allowed list
                    foreach ($prohibited in $prohibitedInAllowed) {
                        if ($allowedList -contains $prohibited) {
                            $issues += "Prohibited group in Allowed list: $prohibited"
                        }
                    }

                    # Check if prohibited groups are NOT in Denied list
                    foreach ($prohibited in $prohibitedInAllowed) {
                        if ($deniedList -notcontains $prohibited) {
                            # This is less critical but still a concern
                            $issues += "Privileged group not explicitly denied: $prohibited"
                        }
                    }

                    # Check for overly permissive allowed list
                    if ($allowedList -contains 'Authenticated Users' -or
                        $allowedList -contains 'Domain Users' -or
                        $allowedList -contains 'Everyone') {
                        $issues += "Overly permissive Allowed list: caches too many passwords"
                    }

                    # Get cached password count
                    $cachedPasswords = (Get-ADDomainControllerPasswordReplicationPolicyUsage -Identity $rodcName -RevealedAccounts -ErrorAction SilentlyContinue).Count

                    if ($issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            RODC                = $rodcName
                            Issues              = ($issues -join '; ')
                            AllowedGroups       = if ($allowedList) { ($allowedList -join ', ') } else { 'None configured' }
                            DeniedGroups        = if ($deniedList) { ($deniedList -join ', ') } else { 'None configured' }
                            CachedPasswords     = $cachedPasswords
                            RiskLevel           = if ($issues -match 'Prohibited') { 'Critical' } else { 'High' }
                            Impact              = 'Compromised RODC could expose privileged credentials'
                            DistinguishedName   = $rodc.DistinguishedName
                        }
                    }

                } catch {
                    # Can't check this RODC
                }
            }
        }

        # Also check default RODC password replication groups
        try {
            # Check Allowed RODC Password Replication Group
            $allowedGroup = Get-ADGroup -Identity 'Allowed RODC Password Replication Group' -Properties Members -ErrorAction SilentlyContinue

            if ($allowedGroup -and $allowedGroup.Members) {
                foreach ($memberDN in $allowedGroup.Members) {
                    try {
                        $member = Get-ADObject -Identity $memberDN -Properties ObjectClass
                        $memberName = ($memberDN -split ',')[0] -replace 'CN='

                        # Check if privileged group or user is in allowed group
                        if ($memberName -in $prohibitedInAllowed) {
                            $findings += [PSCustomObject]@{
                                RODC                = 'Global Policy'
                                Issues              = "Privileged group in Allowed RODC Password Replication Group: $memberName"
                                AllowedGroups       = 'Check group membership'
                                DeniedGroups        = 'N/A'
                                CachedPasswords     = 'Varies by RODC'
                                RiskLevel           = 'Critical'
                                Impact              = 'All RODCs may cache this privileged account password'
                                DistinguishedName   = $allowedGroup.DistinguishedName
                            }
                        }
                    } catch {}
                }
            }
        } catch {}

        return $findings
    }

    Remediation = @{
        Description = 'Configure RODC password replication policy to deny privileged accounts and allow only branch office users.'
        Impact      = 'Medium - Users not in Allowed list cannot authenticate via RODC when WAN is down.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# RODC Password Replication Policy Remediation
#############################################################################
#
# RODCs are designed for branch offices with less physical security.
# If compromised, attackers can extract cached password hashes.
#
# Security principle: NEVER cache privileged passwords on RODCs
#
# Issues Found:
$($Finding.Findings | ForEach-Object { "# - $($_.RODC): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Verify Default Denied Groups
#############################################################################

# These groups should be in the Denied RODC Password Replication Group:
`$requiredDenied = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Backup Operators'
    'Server Operators'
    'Domain Controllers'
    'Read-only Domain Controllers'
    'krbtgt'
)

`$deniedGroup = Get-ADGroup -Identity 'Denied RODC Password Replication Group'

foreach (`$account in `$requiredDenied) {
    `$member = Get-ADGroupMember -Identity `$deniedGroup | Where-Object { `$_.Name -eq `$account }
    if (-not `$member) {
        Write-Host "Adding `$account to Denied group" -ForegroundColor Yellow
        Add-ADGroupMember -Identity `$deniedGroup -Members `$account -ErrorAction SilentlyContinue
    }
}

#############################################################################
# Step 2: Clean Up Allowed Group
#############################################################################

# Remove privileged accounts from Allowed group
`$allowedGroup = Get-ADGroup -Identity 'Allowed RODC Password Replication Group' -Properties Members

`$prohibitedAccounts = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
)

foreach (`$memberDN in `$allowedGroup.Members) {
    `$memberName = (`$memberDN -split ',')[0] -replace 'CN='
    if (`$memberName -in `$prohibitedAccounts) {
        Write-Host "Removing `$memberName from Allowed group" -ForegroundColor Red
        Remove-ADGroupMember -Identity `$allowedGroup -Members `$memberDN -Confirm:`$false
    }
}

#############################################################################
# Step 3: Configure Per-RODC Policies
#############################################################################

"@

            foreach ($item in $Finding.Findings | Where-Object { $_.RODC -ne 'Global Policy' }) {
                $commands += @"

# Configure RODC: $($item.RODC)
`$rodc = '$($item.RODC)'

# Remove privileged groups from allowed list
`$prohibitedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')

foreach (`$group in `$prohibitedGroups) {
    Remove-ADDomainControllerPasswordReplicationPolicy -Identity `$rodc -AllowedList `$group -ErrorAction SilentlyContinue
}

# Add privileged groups to denied list
foreach (`$group in `$prohibitedGroups) {
    Add-ADDomainControllerPasswordReplicationPolicy -Identity `$rodc -DeniedList `$group -ErrorAction SilentlyContinue
}

"@
            }

            $commands += @"

#############################################################################
# Step 4: Review Cached Passwords
#############################################################################

# View accounts with cached passwords on each RODC
Get-ADDomainController -Filter { IsReadOnly -eq `$true } | ForEach-Object {
    Write-Host "`n=== `$(`$_.Name) ===" -ForegroundColor Cyan

    `$cached = Get-ADDomainControllerPasswordReplicationPolicyUsage -Identity `$_.Name -RevealedAccounts -ErrorAction SilentlyContinue
    `$cached | Select-Object Name, ObjectClass, DistinguishedName | Format-Table

    Write-Host "Total cached: `$(`$cached.Count)" -ForegroundColor Yellow
}

# Check for privileged accounts in cache
Get-ADDomainController -Filter { IsReadOnly -eq `$true } | ForEach-Object {
    `$cached = Get-ADDomainControllerPasswordReplicationPolicyUsage -Identity `$_.Name -RevealedAccounts -ErrorAction SilentlyContinue

    `$privileged = `$cached | Where-Object {
        (Get-ADUser -Identity `$_.DistinguishedName -Properties AdminCount -ErrorAction SilentlyContinue).AdminCount -eq 1
    }

    if (`$privileged) {
        Write-Host "WARNING: `$(`$_.Name) has cached privileged accounts:" -ForegroundColor Red
        `$privileged | Select-Object Name
    }
}

#############################################################################
# Step 5: Clear Cached Privileged Passwords
#############################################################################

# If privileged passwords are cached, reset them immediately
# The RODC cache cannot be directly cleared - passwords must be changed

# Reset passwords for affected privileged accounts:
# Set-ADAccountPassword -Identity 'AdminAccount' -Reset -NewPassword (Read-Host -AsSecureString)

#############################################################################
# Best Practices for RODC Deployment
#############################################################################

# 1. Create branch-specific groups for RODC password caching
#    Example: "NYC Branch Users" -> Add to Allowed list for NYC RODC

# 2. Never add Domain Users or Authenticated Users to Allowed list

# 3. All administrative accounts should be in Denied list

# 4. Use separate krbtgt_XXXXX accounts per RODC (default behavior)

# 5. Physically secure RODCs as much as possible

# 6. Monitor RODC for unauthorized access

"@
            return $commands
        }
    }
}
