<#
.SYNOPSIS
    Detects Shadow Credentials attack vectors via msDS-KeyCredentialLink abuse.

.DESCRIPTION
    Identifies accounts with populated msDS-KeyCredentialLink attributes that may indicate
    Shadow Credentials attacks. Also detects accounts with write access to this attribute
    on sensitive targets, enabling the attack.

.NOTES
    Rule ID    : AV-ShadowCredentials
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-ShadowCredentials'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'Shadow Credentials Attack Vector'
    Description = 'Detects potential Shadow Credentials attacks by identifying unexpected values in msDS-KeyCredentialLink and accounts with write access to this attribute on sensitive objects.'
    Severity    = 'Critical'
    Weight      = 80
    DataSource  = 'Users,Computers'

    References  = @(
        @{ Title = 'Shadow Credentials - Elad Shamir'; Url = 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab' }
        @{ Title = 'Whisker - Shadow Credentials Tool'; Url = 'https://github.com/eladshamir/Whisker' }
        @{ Title = 'YOURWAF - Shadow Credentials Detection'; Url = 'https://www.yourwaf.com/2023/12/detecting-shadow-credentials-in-active.html' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0006', 'TA0008')  # Persistence, Credential Access, Lateral Movement
        Techniques = @('T1098', 'T1550.003')  # Account Manipulation, Use Alternate Authentication Material
    }

    CIS   = @('5.18')
    STIG  = @('V-63441')
    ANSSI = @('vuln1_shadow_credentials')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check for unexpected KeyCredentialLink values on user accounts
        if ($Data.Users) {
            foreach ($user in $Data.Users) {
                $keyCredLink = $user.'msDS-KeyCredentialLink'
                if (-not $keyCredLink) {
                    $keyCredLink = $user.Properties['msDS-KeyCredentialLink']
                }

                if ($keyCredLink -and $keyCredLink.Count -gt 0) {
                    # Windows Hello for Business is legitimate, but we should flag for review
                    # Especially on service accounts, admin accounts, or if count is unusual

                    $isServiceAccount = $user.SamAccountName -match '^(svc|service|sql|app|iis|backup)' -or
                                        $user.Description -match 'service'
                    $isAdmin = $user.AdminCount -eq 1 -or
                               $user.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators'
                    $isComputer = $user.ObjectClass -eq 'computer'

                    # Parse key credential info if possible
                    $keyCount = if ($keyCredLink -is [array]) { $keyCredLink.Count } else { 1 }

                    # Flag suspicious scenarios
                    $suspicious = $false
                    $reason = ''

                    if ($isServiceAccount) {
                        $suspicious = $true
                        $reason = 'Service account with KeyCredentialLink (unusual)'
                    } elseif ($isAdmin) {
                        $suspicious = $true
                        $reason = 'Privileged account with KeyCredentialLink (review for legitimacy)'
                    } elseif ($keyCount -gt 2) {
                        $suspicious = $true
                        $reason = "Multiple key credentials present ($keyCount keys)"
                    } elseif (-not $user.Enabled) {
                        $suspicious = $true
                        $reason = 'Disabled account with KeyCredentialLink'
                    }

                    if ($suspicious) {
                        $findings += [PSCustomObject]@{
                            ObjectType          = 'User'
                            SamAccountName      = $user.SamAccountName
                            DisplayName         = $user.DisplayName
                            Enabled             = $user.Enabled
                            AdminCount          = $user.AdminCount
                            KeyCredentialCount  = $keyCount
                            SuspiciousReason    = $reason
                            RiskLevel           = if ($isAdmin) { 'Critical' } else { 'High' }
                            DistinguishedName   = $user.DistinguishedName
                            AttackType          = 'Shadow Credentials Present'
                            Recommendation      = 'Verify if Windows Hello for Business is legitimately configured. Remove unauthorized keys.'
                        }
                    }
                }
            }
        }

        # Check for unexpected KeyCredentialLink values on computer accounts
        if ($Data.Computers) {
            foreach ($computer in $Data.Computers) {
                $keyCredLink = $computer.'msDS-KeyCredentialLink'
                if (-not $keyCredLink) {
                    $keyCredLink = $computer.Properties['msDS-KeyCredentialLink']
                }

                if ($keyCredLink -and $keyCredLink.Count -gt 0) {
                    $isDC = $computer.PrimaryGroupID -eq 516 -or
                            $computer.DistinguishedName -match 'Domain Controllers'
                    $keyCount = if ($keyCredLink -is [array]) { $keyCredLink.Count } else { 1 }

                    # Computers shouldn't normally have KeyCredentialLink
                    # Exception: Azure AD joined devices may have this
                    $suspicious = $true
                    $reason = 'Computer account with KeyCredentialLink'

                    if ($isDC) {
                        $reason = 'CRITICAL: Domain Controller with KeyCredentialLink'
                    } elseif ($keyCount -gt 1) {
                        $reason = "Computer with multiple key credentials ($keyCount keys)"
                    }

                    $findings += [PSCustomObject]@{
                        ObjectType          = 'Computer'
                        SamAccountName      = $computer.SamAccountName
                        DisplayName         = $computer.Name
                        Enabled             = $computer.Enabled
                        IsDomainController  = $isDC
                        KeyCredentialCount  = $keyCount
                        SuspiciousReason    = $reason
                        RiskLevel           = if ($isDC) { 'Critical' } else { 'High' }
                        DistinguishedName   = $computer.DistinguishedName
                        AttackType          = 'Shadow Credentials Present'
                        Recommendation      = 'Computer accounts rarely need KeyCredentialLink. Investigate immediately.'
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove unauthorized msDS-KeyCredentialLink values and investigate potential compromise. Review write permissions to this attribute.'
        Impact      = 'High - Removing legitimate Windows Hello for Business keys will require re-enrollment.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Shadow Credentials Detection - Investigation and Remediation
#############################################################################
#
# Shadow Credentials abuse allows attackers to authenticate as any account
# by adding their own certificate to the msDS-KeyCredentialLink attribute.
#
# This enables:
# - Authentication without knowing the password
# - Persistence across password changes
# - Certificate-based lateral movement
#
#############################################################################

# Affected Accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.SamAccountName): $($_.SuspiciousReason)" } | Out-String)

# Step 1: Investigate each account's KeyCredentialLink values
# Use Whisker or PyWhisker to decode the key credential data

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

#############################################################################
# Account: $($item.SamAccountName)
# Type: $($item.ObjectType)
# Reason: $($item.SuspiciousReason)
#############################################################################

# View current KeyCredentialLink values:
Get-ADObject -Identity '$($item.DistinguishedName)' -Properties 'msDS-KeyCredentialLink' |
    Select-Object -ExpandProperty 'msDS-KeyCredentialLink'

# To remove all KeyCredentialLink values (CAUTION - removes legitimate WHfB keys):
# Set-ADObject -Identity '$($item.DistinguishedName)' -Clear 'msDS-KeyCredentialLink'

# To selectively remove using Whisker (recommended):
# Whisker.exe list /target:$($item.SamAccountName)
# Whisker.exe remove /target:$($item.SamAccountName) /deviceid:<GUID>

"@
            }

            $commands += @"

#############################################################################
# Preventive Measures
#############################################################################

# 1. Audit who has write access to msDS-KeyCredentialLink
`$schemaGUID = 'a2bc3529-8f32-4e03-8a8c-c4f4d9e8e3e3'  # msDS-KeyCredentialLink GUID

# Check sensitive accounts for write permissions
`$sensitiveAccounts = Get-ADUser -Filter { AdminCount -eq 1 } -Properties DistinguishedName

foreach (`$account in `$sensitiveAccounts) {
    `$acl = Get-Acl "AD:\`$(`$account.DistinguishedName)"
    `$dangerousAces = `$acl.Access | Where-Object {
        `$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite' -and
        `$_.AccessControlType -eq 'Allow'
    }
    if (`$dangerousAces) {
        Write-Host "Account: `$(`$account.SamAccountName) has write-capable ACEs" -ForegroundColor Yellow
    }
}

# 2. Enable auditing for attribute changes
# Event ID 5136 - A directory service object was modified

# 3. Consider implementing Protected Users group for privileged accounts
# Protected Users prevents certificate-based authentication

"@
            return $commands
        }
    }
}
