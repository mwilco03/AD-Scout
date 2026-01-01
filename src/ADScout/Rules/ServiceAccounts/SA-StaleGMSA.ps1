<#
.SYNOPSIS
    Detects stale or misconfigured Group Managed Service Accounts (gMSAs).

.DESCRIPTION
    gMSAs provide secure service account management but can become security risks
    if stale, misconfigured, or have overly permissive password retrieval groups.
    This rule checks for gMSA security issues.

.NOTES
    Rule ID    : SA-StaleGMSA
    Category   : ServiceAccounts
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'SA-StaleGMSA'
    Version     = '1.0.0'
    Category    = 'ServiceAccounts'
    Title       = 'Stale or Misconfigured gMSA'
    Description = 'Identifies Group Managed Service Accounts that are stale, unused, or have overly permissive password retrieval configurations.'
    Severity    = 'Medium'
    Weight      = 40
    DataSource  = 'ServiceAccounts'

    References  = @(
        @{ Title = 'gMSA Overview'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview' }
        @{ Title = 'gMSA Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts' }
        @{ Title = 'Golden gMSA Attack'; Url = 'https://www.semperis.com/blog/golden-gmsa-attack/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0003')  # Credential Access, Persistence
        Techniques = @('T1078.002', 'T1555')  # Domain Accounts, Credentials from Password Stores
    }

    CIS   = @('5.6')
    STIG  = @('V-254454')
    ANSSI = @('R47')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            # Get all gMSAs
            $gmsas = Get-ADServiceAccount -Filter { objectClass -eq 'msDS-GroupManagedServiceAccount' } `
                -Properties * -ErrorAction SilentlyContinue

            foreach ($gmsa in $gmsas) {
                $issues = @()
                $riskLevel = 'Low'

                # Check if gMSA is enabled
                if (-not $gmsa.Enabled) {
                    $issues += 'gMSA is disabled'
                }

                # Check last password change
                if ($gmsa.PasswordLastSet) {
                    $pwdAge = ((Get-Date) - $gmsa.PasswordLastSet).Days
                    # gMSA passwords should rotate every 30 days by default
                    if ($pwdAge -gt 60) {
                        $issues += "Password not rotated in $pwdAge days"
                        $riskLevel = 'Medium'
                    }
                }

                # Check last logon
                if ($gmsa.LastLogonDate) {
                    $daysSinceLogon = ((Get-Date) - $gmsa.LastLogonDate).Days
                    if ($daysSinceLogon -gt 90) {
                        $issues += "Not used in $daysSinceLogon days (stale)"
                        $riskLevel = 'Medium'
                    }
                } else {
                    $issues += 'Never logged on (unused)'
                }

                # Check PrincipalsAllowedToRetrieveManagedPassword
                $allowedPrincipals = $gmsa.'PrincipalsAllowedToRetrieveManagedPassword'
                if ($allowedPrincipals) {
                    $principalCount = $allowedPrincipals.Count

                    # Check for overly permissive groups
                    foreach ($principal in $allowedPrincipals) {
                        try {
                            $obj = Get-ADObject -Identity $principal -Properties objectClass, Name -ErrorAction SilentlyContinue
                            if ($obj.objectClass -eq 'group') {
                                $group = Get-ADGroup -Identity $principal -Properties Members -ErrorAction SilentlyContinue
                                $memberCount = (Get-ADGroupMember -Identity $principal -Recursive -ErrorAction SilentlyContinue).Count

                                if ($memberCount -gt 10) {
                                    $issues += "Large group can retrieve password: $($group.Name) ($memberCount members)"
                                    $riskLevel = 'High'
                                }

                                # Check for dangerous groups
                                if ($group.Name -match 'Domain Computers|Authenticated Users|Everyone|Domain Users') {
                                    $issues += "Dangerous group can retrieve password: $($group.Name)"
                                    $riskLevel = 'Critical'
                                }
                            }
                        } catch {}
                    }

                    if ($principalCount -gt 5) {
                        $issues += "Too many principals can retrieve password ($principalCount)"
                        $riskLevel = 'Medium'
                    }
                } else {
                    $issues += 'No principals configured to retrieve password'
                }

                # Check if gMSA has SPNs (Kerberoasting surface)
                if ($gmsa.ServicePrincipalName.Count -gt 0) {
                    # gMSAs with SPNs are technically Kerberoastable but password is strong
                    # Still worth noting for awareness
                }

                # Check KDS root key age (affects all gMSAs)
                # This is checked separately in AV-GoldenGMSA

                if ($issues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        AccountName              = $gmsa.SamAccountName
                        DisplayName              = $gmsa.DisplayName
                        Enabled                  = $gmsa.Enabled
                        Created                  = $gmsa.Created
                        PasswordLastSet          = $gmsa.PasswordLastSet
                        LastLogonDate            = $gmsa.LastLogonDate
                        SPNCount                 = $gmsa.ServicePrincipalName.Count
                        AllowedPrincipals        = ($allowedPrincipals | ForEach-Object { (Get-ADObject $_ -ErrorAction SilentlyContinue).Name }) -join '; '
                        Issues                   = ($issues -join '; ')
                        RiskLevel                = $riskLevel
                        DistinguishedName        = $gmsa.DistinguishedName
                    }
                }
            }

            # Check for sMSAs (standalone Managed Service Accounts) - legacy
            $smsas = Get-ADServiceAccount -Filter { objectClass -eq 'msDS-ManagedServiceAccount' } `
                -Properties * -ErrorAction SilentlyContinue

            foreach ($smsa in $smsas) {
                $findings += [PSCustomObject]@{
                    AccountName              = $smsa.SamAccountName
                    DisplayName              = $smsa.DisplayName
                    Enabled                  = $smsa.Enabled
                    Created                  = $smsa.Created
                    PasswordLastSet          = $smsa.PasswordLastSet
                    LastLogonDate            = $smsa.LastLogonDate
                    SPNCount                 = $smsa.ServicePrincipalName.Count
                    AllowedPrincipals        = 'N/A (sMSA)'
                    Issues                   = 'Legacy sMSA - consider migrating to gMSA'
                    RiskLevel                = 'Low'
                    DistinguishedName        = $smsa.DistinguishedName
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                AccountName              = 'Error'
                DisplayName              = 'Check Failed'
                Enabled                  = 'N/A'
                Created                  = 'N/A'
                PasswordLastSet          = 'N/A'
                LastLogonDate            = 'N/A'
                SPNCount                 = 0
                AllowedPrincipals        = 'N/A'
                Issues                   = "Check failed: $_"
                RiskLevel                = 'Unknown'
                DistinguishedName        = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and remediate gMSA configurations, remove stale accounts, and restrict password retrieval.'
        Impact      = 'Low - gMSA cleanup does not affect running services if done carefully.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# gMSA Security Remediation
#############################################################################
#
# Group Managed Service Accounts are more secure than regular service accounts
# but still require proper configuration and lifecycle management.
#
# Issues identified:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Inventory All gMSAs
#############################################################################

Get-ADServiceAccount -Filter * -Properties * |
    Select-Object Name, SamAccountName, Enabled, Created, PasswordLastSet, LastLogonDate,
        @{N='AllowedPrincipals';E={`$_.PrincipalsAllowedToRetrieveManagedPassword.Count}},
        @{N='SPNs';E={`$_.ServicePrincipalName.Count}} |
    Format-Table -AutoSize

#############################################################################
# Step 2: Remove Stale gMSAs
#############################################################################

# Find gMSAs not used in 90+ days:
`$staleGMSAs = Get-ADServiceAccount -Filter * -Properties LastLogonDate | Where-Object {
    `$_.LastLogonDate -lt (Get-Date).AddDays(-90) -or `$_.LastLogonDate -eq `$null
}

Write-Host "Stale gMSAs:" -ForegroundColor Yellow
`$staleGMSAs | Select-Object Name, LastLogonDate | Format-Table

# To remove (verify not in use first!):
# foreach (`$gmsa in `$staleGMSAs) {
#     # Check if service is running with this account
#     # Remove-ADServiceAccount -Identity `$gmsa.SamAccountName -Confirm:`$false
# }

#############################################################################
# Step 3: Restrict Password Retrieval
#############################################################################

# For each gMSA, limit who can retrieve the password:

`$gmsaName = "gMSA_ServiceName"  # Replace with actual name

# Create a dedicated group for this gMSA's hosts:
# New-ADGroup -Name "gMSA_ServiceName_Hosts" -GroupScope DomainLocal -Path "OU=Groups,DC=domain,DC=com"

# Get current allowed principals:
Get-ADServiceAccount -Identity `$gmsaName -Properties PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword |
    ForEach-Object { Get-ADObject -Identity `$_ | Select-Object Name, ObjectClass }

# Set restrictive principals:
# Set-ADServiceAccount -Identity `$gmsaName -PrincipalsAllowedToRetrieveManagedPassword "gMSA_ServiceName_Hosts"

#############################################################################
# Step 4: Verify Password Rotation
#############################################################################

# gMSA passwords should rotate automatically every 30 days
# If not rotating, check KDS Root Key and DC replication

Get-ADServiceAccount -Filter * -Properties PasswordLastSet |
    Select-Object Name, PasswordLastSet,
        @{N='DaysOld';E={((Get-Date) - `$_.PasswordLastSet).Days}} |
    Where-Object { `$_.DaysOld -gt 35 } |
    Format-Table -AutoSize

# Check KDS Root Key:
Get-KdsRootKey | Select-Object KeyId, CreationTime, EffectiveTime

#############################################################################
# Step 5: Document gMSA Usage
#############################################################################

# For each gMSA, document:
# - Which service uses it
# - Which server(s) run the service
# - Business owner
# - When it was last reviewed

# Export inventory:
Get-ADServiceAccount -Filter * -Properties * |
    Select-Object Name, Description, Created, PasswordLastSet, LastLogonDate,
        @{N='AllowedPrincipals';E={
            (`$_.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object {
                (Get-ADObject `$_ -ErrorAction SilentlyContinue).Name
            }) -join ','
        }} |
    Export-Csv -Path "C:\Reports\gMSA_Inventory.csv" -NoTypeInformation

#############################################################################
# Step 6: Migrate from sMSAs to gMSAs
#############################################################################

# sMSAs (standalone) should be migrated to gMSAs for better security:
# 1. Create new gMSA with same SPNs
# 2. Update service to use gMSA
# 3. Remove old sMSA

Get-ADServiceAccount -Filter { objectClass -eq 'msDS-ManagedServiceAccount' } |
    Select-Object Name, SamAccountName |
    Format-Table -AutoSize

"@
            return $commands
        }
    }
}
