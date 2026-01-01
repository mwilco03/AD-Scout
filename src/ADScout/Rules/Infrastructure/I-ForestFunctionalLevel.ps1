<#
.SYNOPSIS
    Detects outdated forest and domain functional levels.

.DESCRIPTION
    Older functional levels lack modern security features like Protected Users
    group, Authentication Policies, and Compound Identity. This rule checks
    for outdated functional levels.

.NOTES
    Rule ID    : I-ForestFunctionalLevel
    Category   : Infrastructure
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'I-ForestFunctionalLevel'
    Version     = '1.0.0'
    Category    = 'Infrastructure'
    Title       = 'Outdated Forest/Domain Functional Level'
    Description = 'Identifies forests and domains running at outdated functional levels that lack modern security features.'
    Severity    = 'Medium'
    Weight      = 35
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'Forest Functional Levels'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels' }
        @{ Title = 'Windows Server 2016 AD Features'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/whats-new-active-directory-domain-services' }
        @{ Title = 'Protected Users'; Url = 'https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.001')  # Impair Defenses: Disable or Modify Tools
    }

    CIS   = @('9.2')
    STIG  = @('V-254453')
    ANSSI = @('R46')

    Scoring = @{
        Type    = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Functional level mapping
        $levelMap = @{
            0 = 'Windows 2000'
            1 = 'Windows Server 2003 Interim'
            2 = 'Windows Server 2003'
            3 = 'Windows Server 2008'
            4 = 'Windows Server 2008 R2'
            5 = 'Windows Server 2012'
            6 = 'Windows Server 2012 R2'
            7 = 'Windows Server 2016'
            # 8 = 'Windows Server 2019' (same as 2016)
            # 9 = 'Windows Server 2022' (same as 2016)
        }

        # Security features by functional level
        $securityFeatures = @{
            0 = @()
            1 = @()
            2 = @('lastLogonTimestamp replication')
            3 = @('AES for Kerberos', 'Fine-Grained Password Policies')
            4 = @('Managed Service Accounts', 'Authentication Assurance')
            5 = @('Compound Identity', 'KDC support for claims')
            6 = @('Protected Users group', 'Authentication Policies', 'Domain-joined MSAs')
            7 = @('Privileged Access Management', 'gMSA enhancements', 'Key Trust Kerberos')
        }

        try {
            # Get domain functional level
            $domainInfo = Get-ADDomain -ErrorAction SilentlyContinue
            $domainFL = $domainInfo.DomainMode

            # Get forest functional level
            $forestInfo = Get-ADForest -ErrorAction SilentlyContinue
            $forestFL = $forestInfo.ForestMode

            # Convert to level number if string
            $domainLevel = switch -Regex ($domainFL) {
                'Windows2000' { 0 }
                'Windows2003Interim' { 1 }
                'Windows2003' { 2 }
                'Windows2008' { 3 }
                'Windows2008R2' { 4 }
                'Windows2012' { 5 }
                'Windows2012R2' { 6 }
                'Windows2016' { 7 }
                default {
                    if ($_ -match '(\d+)') { [int]$Matches[1] } else { 7 }
                }
            }

            $forestLevel = switch -Regex ($forestFL) {
                'Windows2000' { 0 }
                'Windows2003Interim' { 1 }
                'Windows2003' { 2 }
                'Windows2008' { 3 }
                'Windows2008R2' { 4 }
                'Windows2012' { 5 }
                'Windows2012R2' { 6 }
                'Windows2016' { 7 }
                default {
                    if ($_ -match '(\d+)') { [int]$Matches[1] } else { 7 }
                }
            }

            # Check domain functional level
            if ($domainLevel -lt 6) {
                $issues = @()
                $missingFeatures = @()

                for ($i = $domainLevel + 1; $i -le 7; $i++) {
                    if ($securityFeatures[$i]) {
                        $missingFeatures += $securityFeatures[$i]
                    }
                }

                $issues += "Domain at $($levelMap[$domainLevel]) level"
                $issues += "Missing features: $($missingFeatures -join ', ')"

                $riskLevel = switch ($domainLevel) {
                    { $_ -le 3 } { 'Critical' }  # 2008 or older
                    { $_ -le 4 } { 'High' }      # 2008 R2
                    { $_ -le 5 } { 'Medium' }    # 2012
                    default { 'Low' }
                }

                $findings += [PSCustomObject]@{
                    Level             = 'Domain'
                    Name              = $domainInfo.DNSRoot
                    FunctionalLevel   = $levelMap[$domainLevel]
                    CurrentLevel      = $domainLevel
                    RecommendedLevel  = 7
                    MissingFeatures   = ($missingFeatures -join '; ')
                    Issues            = ($issues -join '; ')
                    RiskLevel         = $riskLevel
                    Note              = if ($domainLevel -lt 6) { 'Protected Users group not available' } else { '' }
                    DistinguishedName = $domainInfo.DistinguishedName
                }
            }

            # Check forest functional level
            if ($forestLevel -lt 6) {
                $issues = @()
                $missingFeatures = @()

                for ($i = $forestLevel + 1; $i -le 7; $i++) {
                    if ($securityFeatures[$i]) {
                        $missingFeatures += $securityFeatures[$i]
                    }
                }

                $issues += "Forest at $($levelMap[$forestLevel]) level"

                $riskLevel = switch ($forestLevel) {
                    { $_ -le 3 } { 'Critical' }
                    { $_ -le 4 } { 'High' }
                    { $_ -le 5 } { 'Medium' }
                    default { 'Low' }
                }

                $findings += [PSCustomObject]@{
                    Level             = 'Forest'
                    Name              = $forestInfo.Name
                    FunctionalLevel   = $levelMap[$forestLevel]
                    CurrentLevel      = $forestLevel
                    RecommendedLevel  = 7
                    MissingFeatures   = ($missingFeatures -join '; ')
                    Issues            = ($issues -join '; ')
                    RiskLevel         = $riskLevel
                    Note              = 'Forest level limits domain level'
                    DistinguishedName = "CN=Partitions,CN=Configuration,$($domainInfo.DistinguishedName)"
                }
            }

            # Check for DCs that are blocking upgrade
            $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue

            foreach ($dc in $dcs) {
                $osVersion = $dc.OperatingSystemVersion
                $dcLevel = switch -Regex ($dc.OperatingSystem) {
                    '2000' { 0 }
                    '2003' { 2 }
                    '2008 R2' { 4 }
                    '2008' { 3 }
                    '2012 R2' { 6 }
                    '2012' { 5 }
                    '2016|2019|2022' { 7 }
                    default { 7 }
                }

                if ($dcLevel -lt 6) {
                    $findings += [PSCustomObject]@{
                        Level             = 'DomainController'
                        Name              = $dc.HostName
                        FunctionalLevel   = $dc.OperatingSystem
                        CurrentLevel      = $dcLevel
                        RecommendedLevel  = 7
                        MissingFeatures   = 'Old DC blocking functional level upgrade'
                        Issues            = "DC running $($dc.OperatingSystem)"
                        RiskLevel         = 'High'
                        Note              = 'Must upgrade or demote before raising functional level'
                        DistinguishedName = $dc.ComputerObjectDN
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                Level             = 'Error'
                Name              = 'Check Failed'
                FunctionalLevel   = 'Unknown'
                CurrentLevel      = 0
                RecommendedLevel  = 7
                MissingFeatures   = 'Unknown'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                Note              = 'Manual verification required'
                DistinguishedName = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Raise forest and domain functional levels to enable modern security features.'
        Impact      = 'Low - Raising levels is non-destructive, but cannot be reversed.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Forest and Domain Functional Level Upgrade
#############################################################################
#
# Raising functional levels enables critical security features:
# - 2012 R2: Protected Users group, Authentication Policies
# - 2016: Privileged Access Management, Key Trust Kerberos
#
# Current status:
$($Finding.Findings | ForEach-Object { "# - $($_.Level) '$($_.Name)': $($_.FunctionalLevel)" } | Out-String)

#############################################################################
# Prerequisites
#############################################################################

# 1. ALL Domain Controllers must run Windows Server version >= target level
# 2. Schema must be updated (adprep /forestprep and /domainprep)
# 3. Backup AD before making changes
# 4. Raising levels cannot be reversed!

# Check current DC operating systems:
Get-ADDomainController -Filter * |
    Select-Object Name, OperatingSystem, OperatingSystemVersion |
    Format-Table -AutoSize

#############################################################################
# Step 1: Verify All DCs Are Current Version
#############################################################################

# All DCs must be at or above the target functional level's minimum OS:
# - 2012 R2 Level: Requires Server 2012 R2 or later
# - 2016 Level: Requires Server 2016 or later

`$oldDCs = Get-ADDomainController -Filter * | Where-Object {
    `$_.OperatingSystem -match '2008|2003|2000|2012(?! R2)'
}

if (`$oldDCs) {
    Write-Host "WARNING: Old DCs must be upgraded or demoted first:" -ForegroundColor Red
    `$oldDCs | Select-Object Name, OperatingSystem | Format-Table
    Write-Host "Cannot raise functional level until these DCs are upgraded." -ForegroundColor Red
    return
}

#############################################################################
# Step 2: Update Schema (If Needed)
#############################################################################

# Run on Schema Master:
`$schemaMaster = (Get-ADForest).SchemaMaster
Write-Host "Schema Master: `$schemaMaster"

# Mount Windows Server installation media and run:
# adprep /forestprep
# adprep /domainprep

#############################################################################
# Step 3: Raise Domain Functional Level
#############################################################################

# Check current level:
`$domain = Get-ADDomain
Write-Host "Current Domain Level: `$(`$domain.DomainMode)"

# Raise to Windows Server 2016:
# WARNING: This cannot be reversed!

# Set-ADDomainMode -Identity `$domain.DNSRoot -DomainMode Windows2016Domain -Confirm:`$false

# Verify:
# (Get-ADDomain).DomainMode

#############################################################################
# Step 4: Raise Forest Functional Level
#############################################################################

# Domain level must be raised BEFORE forest level
# All domains in forest must be at minimum level

`$forest = Get-ADForest
Write-Host "Current Forest Level: `$(`$forest.ForestMode)"

# Check all domains are at target level:
foreach (`$domainName in `$forest.Domains) {
    `$d = Get-ADDomain -Identity `$domainName
    Write-Host "`$domainName : `$(`$d.DomainMode)"
}

# Raise to Windows Server 2016:
# WARNING: This cannot be reversed!

# Set-ADForestMode -Identity `$forest.Name -ForestMode Windows2016Forest -Confirm:`$false

# Verify:
# (Get-ADForest).ForestMode

#############################################################################
# Step 5: Verify New Features Are Available
#############################################################################

# After raising to 2012 R2:
# Protected Users group should be populated
Get-ADGroup -Identity 'Protected Users' -Properties Members |
    Select-Object Name, @{N='MemberCount';E={`$_.Members.Count}}

# After raising to 2016:
# PAM features available
Get-ADOptionalFeature -Filter * |
    Select-Object Name, EnabledScopes |
    Format-Table -AutoSize

# Enable PAM (Privileged Access Management):
# Enable-ADOptionalFeature -Identity 'Privileged Access Management Feature' `
#     -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name

#############################################################################
# Step 6: Leverage New Security Features
#############################################################################

# Add privileged accounts to Protected Users:
`$privilegedUsers = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins'
)

# Get members of privileged groups
`$admins = foreach (`$group in `$privilegedUsers) {
    Get-ADGroupMember -Identity `$group -Recursive
}

# Add to Protected Users (test first!):
# foreach (`$admin in `$admins | Select-Object -Unique) {
#     Add-ADGroupMember -Identity 'Protected Users' -Members `$admin
# }

# Create Authentication Policies (2012 R2+):
# New-ADAuthenticationPolicy -Name 'Tier0-Policy' `
#     -UserTGTLifetimeMins 240 `
#     -ProtectedFromAccidentalDeletion `$true

#############################################################################
# Verification
#############################################################################

Write-Host "`n=== Final Status ===" -ForegroundColor Cyan
Write-Host "Domain: `$((Get-ADDomain).DomainMode)"
Write-Host "Forest: `$((Get-ADForest).ForestMode)"

# List enabled optional features:
Get-ADOptionalFeature -Filter * | Where-Object { `$_.EnabledScopes } |
    Select-Object Name |
    Format-Table

"@
            return $commands
        }
    }
}
