<#
.SYNOPSIS
    Detects unauthorized or suspicious GPO links.

.DESCRIPTION
    GPO links to sensitive OUs can be used to deploy malware, steal credentials,
    or persist access. This rule identifies GPOs linked to privileged OUs that
    may not be authorized.

.NOTES
    Rule ID    : G-GPOLinkAbuse
    Category   : GPO
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'G-GPOLinkAbuse'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Unauthorized GPO Links'
    Description = 'Identifies GPO links to sensitive OUs (Domain Controllers, Tier 0 systems) that may indicate persistence or misconfiguration.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'GPO Abuse'; Url = 'https://attack.mitre.org/techniques/T1484/001/' }
        @{ Title = 'GPO Security'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'GPO Persistence'; Url = 'https://adsecurity.org/?p=2716' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion
        Techniques = @('T1484.001', 'T1484.002')  # Group Policy Modification, Domain Trust Modification
    }

    CIS   = @('5.3')
    STIG  = @('V-254455')
    ANSSI = @('R49')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Sensitive OUs to monitor
        $sensitiveOUs = @(
            'Domain Controllers',
            'Tier 0',
            'Tier0',
            'Admin',
            'Privileged',
            'Service Accounts'
        )

        # Known good GPOs (customize for environment)
        $knownGoodGPOs = @(
            'Default Domain Controllers Policy',
            'Default Domain Policy'
        )

        try {
            # Get Domain Controllers OU
            $dcOU = (Get-ADDomain).DomainControllersContainer

            # Get all GPO links
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue

            foreach ($gpo in $gpos) {
                $gpoReport = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue)
                $linksTo = $gpoReport.GPO.LinksTo

                foreach ($link in $linksTo) {
                    $linkedPath = $link.SOMPath
                    $linkedName = $link.SOMName
                    $linkEnabled = $link.Enabled
                    $enforced = $link.NoOverride

                    # Skip disabled links
                    if ($linkEnabled -ne 'true') { continue }

                    $issues = @()
                    $riskLevel = 'Low'

                    # Check if linked to sensitive OU
                    $isSensitiveOU = $false
                    foreach ($sensitive in $sensitiveOUs) {
                        if ($linkedPath -match $sensitive -or $linkedName -match $sensitive) {
                            $isSensitiveOU = $true
                            break
                        }
                    }

                    # Check if linked to Domain Controllers
                    if ($linkedPath -eq $dcOU -or $linkedName -eq 'Domain Controllers') {
                        $isSensitiveOU = $true

                        if ($gpo.DisplayName -notin $knownGoodGPOs) {
                            $issues += 'Non-default GPO linked to Domain Controllers'
                            $riskLevel = 'High'
                        }
                    }

                    # Check for domain root link (affects everyone)
                    if ($linkedPath -eq (Get-ADDomain).DistinguishedName) {
                        $issues += 'Linked to domain root (affects all objects)'
                        if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                    }

                    # Check if GPO is enforced
                    if ($enforced -eq 'true') {
                        $issues += 'Link is ENFORCED'
                        if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                    }

                    # Check GPO creation date (recently created = suspicious)
                    if ($gpo.CreationTime -gt (Get-Date).AddDays(-30)) {
                        $issues += "Created recently: $($gpo.CreationTime.ToString('yyyy-MM-dd'))"
                        if ($isSensitiveOU) { $riskLevel = 'High' }
                    }

                    # Check GPO modification date
                    if ($gpo.ModificationTime -gt (Get-Date).AddDays(-7)) {
                        $issues += "Modified recently: $($gpo.ModificationTime.ToString('yyyy-MM-dd'))"
                    }

                    # Check for suspicious settings in GPO
                    $gpoSettings = Get-GPOReport -Guid $gpo.Id -ReportType Html -ErrorAction SilentlyContinue
                    $suspiciousPatterns = @(
                        'Scheduled Tasks',
                        'Immediate Task',
                        'Scripts',
                        'PowerShell',
                        'Registry',
                        'Services',
                        'Software Installation'
                    )

                    foreach ($pattern in $suspiciousPatterns) {
                        if ($gpoSettings -match $pattern -and $isSensitiveOU) {
                            $issues += "Contains $pattern configuration"
                            if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                        }
                    }

                    if ($issues.Count -gt 0 -and $isSensitiveOU) {
                        $findings += [PSCustomObject]@{
                            GPOName           = $gpo.DisplayName
                            GPOID             = $gpo.Id
                            LinkedTo          = $linkedPath
                            LinkedName        = $linkedName
                            LinkEnabled       = $linkEnabled
                            Enforced          = $enforced
                            GPOCreated        = $gpo.CreationTime
                            GPOModified       = $gpo.ModificationTime
                            GPOOwner          = $gpo.Owner
                            Issues            = ($issues -join '; ')
                            RiskLevel         = $riskLevel
                            IsSensitiveTarget = $isSensitiveOU
                        }
                    }
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                GPOName           = 'Error'
                GPOID             = 'N/A'
                LinkedTo          = 'N/A'
                LinkedName        = 'N/A'
                LinkEnabled       = 'N/A'
                Enforced          = 'N/A'
                GPOCreated        = 'N/A'
                GPOModified       = 'N/A'
                GPOOwner          = 'N/A'
                Issues            = "Check failed: $_"
                RiskLevel         = 'Unknown'
                IsSensitiveTarget = 'N/A'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and validate all GPO links to sensitive OUs, remove unauthorized links.'
        Impact      = 'Medium - Removing GPO links may affect applied policies. Test in staging first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# GPO Link Security Review
#############################################################################
#
# GPO links to sensitive OUs can be abused for:
# - Deploying malware via scheduled tasks
# - Stealing credentials via scripts
# - Maintaining persistence
# - Modifying security settings
#
# Suspicious GPO links:
$($Finding.Findings | ForEach-Object { "# - $($_.GPOName) -> $($_.LinkedName): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Inventory All GPO Links
#############################################################################

# Get all GPOs and their links:
Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    [xml]`$report = Get-GPOReport -Guid `$gpo.Id -ReportType Xml
    `$report.GPO.LinksTo | ForEach-Object {
        [PSCustomObject]@{
            GPOName = `$gpo.DisplayName
            LinkedTo = `$_.SOMPath
            Enabled = `$_.Enabled
            Enforced = `$_.NoOverride
        }
    }
} | Format-Table -AutoSize

#############################################################################
# Step 2: Review GPOs Linked to Domain Controllers
#############################################################################

`$dcOU = (Get-ADDomain).DomainControllersContainer

# Get GPOs linked to DC OU:
Get-GPInheritance -Target `$dcOU |
    Select-Object -ExpandProperty GpoLinks |
    Select-Object DisplayName, Enabled, Enforced, Order |
    Format-Table -AutoSize

# Only these GPOs should typically be linked to DCs:
# - Default Domain Controllers Policy
# - Security baseline GPOs
# - Specific DC hardening GPOs

#############################################################################
# Step 3: Review GPO Contents
#############################################################################

# For each suspicious GPO, review its settings:
`$gpoName = "Suspicious GPO Name"  # Replace with actual name

# Get detailed HTML report:
Get-GPOReport -Name `$gpoName -ReportType Html -Path "C:\Reports\`$gpoName.html"

# Look for:
# - Scheduled Tasks (Computer/User Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks)
# - Scripts (Computer/User Configuration -> Policies -> Windows Settings -> Scripts)
# - Registry changes (Computer/User Configuration -> Preferences -> Windows Settings -> Registry)
# - Software Installation

#############################################################################
# Step 4: Check GPO Permissions
#############################################################################

# Get GPO ACL:
`$gpo = Get-GPO -Name `$gpoName
Get-GPPermission -Guid `$gpo.Id -All |
    Select-Object Trustee, TrusteeType, Permission |
    Format-Table -AutoSize

# Look for:
# - Unexpected accounts with Edit rights
# - Non-admin accounts with any modify permissions

#############################################################################
# Step 5: Remove Unauthorized GPO Links
#############################################################################

# Remove a GPO link from a specific OU:
# WARNING: This is disruptive - backup first!

# `$targetOU = "OU=Domain Controllers,DC=domain,DC=com"
# `$gpoToRemove = Get-GPO -Name "Suspicious GPO"

# Backup GPO first:
# Backup-GPO -Guid `$gpoToRemove.Id -Path "C:\GPOBackups"

# Remove link:
# Remove-GPLink -Guid `$gpoToRemove.Id -Target `$targetOU

#############################################################################
# Step 6: Monitor GPO Changes
#############################################################################

# Enable GPO change auditing:
# Event ID 5136: Directory Service Changes (GPO modifications)
# Event ID 5137: Directory Service Object Created (new GPO)
# Event ID 5141: Directory Service Object Deleted

# Monitor for GPO link changes:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5136
} -MaxEvents 100 | Where-Object {
    `$_.Message -match 'groupPolicyContainer|gPLink'
} | Select-Object TimeCreated, Message | Format-Table -Wrap

#############################################################################
# Step 7: Implement GPO Change Monitoring
#############################################################################

# Create baseline of GPO links:
`$baseline = Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    [xml]`$report = Get-GPOReport -Guid `$gpo.Id -ReportType Xml
    `$report.GPO.LinksTo | ForEach-Object {
        [PSCustomObject]@{
            GPOName = `$gpo.DisplayName
            GPOID = `$gpo.Id
            LinkedTo = `$_.SOMPath
            Enabled = `$_.Enabled
        }
    }
}

`$baseline | Export-Csv -Path "C:\Baseline\GPOLinks_`$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Compare against baseline periodically

#############################################################################
# Verification
#############################################################################

# Re-check Domain Controllers OU:
Get-GPInheritance -Target (Get-ADDomain).DomainControllersContainer |
    Select-Object -ExpandProperty GpoLinks |
    Select-Object DisplayName, Enabled, Enforced |
    Format-Table -AutoSize

"@
            return $commands
        }
    }
}
