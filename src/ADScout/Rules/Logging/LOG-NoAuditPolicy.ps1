<#
.SYNOPSIS
    Detects missing or inadequate audit policies.

.DESCRIPTION
    Proper audit policies are critical for detecting attacks. This rule checks
    for missing or weak audit policies that create detection blind spots.

.NOTES
    Rule ID    : LOG-NoAuditPolicy
    Category   : Logging
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'LOG-NoAuditPolicy'
    Version     = '1.0.0'
    Category    = 'Logging'
    Title       = 'Missing Audit Policies'
    Description = 'Identifies missing or inadequate audit policies on Domain Controllers that create blind spots for attack detection.'
    Severity    = 'High'
    Weight      = 50
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Windows Security Auditing'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing' }
        @{ Title = 'Audit Policy Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations' }
        @{ Title = 'NSA Event Logging Guidance'; Url = 'https://github.com/nsacyber/Event-Forwarding-Guidance' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.002')  # Disable Windows Event Logging
    }

    CIS   = @('17.1', '17.2', '17.3')
    STIG  = @('V-254457')
    ANSSI = @('R51')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical audit categories that must be enabled
        $requiredAudits = @{
            'Account Logon' = @{
                'Credential Validation' = 'Success, Failure'
                'Kerberos Authentication Service' = 'Success, Failure'
                'Kerberos Service Ticket Operations' = 'Success, Failure'
            }
            'Account Management' = @{
                'Computer Account Management' = 'Success, Failure'
                'Security Group Management' = 'Success, Failure'
                'User Account Management' = 'Success, Failure'
            }
            'DS Access' = @{
                'Directory Service Access' = 'Success, Failure'
                'Directory Service Changes' = 'Success'
            }
            'Logon/Logoff' = @{
                'Logon' = 'Success, Failure'
                'Logoff' = 'Success'
                'Special Logon' = 'Success'
            }
            'Object Access' = @{
                'File System' = 'Failure'
                'SAM' = 'Success, Failure'
            }
            'Policy Change' = @{
                'Audit Policy Change' = 'Success'
                'Authentication Policy Change' = 'Success'
            }
            'Privilege Use' = @{
                'Sensitive Privilege Use' = 'Success, Failure'
            }
            'System' = @{
                'Security State Change' = 'Success'
                'Security System Extension' = 'Success'
            }
        }

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $auditPolicy = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        # Get current audit policy
                        $policies = auditpol /get /category:* 2>$null

                        $result = @{
                            RawPolicy = $policies
                            Categories = @{}
                        }

                        $currentCategory = ''
                        foreach ($line in $policies) {
                            if ($line -match '^\s{2}(\w.+)$' -and $line -notmatch 'Subcategory') {
                                $currentCategory = $Matches[1].Trim()
                                $result.Categories[$currentCategory] = @{}
                            }
                            elseif ($line -match '^\s{4}(.+?)\s{2,}(.+)$') {
                                $subcategory = $Matches[1].Trim()
                                $setting = $Matches[2].Trim()
                                if ($currentCategory) {
                                    $result.Categories[$currentCategory][$subcategory] = $setting
                                }
                            }
                        }

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()

                    # Check each required audit
                    foreach ($category in $requiredAudits.Keys) {
                        foreach ($subcategory in $requiredAudits[$category].Keys) {
                            $required = $requiredAudits[$category][$subcategory]
                            $current = $auditPolicy.Categories[$category][$subcategory]

                            if (-not $current -or $current -eq 'No Auditing') {
                                $issues += "$subcategory: Not auditing (should be $required)"
                            }
                            elseif ($required -match 'Failure' -and $current -notmatch 'Failure') {
                                $issues += "$subcategory: Missing Failure auditing"
                            }
                            elseif ($required -match 'Success' -and $current -notmatch 'Success') {
                                $issues += "$subcategory: Missing Success auditing"
                            }
                        }
                    }

                    # Check for specific critical gaps
                    $criticalGaps = @()

                    # DCSync detection
                    $dsAccess = $auditPolicy.Categories['DS Access']['Directory Service Access']
                    if (-not $dsAccess -or $dsAccess -eq 'No Auditing') {
                        $criticalGaps += 'Cannot detect DCSync attacks'
                    }

                    # Kerberoasting detection
                    $kerbTGS = $auditPolicy.Categories['Account Logon']['Kerberos Service Ticket Operations']
                    if (-not $kerbTGS -or $kerbTGS -eq 'No Auditing') {
                        $criticalGaps += 'Cannot detect Kerberoasting'
                    }

                    # Logon failures
                    $logon = $auditPolicy.Categories['Logon/Logoff']['Logon']
                    if (-not $logon -or $logon -notmatch 'Failure') {
                        $criticalGaps += 'Cannot detect brute force attacks'
                    }

                    if ($issues.Count -gt 0 -or $criticalGaps.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            DomainController = $dcName
                            MissingAudits    = $issues.Count
                            CriticalGaps     = ($criticalGaps -join '; ')
                            Issues           = ($issues | Select-Object -First 10) -join '; '
                            AllIssues        = $issues
                            RiskLevel        = if ($criticalGaps.Count -gt 0) { 'Critical' } elseif ($issues.Count -gt 5) { 'High' } else { 'Medium' }
                            Impact           = 'Reduced detection capability for attacks'
                            DistinguishedName = $dc.DistinguishedName
                        }
                    }

                } catch {
                    $findings += [PSCustomObject]@{
                        DomainController = $dcName
                        MissingAudits    = 'Unknown'
                        CriticalGaps     = 'Check failed'
                        Issues           = "Unable to verify audit policy: $_"
                        AllIssues        = @()
                        RiskLevel        = 'Unknown'
                        Impact           = 'Manual verification required'
                        DistinguishedName = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure comprehensive audit policies on all Domain Controllers.'
        Impact      = 'Low - Audit policies increase log volume but do not affect operations.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Audit Policy Configuration
#############################################################################
#
# Proper audit policies are essential for detecting:
# - DCSync attacks
# - Kerberoasting
# - Golden/Silver ticket attacks
# - Privilege escalation
# - Lateral movement
#
# Missing auditing on:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.CriticalGaps)" } | Out-String)

#############################################################################
# Step 1: Configure Advanced Audit Policies via GPO
#############################################################################

# Create GPO for DC audit policy:
`$gpoName = 'DC Security - Audit Policy'
# New-GPO -Name `$gpoName | New-GPLink -Target (Get-ADDomain).DomainControllersContainer

# Configure via:
# Computer Configuration -> Policies -> Windows Settings ->
# Security Settings -> Advanced Audit Policy Configuration

#############################################################################
# Step 2: Apply Recommended Audit Subcategories
#############################################################################

# Run on each DC or via GPO:

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable

# DS Access (Critical for DCSync detection)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

#############################################################################
# Step 3: Configure SACL on AD Objects
#############################################################################

# For detailed DS Access auditing, configure SACL on domain root:

`$domainDN = (Get-ADDomain).DistinguishedName

# Enable auditing for replication (DCSync detection):
# This is configured via Advanced Security Settings on the domain object

# Key SACLs to configure:
# - Replicating Directory Changes: Everyone, Success
# - Replicating Directory Changes All: Everyone, Success

#############################################################################
# Step 4: Increase Event Log Sizes
#############################################################################

# Default 128MB is often insufficient
# Recommend 1-4GB for Security log on DCs

`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Increase Security log to 2GB
        wevtutil sl Security /ms:2147483648

        # Increase other relevant logs
        wevtutil sl 'Directory Service' /ms:1073741824
        wevtutil sl System /ms:268435456

        Write-Host "Configured log sizes on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 5: Configure Event Forwarding (WEF)
#############################################################################

# Forward security events to central SIEM:
# 1. Configure WinRM on all DCs
# 2. Create subscription on collector
# 3. Forward critical events

# Critical Event IDs to forward:
# 4624, 4625, 4648 - Logons
# 4662 - Directory Service Access (DCSync)
# 4768, 4769, 4770 - Kerberos
# 4672 - Special privileges assigned
# 4720, 4722, 4724, 4728, 4732, 4756 - Account/Group changes

#############################################################################
# Step 6: Apply to All DCs
#############################################################################

# Apply audit policy to all DCs:
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Import audit policy from backup or apply commands above
        # auditpol /restore /file:C:\AuditPolicy.csv

        Write-Host "Applied audit policy to `$env:COMPUTERNAME"
    }
}

#############################################################################
# Verification
#############################################################################

# Verify audit policy on all DCs:
foreach (`$dc in `$dcs) {
    Write-Host "`n=== `$(`$dc.HostName) ===" -ForegroundColor Cyan
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        auditpol /get /category:"Account Logon","DS Access","Logon/Logoff"
    }
}

# Test by generating audit events:
# - Failed logon attempt
# - DCSync simulation (with proper authorization)

"@
            return $commands
        }
    }
}
