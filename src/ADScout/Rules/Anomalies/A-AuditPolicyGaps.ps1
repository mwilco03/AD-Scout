@{
    Id          = 'A-AuditPolicyGaps'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Insufficient Audit Policy Configuration'
    Description = 'Detects missing or insufficient audit policy settings on Domain Controllers. Proper auditing is essential for detecting attacks, investigating incidents, and maintaining compliance. Key events may not be logged if audit policies are not configured.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'GPO'

    References  = @(
        @{ Title = 'Windows Security Auditing'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing' }
        @{ Title = 'CIS Audit Policy'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.002')  # Impair Defenses: Disable Windows Event Logging
    }

    CIS   = @('17.1', '17.2', '17.3', '17.4', '17.5', '17.6', '17.7', '17.8', '17.9')
    STIG  = @('V-220945')
    ANSSI = @('R55')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical audit subcategories that should be enabled
        $criticalAuditCategories = @{
            'Credential Validation'                 = @{ Importance = 'Critical'; Events = '4774, 4775, 4776' }
            'Security Group Management'             = @{ Importance = 'Critical'; Events = '4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758' }
            'User Account Management'               = @{ Importance = 'Critical'; Events = '4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4780, 4781, 4794' }
            'Computer Account Management'           = @{ Importance = 'High'; Events = '4741, 4742, 4743' }
            'Directory Service Access'              = @{ Importance = 'Critical'; Events = '4662' }
            'Directory Service Changes'             = @{ Importance = 'Critical'; Events = '5136, 5137, 5138, 5139, 5141' }
            'Logon'                                 = @{ Importance = 'Critical'; Events = '4624, 4625, 4634, 4647, 4648, 4649, 4672, 4675' }
            'Special Logon'                         = @{ Importance = 'Critical'; Events = '4964' }
            'Logoff'                                = @{ Importance = 'High'; Events = '4634, 4647' }
            'Kerberos Authentication Service'       = @{ Importance = 'High'; Events = '4768, 4771, 4772' }
            'Kerberos Service Ticket Operations'    = @{ Importance = 'High'; Events = '4769, 4770, 4773' }
            'Sensitive Privilege Use'               = @{ Importance = 'Critical'; Events = '4673, 4674, 4985' }
            'Process Creation'                      = @{ Importance = 'Critical'; Events = '4688' }
            'Security System Extension'             = @{ Importance = 'High'; Events = '4610, 4611, 4614, 4622, 4697' }
            'Audit Policy Change'                   = @{ Importance = 'Critical'; Events = '4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912' }
        }

        try {
            # Check Default Domain Controllers Policy
            $dcPolicy = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction SilentlyContinue

            if ($dcPolicy) {
                try {
                    [xml]$report = Get-GPOReport -Guid $dcPolicy.Id -ReportType Xml -ErrorAction SilentlyContinue

                    $auditPolicies = $report.SelectNodes("//AuditSetting")

                    foreach ($categoryName in $criticalAuditCategories.Keys) {
                        $categoryInfo = $criticalAuditCategories[$categoryName]
                        $found = $false

                        foreach ($policy in $auditPolicies) {
                            if ($policy.SubcategoryName -eq $categoryName) {
                                $found = $true
                                $setting = $policy.SettingValue

                                # Check if both success and failure are audited (or at least success)
                                if ($setting -notmatch 'Success') {
                                    $findings += [PSCustomObject]@{
                                        GPOName             = $dcPolicy.DisplayName
                                        AuditCategory       = $categoryName
                                        CurrentSetting      = $setting
                                        RecommendedSetting  = 'Success and Failure'
                                        Importance          = $categoryInfo.Importance
                                        MissingEvents       = $categoryInfo.Events
                                        RiskLevel           = $categoryInfo.Importance
                                        Issue               = "Audit category not fully configured"
                                    }
                                }
                                break
                            }
                        }

                        if (-not $found -and $categoryInfo.Importance -eq 'Critical') {
                            $findings += [PSCustomObject]@{
                                GPOName             = $dcPolicy.DisplayName
                                AuditCategory       = $categoryName
                                CurrentSetting      = 'Not Configured'
                                RecommendedSetting  = 'Success and Failure'
                                Importance          = $categoryInfo.Importance
                                MissingEvents       = $categoryInfo.Events
                                RiskLevel           = 'Critical'
                                Issue               = "Critical audit category not configured"
                            }
                        }
                    }
                }
                catch { }
            }

            # Check local audit policy using auditpol
            try {
                $auditPolOutput = auditpol /get /category:* 2>$null

                if ($auditPolOutput) {
                    # Parse and check for "No Auditing" entries
                    $noAuditingCategories = @()

                    foreach ($line in $auditPolOutput) {
                        if ($line -match 'No Auditing') {
                            $categoryMatch = $line -replace '\s+No Auditing.*', ''
                            if ($categoryMatch.Trim()) {
                                $noAuditingCategories += $categoryMatch.Trim()
                            }
                        }
                    }

                    if ($noAuditingCategories.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            CheckType           = 'Local Audit Policy'
                            CategoriesDisabled  = $noAuditingCategories.Count
                            SampleCategories    = ($noAuditingCategories | Select-Object -First 5) -join '; '
                            RiskLevel           = 'High'
                            Issue               = 'Multiple audit categories disabled'
                        }
                    }
                }
            }
            catch { }
        }
        catch {
            # Could not check audit policy
        }

        return $findings | Sort-Object RiskLevel, AuditCategory
    }

    Remediation = @{
        Description = 'Configure comprehensive audit policies via GPO. Enable success and failure auditing for critical categories.'
        Impact      = 'Low - Auditing has minimal performance impact. May increase log storage needs.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# AUDIT POLICY CONFIGURATION
# ================================================================
# Without proper auditing, you cannot:
# - Detect ongoing attacks
# - Investigate security incidents
# - Meet compliance requirements
# - Identify privilege abuse

# ================================================================
# CURRENT GAPS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Category: $($item.AuditCategory ?? $item.CheckType)
# Current: $($item.CurrentSetting ?? $item.CategoriesDisabled)
# Recommended: $($item.RecommendedSetting ?? 'Enable auditing')
# Missing Events: $($item.MissingEvents ?? $item.SampleCategories)
# Importance: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# CONFIGURE VIA GPO
# ================================================================

# 1. Open Group Policy Management
# 2. Edit Default Domain Controllers Policy
# 3. Navigate to:
#    Computer Configuration
#    -> Policies
#    -> Windows Settings
#    -> Security Settings
#    -> Advanced Audit Policy Configuration
#    -> Audit Policies

# ================================================================
# RECOMMENDED AUDIT SETTINGS
# ================================================================

# Account Logon:
#   - Credential Validation: Success and Failure
#   - Kerberos Authentication Service: Success and Failure
#   - Kerberos Service Ticket Operations: Success and Failure

# Account Management:
#   - Computer Account Management: Success and Failure
#   - Security Group Management: Success and Failure
#   - User Account Management: Success and Failure

# DS Access:
#   - Directory Service Access: Success and Failure
#   - Directory Service Changes: Success and Failure

# Logon/Logoff:
#   - Logon: Success and Failure
#   - Logoff: Success
#   - Special Logon: Success

# Object Access:
#   - File System: Success and Failure (selective)
#   - Registry: Success and Failure (selective)
#   - SAM: Success and Failure

# Privilege Use:
#   - Sensitive Privilege Use: Success and Failure

# Detailed Tracking:
#   - Process Creation: Success

# Policy Change:
#   - Audit Policy Change: Success and Failure
#   - Authentication Policy Change: Success

# ================================================================
# AUDITPOL COMMANDS
# ================================================================

# Set audit policy via command line:
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# ================================================================
# ENABLE COMMAND LINE LOGGING
# ================================================================

# Include process command line in Event 4688:
# GPO: Administrative Templates -> System -> Audit Process Creation
# -> Include command line in process creation events: Enabled

# ================================================================
# LOG SIZE AND RETENTION
# ================================================================

# Increase Security log size (default is too small):
# wevtutil sl Security /ms:4194304000

# Set to 4GB to ensure adequate retention

"@
            return $commands
        }
    }
}
