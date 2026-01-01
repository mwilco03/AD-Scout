@{
    Id          = 'A-IncompleteAudit'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Incomplete Audit Policy Configuration'
    Description = 'The domain audit policy is missing critical security event categories required for effective monitoring and incident response. Incomplete audit policies leave blind spots that attackers can exploit.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'NIST AU-2 Event Logging'; Url = 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final' }
        @{ Title = 'Windows Security Auditing'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing' }
        @{ Title = 'Audit Policy Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.002', 'T1070')  # Disable Windows Event Logging, Indicator Removal
    }

    CIS   = @('17.1', '17.2', '17.3', '17.4', '17.5', '17.6', '17.7', '17.8', '17.9')
    STIG  = @('V-63449', 'V-63453', 'V-63457', 'V-63461')
    ANSSI = @('vuln1_audit_incomplete')
    NIST  = @('AU-2', 'AU-2(1)', 'AU-3', 'AU-12')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Required audit categories and subcategories per NIST/CIS
        $requiredAudits = @{
            'Credential Validation' = @{ Category = 'Account Logon'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Kerberos Authentication Service' = @{ Category = 'Account Logon'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Kerberos Service Ticket Operations' = @{ Category = 'Account Logon'; Severity = 'High'; NISTControl = 'AU-2' }
            'User Account Management' = @{ Category = 'Account Management'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Security Group Management' = @{ Category = 'Account Management'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Computer Account Management' = @{ Category = 'Account Management'; Severity = 'High'; NISTControl = 'AU-2' }
            'Directory Service Access' = @{ Category = 'DS Access'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Directory Service Changes' = @{ Category = 'DS Access'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Logon' = @{ Category = 'Logon/Logoff'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Logoff' = @{ Category = 'Logon/Logoff'; Severity = 'Medium'; NISTControl = 'AU-2' }
            'Special Logon' = @{ Category = 'Logon/Logoff'; Severity = 'High'; NISTControl = 'AU-2' }
            'Audit Policy Change' = @{ Category = 'Policy Change'; Severity = 'Critical'; NISTControl = 'AU-2' }
            'Authentication Policy Change' = @{ Category = 'Policy Change'; Severity = 'High'; NISTControl = 'AU-2' }
            'Sensitive Privilege Use' = @{ Category = 'Privilege Use'; Severity = 'High'; NISTControl = 'AU-2' }
            'Security State Change' = @{ Category = 'System'; Severity = 'High'; NISTControl = 'AU-2' }
            'Security System Extension' = @{ Category = 'System'; Severity = 'High'; NISTControl = 'AU-2' }
        }

        foreach ($dc in $Data) {
            $missingAudits = @()
            $partialAudits = @()

            try {
                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local audit policy check
                    $auditOutput = auditpol /get /category:* 2>$null

                    if ($auditOutput) {
                        foreach ($subcategory in $requiredAudits.Keys) {
                            $line = $auditOutput | Where-Object { $_ -match [regex]::Escape($subcategory) }

                            if ($line) {
                                if ($line -match 'No Auditing') {
                                    $missingAudits += [PSCustomObject]@{
                                        Subcategory = $subcategory
                                        Category    = $requiredAudits[$subcategory].Category
                                        Status      = 'Not Configured'
                                        Required    = 'Success and Failure'
                                        Severity    = $requiredAudits[$subcategory].Severity
                                        NISTControl = $requiredAudits[$subcategory].NISTControl
                                    }
                                } elseif ($line -notmatch 'Success and Failure') {
                                    $currentSetting = if ($line -match 'Success') { 'Success Only' }
                                                     elseif ($line -match 'Failure') { 'Failure Only' }
                                                     else { 'Unknown' }
                                    $partialAudits += [PSCustomObject]@{
                                        Subcategory = $subcategory
                                        Category    = $requiredAudits[$subcategory].Category
                                        Status      = $currentSetting
                                        Required    = 'Success and Failure'
                                        Severity    = $requiredAudits[$subcategory].Severity
                                        NISTControl = $requiredAudits[$subcategory].NISTControl
                                    }
                                }
                            }
                        }
                    }
                } else {
                    # Remote DC - flag for manual check
                    $missingAudits += [PSCustomObject]@{
                        Subcategory = 'All Required Subcategories'
                        Category    = 'All Categories'
                        Status      = 'Unable to check remotely'
                        Required    = 'Manual verification'
                        Severity    = 'Unknown'
                        NISTControl = 'AU-2'
                    }
                }

                if ($missingAudits.Count -gt 0 -or $partialAudits.Count -gt 0) {
                    $criticalMissing = ($missingAudits + $partialAudits) | Where-Object { $_.Severity -eq 'Critical' }

                    $findings += [PSCustomObject]@{
                        DomainController    = $dc.Name
                        OperatingSystem     = $dc.OperatingSystem
                        MissingAudits       = $missingAudits
                        PartialAudits       = $partialAudits
                        TotalIssues         = $missingAudits.Count + $partialAudits.Count
                        CriticalMissing     = $criticalMissing.Count
                        RiskLevel           = if ($criticalMissing.Count -gt 0) { 'Critical' } else { 'High' }
                        Impact              = 'Security events not captured for incident response'
                        NISTCompliance      = 'AU-2 (Event Logging) - Non-Compliant'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController    = $dc.Name
                    OperatingSystem     = $dc.OperatingSystem
                    MissingAudits       = @()
                    PartialAudits       = @()
                    TotalIssues         = 1
                    CriticalMissing     = 0
                    RiskLevel           = 'Unknown'
                    Impact              = "Unable to check audit policy: $_"
                    NISTCompliance      = 'AU-2 - Verification Required'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure complete audit policy on all Domain Controllers to capture all security-relevant events per NIST AU-2 requirements.'
        Impact      = 'Low - Increased log volume requires adequate storage and SIEM integration.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Configure Complete Audit Policy per NIST AU-2
# DCs with incomplete audit: $($Finding.Findings.Count)

# NIST 800-53 AU-2 Required Audit Events for AD:
# - Account logon events (success/failure)
# - Account management (user, group, computer)
# - Directory service access and changes
# - Logon/logoff events
# - Policy changes
# - Privilege use
# - System events

# Configure via auditpol on each DC:

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable

# DS Access
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Verify configuration:
auditpol /get /category:*

# Configure log size (minimum 1GB recommended):
wevtutil sl Security /ms:1073741824

# Export configuration for GPO:
auditpol /backup /file:C:\AuditPolicy_NIST.csv

"@
            return $commands
        }
    }
}
