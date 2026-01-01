@{
    Id          = 'A-AuditDC'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Insufficient Audit Policy on Domain Controllers'
    Description = 'Domain Controllers do not have adequate audit policies configured. Critical security events such as logon attempts, privilege use, and object access are not being logged, making it difficult to detect and investigate security incidents.'
    Severity    = 'High'
    Weight      = 20
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Windows Security Auditing'; Url = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing' }
        @{ Title = 'MITRE Detection'; Url = 'https://attack.mitre.org/tactics/TA0005/' }
        @{ Title = 'Audit Policy Recommendations'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.002')  # Impair Defenses: Disable Windows Event Logging
    }

    CIS   = @('17.1', '17.2', '17.3', '17.4', '17.5', '17.6', '17.7', '17.8', '17.9')
    STIG  = @('V-63449', 'V-63453', 'V-63457')
    ANSSI = @('vuln1_audit_policy')
    NIST  = @('AU-2', 'AU-3', 'AU-6', 'AU-12', 'SI-4')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical audit categories that should be enabled on DCs
        $requiredAudits = @{
            'Account Logon' = @{
                Subcategories = @('Credential Validation', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations')
                CISRef = '17.1'
            }
            'Account Management' = @{
                Subcategories = @('User Account Management', 'Security Group Management', 'Computer Account Management')
                CISRef = '17.2'
            }
            'Logon/Logoff' = @{
                Subcategories = @('Logon', 'Logoff', 'Special Logon', 'Other Logon/Logoff Events')
                CISRef = '17.5'
            }
            'Object Access' = @{
                Subcategories = @('File System', 'Registry', 'SAM')
                CISRef = '17.6'
            }
            'Policy Change' = @{
                Subcategories = @('Audit Policy Change', 'Authentication Policy Change')
                CISRef = '17.7'
            }
            'Privilege Use' = @{
                Subcategories = @('Sensitive Privilege Use')
                CISRef = '17.8'
            }
            'System' = @{
                Subcategories = @('Security State Change', 'Security System Extension')
                CISRef = '17.9'
            }
            'DS Access' = @{
                Subcategories = @('Directory Service Access', 'Directory Service Changes')
                CISRef = '17.4'
            }
        }

        foreach ($dc in $Data) {
            $auditIssues = @()

            try {
                # Try to get audit policy from DC
                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local check using auditpol
                    $auditOutput = auditpol /get /category:* 2>$null

                    if ($auditOutput) {
                        foreach ($category in $requiredAudits.Keys) {
                            $categoryLine = $auditOutput | Where-Object { $_ -match $category }

                            if ($categoryLine) {
                                # Check if it shows "No Auditing"
                                foreach ($line in $auditOutput) {
                                    if ($line -match "No Auditing" -and $line -notmatch "^\s*$category") {
                                        # Check subcategories
                                        foreach ($subcat in $requiredAudits[$category].Subcategories) {
                                            if ($line -match $subcat -and $line -match "No Auditing") {
                                                $auditIssues += [PSCustomObject]@{
                                                    Category     = $category
                                                    Subcategory  = $subcat
                                                    CurrentState = 'No Auditing'
                                                    Required     = 'Success and Failure'
                                                    CISRef       = $requiredAudits[$category].CISRef
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    # Remote check - note for manual verification
                    $auditIssues += [PSCustomObject]@{
                        Category     = 'All Categories'
                        Subcategory  = 'Remote DC - requires manual check'
                        CurrentState = 'Unable to query remotely'
                        Required     = 'Manual verification with auditpol'
                        CISRef       = 'Multiple'
                    }
                }

                # If we couldn't check or found issues
                if ($auditIssues.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dc.Name
                        OperatingSystem     = $dc.OperatingSystem
                        AuditIssues         = $auditIssues
                        IssueCount          = $auditIssues.Count
                        RiskLevel           = 'High'
                        Impact              = 'Security events not logged, incident response impaired'
                        AttackVector        = 'Attackers can operate undetected without proper logging'
                    }
                }
            } catch {
                $findings += [PSCustomObject]@{
                    DomainController    = $dc.Name
                    OperatingSystem     = $dc.OperatingSystem
                    AuditIssues         = @([PSCustomObject]@{
                        Category     = 'Error'
                        Subcategory  = "Unable to check: $_"
                        CurrentState = 'Unknown'
                        Required     = 'Manual verification'
                        CISRef       = 'Multiple'
                    })
                    IssueCount          = 1
                    RiskLevel           = 'Unknown'
                    Impact              = 'Audit policy status unknown'
                    AttackVector        = 'Manual review required'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure comprehensive audit policies on all Domain Controllers via Group Policy. Enable success and failure auditing for critical security events.'
        Impact      = 'Low - Audit logging has minimal performance impact. Ensure adequate log storage and forwarding.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Configure Domain Controller Audit Policy
# DCs with Issues: $($Finding.Findings.Count)

# RECOMMENDED AUDIT POLICY (per CIS Benchmark):

# Option 1: Configure via Group Policy (Recommended)
# Computer Configuration > Policies > Windows Settings > Security Settings
# > Advanced Audit Policy Configuration

# Option 2: Configure via auditpol command:

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

# DS Access (critical for DCs)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Object Access (optional but recommended)
auditpol /set /subcategory:"File System" /failure:enable
auditpol /set /subcategory:"Registry" /failure:enable

# Verify configuration:
auditpol /get /category:*

# ALSO CONFIGURE:
# 1. Event log size (increase Security log to 1GB+)
wevtutil sl Security /ms:1073741824

# 2. Log retention (overwrite as needed or archive)
# 3. Forward logs to SIEM

# Apply to all DCs via GPO:
# Create GPO: "DC Security Audit Policy"
# Link to Domain Controllers OU

"@
            return $commands
        }
    }
}
