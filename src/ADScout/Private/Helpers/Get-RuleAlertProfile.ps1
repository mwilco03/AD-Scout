function Get-RuleAlertProfile {
    <#
    .SYNOPSIS
        Determines the alert profile for a rule based on its detection techniques.

    .DESCRIPTION
        Analyzes a rule's Detect scriptblock and DataSource to classify its
        operational footprint as Stealth, Moderate, or Noisy.

        This helps operators select appropriate rules for different assessment
        scenarios and provides customers with whitelist guidance.

    .PARAMETER Rule
        The rule object to analyze.

    .OUTPUTS
        String - 'Stealth', 'Moderate', or 'Noisy'

    .NOTES
        Alert Profiles:
        - Stealth: Read-only LDAP, minimal logging footprint
        - Moderate: Enhanced queries, ACL reads, GPO parsing
        - Noisy: Remote execution, PSRemoting, triggers security events
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Rule
    )

    # If rule explicitly defines AlertProfile, use it
    if ($Rule.AlertProfile) {
        return $Rule.AlertProfile
    }

    # Patterns that indicate Noisy rules (high detection risk)
    $noisyPatterns = @(
        'Invoke-Command',
        'Invoke-CimMethod',
        'Get-WmiObject',
        'Invoke-WmiMethod',
        'Enter-PSSession',
        'New-PSSession',
        'Get-CimInstance.*-ComputerName',
        'Get-Service.*-ComputerName',
        'Get-Process.*-ComputerName',
        'Test-NetConnection',
        'Get-NetTCPConnection',
        'Get-ItemProperty.*HKLM:.*-ComputerName',
        'Remote-Registry',
        '-ComputerName\s+\$',
        'Invoke-Expression',
        'Start-Process.*-ComputerName',
        'Get-MpComputerStatus',
        'Get-ScheduledTask.*-CimSession',
        'Get-WinEvent.*-ComputerName'
    )

    # Patterns that indicate Moderate rules
    $moderatePatterns = @(
        'Get-Acl',
        'Get-ADObject.*-Properties.*nTSecurityDescriptor',
        '\[System\.DirectoryServices\.ActiveDirectorySecurity\]',
        'Get-GPO',
        'Get-GPPermission',
        'Get-GPOReport',
        'Get-ADReplicationSite',
        '\[ADSI\].*LDAP://CN=Configuration',
        '\[ADSI\].*LDAP://CN=Schema',
        'Get-ADRootDSE',
        'Get-ADOptionalFeature',
        'certutil',
        'Get-CertificateTemplate',
        'Get-CATemplate',
        'SYSVOL',
        'Get-ChildItem.*\\\\.*SYSVOL',
        'Get-Content.*\\\\.*SYSVOL',
        'Get-Content.*\.xml'
    )

    # DataSources that indicate Noisy rules
    $noisyDataSources = @(
        'EndpointSecurity',
        'RemoteRegistry',
        'RemoteService',
        'RemoteProcess',
        'RemoteScheduledTask',
        'RemoteEventLog'
    )

    # DataSources that indicate Moderate rules
    $moderateDataSources = @(
        'GPO',
        'PKI',
        'Certificates',
        'ACL',
        'Schema',
        'Configuration'
    )

    # Get the scriptblock content for analysis
    $scriptContent = ''
    if ($Rule.Detect) {
        $scriptContent = $Rule.Detect.ToString()
    } elseif ($Rule.ScriptBlock) {
        $scriptContent = $Rule.ScriptBlock.ToString()
    }

    # Check DataSource first
    $dataSource = $Rule.DataSource -split ',' | ForEach-Object { $_.Trim() }

    foreach ($ds in $dataSource) {
        if ($ds -in $noisyDataSources) {
            return 'Noisy'
        }
    }

    # Check for noisy patterns in scriptblock
    foreach ($pattern in $noisyPatterns) {
        if ($scriptContent -match $pattern) {
            return 'Noisy'
        }
    }

    # Check for moderate datasources
    foreach ($ds in $dataSource) {
        if ($ds -in $moderateDataSources) {
            return 'Moderate'
        }
    }

    # Check for moderate patterns in scriptblock
    foreach ($pattern in $moderatePatterns) {
        if ($scriptContent -match $pattern) {
            return 'Moderate'
        }
    }

    # Default to Stealth for standard LDAP-only rules
    return 'Stealth'
}

function Get-AlertProfileDescription {
    <#
    .SYNOPSIS
        Returns human-readable description for an alert profile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Stealth', 'Moderate', 'Noisy')]
        [string]$Profile
    )

    switch ($Profile) {
        'Stealth' {
            @{
                Name        = 'Stealth'
                Description = 'Read-only LDAP queries with minimal logging footprint'
                RiskLevel   = 'Low'
                Techniques  = @('LDAP queries', 'Get-AD* cmdlets', 'DirectorySearcher')
                Alerts      = @('Minimal - blends with normal admin activity')
                Whitelist   = @('Generally not required')
            }
        }
        'Moderate' {
            @{
                Name        = 'Moderate'
                Description = 'Enhanced AD queries including ACLs, GPO content, and configuration'
                RiskLevel   = 'Medium'
                Techniques  = @('Get-Acl', 'GPO parsing', 'SYSVOL reads', 'Schema queries')
                Alerts      = @('AD audit logs (4662)', 'File access on SYSVOL')
                Whitelist   = @('Consider time-boxed exclusions for assessment account')
            }
        }
        'Noisy' {
            @{
                Name        = 'Noisy'
                Description = 'Remote execution and privileged operations that trigger security events'
                RiskLevel   = 'High'
                Techniques  = @('Invoke-Command', 'PSRemoting', 'Remote WMI/CIM', 'Registry access')
                Alerts      = @(
                    'PowerShell remoting (Event 91, 168)'
                    'Process creation (4688)'
                    'Logon events (4624, 4648)'
                    'EDR process injection/enumeration alerts'
                )
                Whitelist   = @(
                    'Required: Create assessment exclusion window'
                    'Notify SOC before execution'
                    'Pre-approve PSRemoting from assessment host'
                )
            }
        }
    }
}
