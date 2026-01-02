@{
    Id          = 'A-AuditDCGPO'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Domain Controllers Missing Audit Policy GPO'
    Description = 'Detects when Domain Controllers are not covered by a GPO that configures security auditing. Proper auditing is essential for detecting attacks and forensic investigation.'
    Severity    = 'Medium'
    Weight      = 25
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Windows Security Auditing'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing' }
        @{ Title = 'CIS Benchmark Auditing'; Url = 'https://www.cisecurity.org/benchmark/microsoft_windows_server' }
        @{ Title = 'PingCastle Rule A-AuditDCGPO'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.002')  # Impair Defenses: Disable Windows Event Logging
    }

    CIS   = @()  # CIS Chapter 17 covers auditing - specific controls vary by OS
    STIG  = @()  # Audit STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('AU-2', 'AU-3', 'AU-6', 'AU-12')  # Audit Events, Content, Review, Generation

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Critical audit categories that should be configured
        $requiredAuditCategories = @{
            'AuditAccountLogon' = 'Account Logon events (credential validation)'
            'AuditAccountManage' = 'Account Management (user/group changes)'
            'AuditDSAccess' = 'Directory Service Access (AD object access)'
            'AuditLogonEvents' = 'Logon/Logoff events'
            'AuditObjectAccess' = 'Object Access (file, registry)'
            'AuditPolicyChange' = 'Policy Change events'
            'AuditPrivilegeUse' = 'Privilege Use (sensitive privileges)'
            'AuditSystemEvents' = 'System events'
        }

        # Advanced audit policies (preferred)
        $advancedAuditPolicies = @(
            'Credential Validation',
            'Kerberos Authentication Service',
            'Kerberos Service Ticket Operations',
            'Computer Account Management',
            'Security Group Management',
            'User Account Management',
            'Directory Service Access',
            'Directory Service Changes',
            'Logon',
            'Logoff',
            'Special Logon',
            'Audit Policy Change',
            'Sensitive Privilege Use'
        )

        $auditGPOFound = $false
        $auditSettings = @{}

        try {
            foreach ($gpo in $Data.GPOs) {
                $gpoName = $gpo.DisplayName
                $gpoPath = $gpo.Path

                if (-not $gpoPath) { continue }

                # Check if GPO links to Domain Controllers OU
                $linkedToDC = $false
                if ($gpo.Links) {
                    foreach ($link in $gpo.Links) {
                        if ($link -match 'Domain Controllers|OU=Domain Controllers') {
                            $linkedToDC = $true
                            break
                        }
                    }
                }

                # Check GptTmpl.inf for audit settings
                $securityInfPath = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $securityInfPath -ErrorAction SilentlyContinue) {
                    $content = Get-Content $securityInfPath -Raw -ErrorAction SilentlyContinue

                    if ($content -match '\[Event Audit\]') {
                        foreach ($category in $requiredAuditCategories.Keys) {
                            if ($content -match "$category\s*=\s*(\d+)") {
                                $value = [int]$Matches[1]
                                if ($value -gt 0) {
                                    $auditGPOFound = $true
                                    $auditSettings[$category] = @{
                                        GPO = $gpoName
                                        Value = $value
                                        LinkedToDC = $linkedToDC
                                    }
                                }
                            }
                        }
                    }
                }

                # Check for advanced audit policy (audit.csv)
                $auditCsvPath = "$gpoPath\Machine\Microsoft\Windows NT\Audit\audit.csv"
                if (Test-Path $auditCsvPath -ErrorAction SilentlyContinue) {
                    $auditGPOFound = $true
                    $auditSettings['AdvancedAudit'] = @{
                        GPO = $gpoName
                        LinkedToDC = $linkedToDC
                    }
                }
            }

            if (-not $auditGPOFound) {
                $findings += [PSCustomObject]@{
                    Issue               = 'No audit policy GPO found'
                    Severity            = 'High'
                    Risk                = 'Domain Controllers have no security auditing configured via GPO'
                    Impact              = 'Attacks may go undetected, forensics severely limited'
                    MissingCategories   = ($requiredAuditCategories.Keys -join ', ')
                    Recommendation      = 'Create and link an audit policy GPO to Domain Controllers OU'
                }
            } else {
                # Check for missing categories
                $missingCategories = @()
                foreach ($category in $requiredAuditCategories.Keys) {
                    if (-not $auditSettings.ContainsKey($category) -and -not $auditSettings.ContainsKey('AdvancedAudit')) {
                        $missingCategories += $category
                    }
                }

                if ($missingCategories.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Issue               = 'Incomplete audit policy'
                        Severity            = 'Medium'
                        Risk                = 'Some audit categories not configured'
                        MissingCategories   = ($missingCategories -join ', ')
                        ConfiguredSettings  = ($auditSettings.Keys -join ', ')
                        Recommendation      = 'Enable all recommended audit categories'
                    }
                }

                # Check if GPO is linked to DC OU
                $notLinkedToDC = $auditSettings.Values | Where-Object { -not $_.LinkedToDC }
                if ($notLinkedToDC -and -not ($auditSettings.Values | Where-Object { $_.LinkedToDC })) {
                    $findings += [PSCustomObject]@{
                        Issue               = 'Audit GPO not linked to Domain Controllers'
                        Severity            = 'Medium'
                        Risk                = 'Audit policy GPO exists but may not apply to DCs'
                        GPOsWithAudit       = ($auditSettings.Values | ForEach-Object { $_.GPO } | Select-Object -Unique) -join ', '
                        Recommendation      = 'Link audit GPO to Domain Controllers OU'
                    }
                }
            }

        } catch {
            Write-Verbose "A-AuditDCGPO: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Create or update a GPO with comprehensive audit policies and link it to the Domain Controllers OU.'
        Impact      = 'Low - Enabling auditing has minimal performance impact. May increase log volume.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Domain Controller Audit Policy Remediation
#
# Issues found:
$($Finding.Findings | ForEach-Object { "# - $($_.Issue): $($_.Risk)" } | Out-String)

# STEP 1: Create a new GPO for DC auditing
`$gpoName = "DC-Security-Auditing"
`$gpo = New-GPO -Name `$gpoName -Comment "Security auditing for Domain Controllers"
Write-Host "Created GPO: `$gpoName" -ForegroundColor Green

# STEP 2: Link to Domain Controllers OU
`$dcOU = "OU=Domain Controllers," + (Get-ADDomain).DistinguishedName
New-GPLink -Name `$gpoName -Target `$dcOU
Write-Host "Linked to: `$dcOU" -ForegroundColor Green

# STEP 3: Configure Advanced Audit Policies (preferred over basic)
# These are configured via auditpol, but we can also use GPMC

# Create audit.csv content for advanced audit policy
`$auditPolicy = @"

Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Logon/Logoff,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Logon/Logoff,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1
,Logon/Logoff,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success,,1
,Logon/Logoff,Other Logon/Logoff Events,{0CCE921C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Object Access,File System,{0CCE921D-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Object Access,Registry,{0CCE921E-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Object Access,SAM,{0CCE9220-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Privilege Use,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Management,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Management,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Management,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,,3
,DS Access,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,DS Access,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Logon,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Logon,Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Account Logon,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Policy Change,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,Policy Change,Authentication Policy Change,{0CCE9230-69AE-11D9-BED3-505054503030},Success,,1
"@

# Get GPO path and create audit.csv
`$gpoId = `$gpo.Id.Guid
`$sysvolPath = "\\`$env:USERDNSDOMAIN\SYSVOL\`$env:USERDNSDOMAIN\Policies\{`$gpoId}\Machine\Microsoft\Windows NT\Audit"

New-Item -Path `$sysvolPath -ItemType Directory -Force | Out-Null
`$auditPolicy | Set-Content -Path "`$sysvolPath\audit.csv" -Encoding Unicode
Write-Host "Created advanced audit policy" -ForegroundColor Green

# STEP 4: Enable "Force audit policy subcategory settings"
# This ensures advanced audit policy is used instead of basic

# Via GPO:
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > Security Options >
# "Audit: Force audit policy subcategory settings to override audit policy category settings"

# STEP 5: Configure Security Event Log size
# Recommended: At least 4GB for DCs
Set-GPRegistryValue -Name `$gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
    -ValueName "MaxSize" -Type DWord -Value 4194304000

# STEP 6: Force Group Policy update on DCs
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Write-Host "Updating GPO on `$(`$dc.Name)..."
    Invoke-GPUpdate -Computer `$dc.HostName -Force -RandomDelayInMinutes 0
}

# STEP 7: Verify audit policy on a DC
Write-Host "`nVerifying audit policy..." -ForegroundColor Yellow
auditpol /get /category:*

# STEP 8: Key events to monitor
Write-Host @"

Key Security Events for Domain Controllers:
- 4624/4625: Successful/Failed logon
- 4648: Explicit credential logon
- 4662: Object access (with DCSync detection)
- 4670: Permissions changed
- 4672: Special privileges assigned
- 4720: User account created
- 4728/4732/4756: Member added to security groups
- 4768: Kerberos TGT requested
- 4769: Kerberos service ticket requested
- 4776: Credential validation
- 5136: Directory object modified
- 5137: Directory object created

"@ -ForegroundColor Cyan

"@
            return $commands
        }
    }
}
