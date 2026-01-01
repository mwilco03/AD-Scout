@{
    Id          = 'P-DsHeuristicsAdminSDExMask'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'AdminSDHolder Protection Disabled via dsHeuristics'
    Description = 'Detects when the dsHeuristics attribute has been configured to exclude certain groups from AdminSDHolder protection. This weakens the security of privileged groups by preventing the SDProp process from resetting their ACLs.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AdminSDHolder and SDProp'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
        @{ Title = 'dsHeuristics Attribute'; Url = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5' }
        @{ Title = 'PingCastle Rule P-DsHeuristicsAdminSDExMask'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion
        Techniques = @('T1222.001', 'T1562.001')  # File and Directory Permissions Modification, Disable or Modify Tools
    }

    CIS   = @('5.6')
    STIG  = @('V-63337')
    ANSSI = @('vuln1_dsheuristics_adminsd')
    NIST  = @('AC-3', 'AC-6')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Group bit positions in dsHeuristics character 16 (AdminSDExMask)
        # Each bit disables AdminSDHolder protection for a specific group
        $protectedGroups = @{
            0x01 = 'Account Operators'
            0x02 = 'Server Operators'
            0x04 = 'Print Operators'
            0x08 = 'Backup Operators'
        }

        try {
            # Get the Directory Service object
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $configNC = $rootDSE.configurationNamingContext.ToString()

            $dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            $dsService = [ADSI]"LDAP://$dsServiceDN"

            $dsHeuristics = $dsService.dsHeuristics

            if ($dsHeuristics -and $dsHeuristics.ToString().Length -ge 16) {
                $heuristicsValue = $dsHeuristics.ToString()

                # Character 16 (index 15) is the AdminSDExMask
                $adminSDExMask = $heuristicsValue[15]

                # Convert character to numeric value
                $maskValue = 0
                if ($adminSDExMask -match '[0-9]') {
                    $maskValue = [int]::Parse($adminSDExMask.ToString())
                } elseif ($adminSDExMask -match '[a-fA-F]') {
                    $maskValue = [Convert]::ToInt32($adminSDExMask.ToString(), 16)
                }

                if ($maskValue -gt 0) {
                    $excludedGroups = @()

                    foreach ($bit in $protectedGroups.Keys) {
                        if ($maskValue -band $bit) {
                            $excludedGroups += $protectedGroups[$bit]
                        }
                    }

                    if ($excludedGroups.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            DsHeuristics        = $heuristicsValue
                            AdminSDExMask       = $adminSDExMask
                            MaskValue           = $maskValue
                            ExcludedGroups      = $excludedGroups -join ', '
                            ExcludedGroupCount  = $excludedGroups.Count
                            Severity            = 'Critical'
                            Risk                = 'Protected groups excluded from AdminSDHolder protection'
                            Impact              = "ACL changes on $($excludedGroups -join ', ') will NOT be automatically reverted"
                            AttackScenario      = 'Attacker can modify permissions on excluded groups without SDProp reverting changes'
                        }
                    }
                }

                # Also check character 7 for DoListObject (index 6)
                if ($heuristicsValue.Length -ge 7) {
                    $doListObject = $heuristicsValue[6]
                    if ($doListObject -eq '1') {
                        $findings += [PSCustomObject]@{
                            DsHeuristics        = $heuristicsValue
                            Setting             = 'fDoListObject'
                            Value               = '1'
                            Severity            = 'Medium'
                            Risk                = 'DoListObject mode is enabled'
                            Impact              = 'Enables additional access control checking but may have performance impact'
                            AttackScenario      = 'N/A - This is informational'
                        }
                    }
                }
            }

        } catch {
            Write-Verbose "P-DsHeuristicsAdminSDExMask: Error checking dsHeuristics - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Reset the dsHeuristics attribute to remove the AdminSDExMask exclusions. All protected groups should be covered by AdminSDHolder protection.'
        Impact      = 'Low - Restoring protection improves security. May affect delegated administration to excluded groups if ACLs were intentionally modified.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# AdminSDHolder Protection Bypass Remediation
#
# Current dsHeuristics configuration:
$($Finding.Findings | ForEach-Object { "# dsHeuristics: $($_.DsHeuristics)`n# Excluded Groups: $($_.ExcludedGroups)" } | Out-String)

# The AdminSDExMask in dsHeuristics (character 16) controls which groups
# are excluded from AdminSDHolder protection:
# Bit 0 (value 1): Account Operators
# Bit 1 (value 2): Server Operators
# Bit 2 (value 4): Print Operators
# Bit 3 (value 8): Backup Operators

# STEP 1: View current dsHeuristics value
`$configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
`$dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,`$configNC"
`$dsService = [ADSI]"LDAP://`$dsServiceDN"
Write-Host "Current dsHeuristics: `$(`$dsService.dsHeuristics)"

# STEP 2: Reset AdminSDExMask to 0 (protect all groups)
# The 16th character should be set to 0

`$currentValue = `$dsService.dsHeuristics.ToString()
if (`$currentValue.Length -ge 16) {
    # Replace character at position 16 with '0'
    `$newValue = `$currentValue.Substring(0, 15) + '0' + `$currentValue.Substring(16)
    `$dsService.Put("dsHeuristics", `$newValue)
    `$dsService.SetInfo()
    Write-Host "Updated dsHeuristics to: `$newValue"
} else {
    Write-Host "dsHeuristics value is too short to contain AdminSDExMask"
}

# STEP 3: Force SDProp to run and reset ACLs
# SDProp runs every 60 minutes by default
# To run immediately:
`$rootDSE = [ADSI]"LDAP://RootDSE"
`$rootDSE.Put("runProtectAdminGroupsTask", 1)
`$rootDSE.SetInfo()
Write-Host "SDProp task triggered"

# STEP 4: Verify protected groups have correct ACLs
`$protectedGroups = @(
    'Account Operators',
    'Server Operators',
    'Print Operators',
    'Backup Operators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins'
)

foreach (`$group in `$protectedGroups) {
    try {
        `$grp = Get-ADGroup `$group
        `$acl = Get-Acl "AD:\`$(`$grp.DistinguishedName)"
        Write-Host "`n`$group ACL count: `$(`$acl.Access.Count)"
    } catch {
        Write-Host "Could not check `$group"
    }
}

# STEP 5: Compare with AdminSDHolder template
`$domainDN = (Get-ADDomain).DistinguishedName
`$adminSDHolderDN = "CN=AdminSDHolder,CN=System,`$domainDN"
`$templateAcl = Get-Acl "AD:\`$adminSDHolderDN"
Write-Host "`nAdminSDHolder template ACL count: `$(`$templateAcl.Access.Count)"

"@
            return $commands
        }
    }
}
