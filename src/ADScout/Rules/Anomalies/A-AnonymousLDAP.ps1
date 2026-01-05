@{
    Id          = 'A-AnonymousLDAP'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Anonymous LDAP Access Enabled'
    Description = 'Detects if anonymous LDAP access is enabled on Domain Controllers. This allows unauthenticated users to query AD information, potentially exposing usernames, group memberships, and other sensitive directory data.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Anonymous LDAP'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sid-name-translation' }
        @{ Title = 'LDAP Reconnaissance'; Url = 'https://attack.mitre.org/techniques/T1087/002/' }
    )

    MITRE = @{
        Tactics    = @('TA0007', 'TA0043')  # Discovery, Reconnaissance
        Techniques = @('T1087.002', 'T1069.002')  # Domain Account Discovery, Domain Groups
    }

    CIS   = @('2.3.10.2')
    STIG  = @('V-220928')
    ANSSI = @('R29')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $domainDN = (Get-ADDomain).DistinguishedName

            # Check dsHeuristics for anonymous access flag
            $configDN = (Get-ADRootDSE).configurationNamingContext
            $directoryService = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configDN" -Properties dsHeuristics -ErrorAction SilentlyContinue

            if ($directoryService -and $directoryService.dsHeuristics) {
                $dsHeuristics = $directoryService.dsHeuristics

                # 7th character: fLDAPBlockAnonOps (0 = allow anonymous, 2 = block)
                if ($dsHeuristics.Length -ge 7) {
                    $anonFlag = $dsHeuristics[6]
                    if ($anonFlag -ne '2') {
                        $findings += [PSCustomObject]@{
                            CheckType           = 'dsHeuristics'
                            CurrentValue        = $dsHeuristics
                            AnonymousFlag       = $anonFlag
                            RiskLevel           = 'High'
                            Issue               = 'Anonymous LDAP operations may be allowed'
                            Impact              = 'Unauthenticated users can enumerate AD'
                        }
                    }
                }
            }

            # Check for anonymous SID/Name translation
            try {
                $anonSidTranslation = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -ErrorAction SilentlyContinue
                if ($anonSidTranslation -and $anonSidTranslation.TurnOffAnonymousBlock -eq 1) {
                    $findings += [PSCustomObject]@{
                        CheckType           = 'Anonymous SID Translation'
                        RegistryPath        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\TurnOffAnonymousBlock'
                        CurrentValue        = $anonSidTranslation.TurnOffAnonymousBlock
                        RiskLevel           = 'High'
                        Issue               = 'Anonymous SID/Name translation is allowed'
                        Impact              = 'Anonymous users can resolve SIDs to usernames'
                    }
                }
            }
            catch { }

            # Check RestrictAnonymous settings
            try {
                $restrictAnon = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue
                if ($null -eq $restrictAnon -or $restrictAnon.RestrictAnonymous -lt 1) {
                    $findings += [PSCustomObject]@{
                        CheckType           = 'RestrictAnonymous'
                        RegistryPath        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous'
                        CurrentValue        = if ($restrictAnon) { $restrictAnon.RestrictAnonymous } else { 'Not Set' }
                        RequiredValue       = '1 or 2'
                        RiskLevel           = 'Medium'
                        Issue               = 'Anonymous enumeration may be possible'
                    }
                }

                $restrictAnonSAM = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue
                if ($null -eq $restrictAnonSAM -or $restrictAnonSAM.RestrictAnonymousSAM -ne 1) {
                    $findings += [PSCustomObject]@{
                        CheckType           = 'RestrictAnonymousSAM'
                        RegistryPath        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'
                        CurrentValue        = if ($restrictAnonSAM) { $restrictAnonSAM.RestrictAnonymousSAM } else { 'Not Set' }
                        RequiredValue       = '1'
                        RiskLevel           = 'Medium'
                        Issue               = 'Anonymous SAM enumeration may be possible'
                    }
                }
            }
            catch { }
        }
        catch {
            # Could not check settings
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable anonymous LDAP access and enumeration on all Domain Controllers.'
        Impact      = 'Low - Anonymous access should not be needed in modern environments'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# ANONYMOUS LDAP ACCESS
# ================================================================
# Anonymous LDAP allows unauthenticated enumeration of:
# - User accounts and attributes
# - Group memberships
# - Computer accounts
# - Password policies
# - Domain structure

# This aids attackers in reconnaissance without any credentials.

# ================================================================
# CURRENT STATUS
# ================================================================

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Check: $($item.CheckType)
# Current Value: $($item.CurrentValue)
# Risk: $($item.RiskLevel)
# Issue: $($item.Issue)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION
# ================================================================

# 1. BLOCK ANONYMOUS LDAP OPERATIONS
# Set 7th character of dsHeuristics to '2'

`$configDN = (Get-ADRootDSE).configurationNamingContext
`$dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,`$configDN"
`$currentValue = (Get-ADObject -Identity `$dsPath -Properties dsHeuristics).dsHeuristics

# Ensure string is long enough and set 7th char to '2'
# Be careful - this affects multiple settings!
# Consult Microsoft docs before modifying

# 2. RESTRICT ANONYMOUS SID/NAME TRANSLATION
# GPO: Network access: Allow anonymous SID/Name translation = Disabled

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -Value 0 -Type DWord

# 3. RESTRICT ANONYMOUS ENUMERATION
# GPO: Network access: Do not allow anonymous enumeration of SAM accounts

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord

# GPO: Network access: Do not allow anonymous enumeration of SAM accounts and shares

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord

# ================================================================
# GPO SETTINGS
# ================================================================

# In Group Policy:
# Computer Configuration
# -> Policies
# -> Windows Settings
# -> Security Settings
# -> Local Policies
# -> Security Options

# Configure:
# - Network access: Allow anonymous SID/Name translation -> Disabled
# - Network access: Do not allow anonymous enumeration of SAM accounts -> Enabled
# - Network access: Do not allow anonymous enumeration of SAM accounts and shares -> Enabled
# - Network access: Let Everyone permissions apply to anonymous users -> Disabled

# ================================================================
# VERIFICATION
# ================================================================

# Test anonymous LDAP from Linux:
# ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=com" -s sub "(objectClass=*)"
# Should return: "Operations error" or similar

# Test from Windows (no credentials):
# [System.DirectoryServices.DirectoryEntry]::new("LDAP://DC_IP")
# Should fail if properly configured

"@
            return $commands
        }
    }
}
