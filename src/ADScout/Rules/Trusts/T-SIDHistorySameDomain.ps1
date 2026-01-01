@{
    Id          = 'T-SIDHistorySameDomain'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'SID History Pointing to Same Domain'
    Description = 'User or computer accounts have SID History entries containing SIDs from the same domain. This is a strong indicator of a privilege escalation attack, as legitimate migrations would involve SIDs from different (source) domains.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'SID History Injection Attack'; Url = 'https://attack.mitre.org/techniques/T1134/005/' }
        @{ Title = 'SID History Abuse'; Url = 'https://adsecurity.org/?p=1772' }
        @{ Title = 'Detecting SID History Attacks'; Url = 'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-sids' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0004', 'TA0005')  # Persistence, Privilege Escalation, Defense Evasion
        Techniques = @('T1134.005')  # Access Token Manipulation: SID-History Injection
    }

    CIS   = @('5.27')
    STIG  = @('V-36437')
    ANSSI = @('vuln1_sid_history')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 40
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get the domain SID
        $domainSID = $null
        try {
            if ($Domain.DomainSID) {
                $domainSID = $Domain.DomainSID.Value
            } else {
                $domainSID = (Get-ADDomain).DomainSID.Value
            }
        } catch {
            # Try alternative method
            try {
                $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
                $searcher = [System.DirectoryServices.DirectorySearcher]::new()
                $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
                $searcher.Filter = "(objectClass=domainDNS)"
                $searcher.PropertiesToLoad.Add("objectSid") | Out-Null
                $result = $searcher.FindOne()
                if ($result) {
                    $sidBytes = $result.Properties["objectsid"][0]
                    $domainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                }
            } catch {
                return $findings  # Cannot determine domain SID
            }
        }

        if (-not $domainSID) { return $findings }

        # Check all users and computers for SID History
        foreach ($obj in $Data) {
            $sidHistory = $obj.SIDHistory

            if ($sidHistory -and $sidHistory.Count -gt 0) {
                foreach ($historySID in $sidHistory) {
                    $sidValue = if ($historySID -is [System.Security.Principal.SecurityIdentifier]) {
                        $historySID.Value
                    } elseif ($historySID -is [byte[]]) {
                        (New-Object System.Security.Principal.SecurityIdentifier($historySID, 0)).Value
                    } else {
                        $historySID.ToString()
                    }

                    # Extract the domain portion of the SID (everything before the last dash and RID)
                    if ($sidValue -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
                        $sidDomainPart = $Matches[1]
                        $currentDomainPart = $domainSID -replace '-\d+$', ''

                        # Check if SID History points to the same domain
                        if ($sidDomainPart -eq $currentDomainPart -or $sidValue.StartsWith($domainSID)) {
                            # This is suspicious - SID History from same domain
                            $findings += [PSCustomObject]@{
                                AccountName         = $obj.SamAccountName
                                DistinguishedName   = $obj.DistinguishedName
                                AccountSID          = $obj.SID
                                SIDHistoryEntry     = $sidValue
                                SIDHistoryDomain    = $sidDomainPart
                                CurrentDomainSID    = $domainSID
                                IsSameDomain        = $true
                                RiskLevel           = 'Critical'
                                AttackIndicator     = 'SID History Injection attack - immediate investigation required'
                                PotentialPrivileges = 'May grant access to any resource the historical SID could access'
                            }
                        }
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove SID History entries that point to the same domain as they indicate a potential attack. Investigate the account for compromise.'
        Impact      = 'Low - Removing malicious SID History has no legitimate impact. However, investigate the attack vector first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: SID History Injection Attack Detected
# Affected Accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): SID History $($_.SIDHistoryEntry)" } | Out-String)

# IMMEDIATE ACTIONS REQUIRED:
# 1. Investigate how the SID History was added (requires Domain Admin or migration tools)
# 2. Check for compromise of accounts with SIDHistory write permissions
# 3. Review security logs for SID History modification events (Event ID 4765, 4766)

# Remove SID History from affected accounts:
foreach (`$account in @('$($Finding.Findings.AccountName -join "','")')) {
    try {
        `$user = Get-ADUser -Identity `$account -Properties SIDHistory

        # Log current SID History for forensics
        Write-Host "Account: `$account"
        Write-Host "Current SID History: `$(`$user.SIDHistory -join ', ')"

        # Clear SID History (requires appropriate permissions)
        Set-ADUser -Identity `$account -Remove @{SIDHistory = `$user.SIDHistory}

        Write-Host "SID History cleared for `$account"
    } catch {
        Write-Warning "Failed to clear SID History for `$account: `$_"
    }
}

# Verify removal:
Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory |
    Select-Object SamAccountName, SIDHistory

# Investigate the attack:
# 1. Check who has permissions to modify SID History
# 2. Review Event ID 4765 (SID History added) in Security logs
# 3. Check for mimikatz or similar tool artifacts
# 4. Consider the account as potentially compromised

"@
            return $commands
        }
    }
}
