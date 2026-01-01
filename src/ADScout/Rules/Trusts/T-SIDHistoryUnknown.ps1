@{
    Id          = 'T-SIDHistoryUnknown'
    Version     = '1.0.0'
    Category    = 'Trusts'
    Title       = 'SID History from Unknown or Untrusted Domain'
    Description = 'User accounts have SID History entries containing SIDs from domains that cannot be resolved or are no longer trusted. This may indicate orphaned entries from old migrations or potentially injected SIDs for persistence.'
    Severity    = 'Medium'
    Weight      = 20
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'SID History Abuse'; Url = 'https://attack.mitre.org/techniques/T1134/005/' }
        @{ Title = 'Cleaning Up SID History'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779590(v=ws.10)' }
        @{ Title = 'Migration Cleanup'; Url = 'https://adsecurity.org/?p=1772' }
    )

    MITRE = @{
        Tactics    = @('TA0003', 'TA0005')  # Persistence, Defense Evasion
        Techniques = @('T1134.005')  # Access Token Manipulation: SID-History Injection
    }

    CIS   = @('5.27')
    STIG  = @('V-36437')
    ANSSI = @('vuln2_sid_history_orphan')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 10
        MaxPoints = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Get known trusted domains
        $trustedDomainSIDs = @()
        try {
            $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
            foreach ($trust in $trusts) {
                if ($trust.SecurityIdentifier) {
                    $trustedDomainSIDs += $trust.SecurityIdentifier.Value
                }
            }
        } catch {
            # Can't enumerate trusts, will rely on resolution
        }

        # Get current domain SID
        $currentDomainSID = $null
        try {
            if ($Domain.DomainSID) {
                $currentDomainSID = $Domain.DomainSID.Value
            } else {
                $currentDomainSID = (Get-ADDomain -ErrorAction SilentlyContinue).DomainSID.Value
            }
        } catch { }

        foreach ($user in $Data) {
            $sidHistory = $user.SIDHistory
            if (-not $sidHistory -or $sidHistory.Count -eq 0) { continue }

            foreach ($historySID in $sidHistory) {
                $sidValue = if ($historySID -is [System.Security.Principal.SecurityIdentifier]) {
                    $historySID.Value
                } elseif ($historySID -is [byte[]]) {
                    try {
                        (New-Object System.Security.Principal.SecurityIdentifier($historySID, 0)).Value
                    } catch { continue }
                } else {
                    $historySID.ToString()
                }

                # Extract domain portion of SID
                if ($sidValue -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
                    $sidDomainPart = $Matches[1]

                    # Check if it's the current domain (handled by T-SIDHistorySameDomain)
                    if ($currentDomainSID -and $sidValue.StartsWith($currentDomainSID)) {
                        continue
                    }

                    # Check if it's a known trusted domain
                    $isTrusted = $trustedDomainSIDs | Where-Object { $sidDomainPart -eq $_ }

                    if (-not $isTrusted) {
                        # Try to resolve the SID
                        $resolved = $null
                        try {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
                            $resolved = $sid.Translate([System.Security.Principal.NTAccount]).Value
                        } catch {
                            $resolved = $null
                        }

                        $findings += [PSCustomObject]@{
                            AccountName         = $user.SamAccountName
                            DistinguishedName   = $user.DistinguishedName
                            AccountSID          = $user.SID
                            SIDHistoryEntry     = $sidValue
                            SIDHistoryDomain    = $sidDomainPart
                            Resolved            = if ($resolved) { $resolved } else { 'Unresolvable' }
                            IsTrustedDomain     = $false
                            RiskLevel           = if (-not $resolved) { 'Medium' } else { 'Low' }
                            PotentialIssue      = if (-not $resolved) { 'SID from unknown/defunct domain - possible orphan or injected SID' } else { 'SID from non-trusted domain' }
                            Recommendation      = 'Investigate origin and remove if no longer needed'
                        }
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review and clean up SID History entries from unknown or untrusted domains. Remove entries that are no longer needed after migrations are complete.'
        Impact      = 'Low - Removing orphaned SID History has no impact. Removing valid entries may affect access to resources in source domains.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Clean Up Unknown SID History Entries
# Accounts with Unknown SID History: $($Finding.Findings.Count)

# Affected Accounts:
$($Finding.Findings | ForEach-Object { "# - $($_.AccountName): SID $($_.SIDHistoryEntry) (Domain: $($_.SIDHistoryDomain)) - $($_.PotentialIssue)" } | Out-String)

# INVESTIGATION STEPS:

# 1. Identify the source domain for each SID
# Check historical documentation for domain migrations
# Domain SID portion: $($Finding.Findings[0].SIDHistoryDomain)

# 2. Verify if these are from legitimate migrations
# Common scenarios:
# - Migration from legacy domain that's been decommissioned
# - Merger/acquisition migrations
# - Forest restructuring

# 3. Check if the SID History is still needed
# Test resource access before and after removal

# CLEANUP:

# Remove SID History for accounts that no longer need it:
foreach (`$account in @('$($Finding.Findings.AccountName -join "','")')) {
    `$user = Get-ADUser -Identity `$account -Properties SIDHistory

    if (`$user.SIDHistory) {
        Write-Host "Account: `$account"
        Write-Host "Current SID History:"
        `$user.SIDHistory | ForEach-Object { Write-Host "  - `$_" }

        # Remove all SID History (use cautiously)
        # Set-ADUser -Identity `$account -Remove @{SIDHistory = `$user.SIDHistory}

        # Or remove specific SIDs
        # `$sidToRemove = [System.Security.Principal.SecurityIdentifier]"S-1-5-21-xxx"
        # Set-ADUser -Identity `$account -Remove @{SIDHistory = `$sidToRemove}
    }
}

# Verify cleanup:
Get-ADUser -Filter 'SIDHistory -like "*"' -Properties SIDHistory |
    Select-Object SamAccountName, @{N='SIDHistoryCount';E={`$_.SIDHistory.Count}}

# POST-CLEANUP:
# - Test user access to resources
# - Monitor for access denied errors
# - Document changes for audit trail

"@
            return $commands
        }
    }
}
