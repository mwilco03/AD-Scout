@{
    Id          = 'S-DuplicateSPN'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Duplicate Service Principal Names'
    Description = 'Multiple accounts share the same Service Principal Name (SPN). Duplicate SPNs cause Kerberos authentication failures and can indicate misconfigurations or stale accounts that should be cleaned up.'
    Severity    = 'Medium'
    Weight      = 10
    DataSource  = 'Users'

    References  = @(
        @{ Title = 'SPN Overview'; Url = 'https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names' }
        @{ Title = 'Troubleshooting SPNs'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-spn-issues' }
        @{ Title = 'setspn Tool'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1558.003')  # Kerberoasting
    }

    CIS   = @('5.5')
    STIG  = @()
    ANSSI = @('vuln2_duplicate_spn')
    NIST  = @('CM-8', 'IA-4')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 5
        MaxPoints = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()
        $spnMap = @{}

        # Collect all SPNs from all accounts
        foreach ($account in $Data) {
            $spns = $account.ServicePrincipalNames
            if (-not $spns) { $spns = $account.servicePrincipalName }
            if (-not $spns) { continue }

            foreach ($spn in $spns) {
                $spnNormalized = $spn.ToLower()

                if (-not $spnMap.ContainsKey($spnNormalized)) {
                    $spnMap[$spnNormalized] = @()
                }
                $spnMap[$spnNormalized] += [PSCustomObject]@{
                    AccountName       = $account.SamAccountName
                    DistinguishedName = $account.DistinguishedName
                    Enabled           = $account.Enabled
                    ObjectClass       = if ($account.ObjectClass) { $account.ObjectClass } else { 'user' }
                }
            }
        }

        # Find duplicates
        foreach ($spn in $spnMap.Keys) {
            $accounts = $spnMap[$spn]

            if ($accounts.Count -gt 1) {
                $enabledCount = ($accounts | Where-Object { $_.Enabled -ne $false }).Count

                $findings += [PSCustomObject]@{
                    DuplicateSPN      = $spn
                    AccountCount      = $accounts.Count
                    EnabledAccounts   = $enabledCount
                    Accounts          = ($accounts.AccountName -join ', ')
                    AccountDetails    = $accounts
                    RiskLevel         = if ($enabledCount -gt 1) { 'High' } else { 'Medium' }
                    Impact            = 'Kerberos authentication may fail unpredictably'
                    Recommendation    = 'Remove SPN from all but one account, preferably the active service account'
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove duplicate SPNs from inactive or incorrect accounts. Use setspn -X to detect duplicates and setspn -D to remove them.'
        Impact      = 'Low to Medium - Verify which account should own the SPN before removing from others.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Fix Duplicate Service Principal Names
# Duplicates Found: $($Finding.Findings.Count)

# Duplicate SPNs:
$($Finding.Findings | ForEach-Object { "# - $($_.DuplicateSPN): $($_.Accounts)" } | Out-String)

# Step 1: Use setspn to detect duplicates
setspn -X

# Step 2: Query specific duplicate SPNs
$($Finding.Findings | ForEach-Object { "setspn -Q $($_.DuplicateSPN)" } | Out-String)

# Step 3: Remove duplicates (keep on correct account)

# For each duplicate, determine which account is the active service:
# - Check which computer/service is actually running
# - Verify account is enabled and in use
# - Remove from other accounts

# Example removal:
# setspn -D "HTTP/webapp.domain.com" "OldServiceAccount"

# Using PowerShell:
# `$account = Get-ADUser -Identity "OldServiceAccount" -Properties ServicePrincipalNames
# Set-ADUser -Identity "OldServiceAccount" -ServicePrincipalNames @{Remove="HTTP/webapp.domain.com"}

# Step 4: Verify fix
setspn -X  # Should show no duplicates

# AUTOMATED CLEANUP (use with caution):
# This removes SPN from disabled accounts

foreach (`$dup in @(
$($Finding.Findings | ForEach-Object { "    @{SPN='$($_.DuplicateSPN)'; Accounts=@($($_.AccountDetails | ForEach-Object { "'$($_.AccountName)'" } | Out-String -NoNewline))}" } | Out-String -NoNewline)
)) {
    foreach (`$account in `$dup.Accounts) {
        `$adAccount = Get-ADUser -Identity `$account -Properties Enabled, ServicePrincipalNames -ErrorAction SilentlyContinue
        if (`$adAccount -and -not `$adAccount.Enabled) {
            Write-Host "Removing `$(`$dup.SPN) from disabled account: `$account"
            # Set-ADUser -Identity `$account -ServicePrincipalNames @{Remove=`$dup.SPN}
        }
    }
}

"@
            return $commands
        }
    }
}
