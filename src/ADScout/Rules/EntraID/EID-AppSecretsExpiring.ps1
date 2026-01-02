<#
.SYNOPSIS
    Detects applications with expiring or expired credentials in Entra ID.

.DESCRIPTION
    Applications with expired credentials may cause service outages, while
    long-lived credentials without rotation create security risks. This rule
    identifies apps needing credential attention.

.NOTES
    Rule ID    : EID-AppSecretsExpiring
    Category   : EntraID
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'EID-AppSecretsExpiring'
    Version     = '1.0.0'
    Category    = 'EntraID'
    Title       = 'Application Credentials Expiring or Expired'
    Description = 'Identifies applications with client secrets or certificates that are expired or expiring within 30 days.'
    Severity    = 'Medium'
    Weight      = 30
    DataSource  = 'EntraApps'

    References  = @(
        @{ Title = 'Manage app credentials'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#option-3-create-a-new-application-secret' }
        @{ Title = 'Certificate credentials'; Url = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0040')  # Credential Access, Impact
        Techniques = @('T1528', 'T1499')    # Steal Application Access Token, Endpoint Denial of Service
    }

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 5
        MaxPoints = 50
    }

    Detect = {
        param($Data, $Domain)

        if (-not (Test-ADScoutGraphConnection)) {
            Write-Verbose "Microsoft Graph not connected. Skipping EID-AppSecretsExpiring."
            return @()
        }

        $findings = @()

        try {
            $apps = Get-ADScoutEntraAppData

            foreach ($app in $apps) {
                # Skip first-party Microsoft apps
                if ($app.IsFirstParty) { continue }

                # Skip apps without credentials
                if ($app.CredentialCount -eq 0) { continue }

                # Check for expired or expiring credentials
                $expiredCreds = $app.Credentials | Where-Object { $_.IsExpired -eq $true }
                $expiringCreds = $app.Credentials | Where-Object {
                    $_.IsExpired -eq $false -and $_.DaysUntilExpiry -le 30
                }

                if ($expiredCreds.Count -gt 0 -or $expiringCreds.Count -gt 0) {
                    $riskLevel = if ($expiredCreds.Count -gt 0) { 'High' } else { 'Medium' }

                    $findings += [PSCustomObject]@{
                        AppId                 = $app.AppId
                        DisplayName           = $app.DisplayName
                        ServicePrincipalType  = $app.ServicePrincipalType
                        Enabled               = $app.Enabled
                        TotalCredentials      = $app.CredentialCount
                        ExpiredCredentials    = $expiredCreds.Count
                        ExpiringCredentials   = $expiringCreds.Count
                        ExpiredDetails        = ($expiredCreds | ForEach-Object {
                            "$($_.Type): $($_.DisplayName) expired $([Math]::Abs($_.DaysUntilExpiry)) days ago"
                        }) -join '; '
                        ExpiringDetails       = ($expiringCreds | ForEach-Object {
                            "$($_.Type): $($_.DisplayName) expires in $($_.DaysUntilExpiry) days"
                        }) -join '; '
                        RiskLevel             = $riskLevel
                        Recommendation        = if ($expiredCreds.Count -gt 0) {
                            'Rotate expired credentials immediately'
                        }
                        else {
                            'Plan credential rotation before expiration'
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error in EID-AppSecretsExpiring: $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Rotate expired credentials and plan regular rotation schedule.'
        Impact      = 'Medium - Requires updating apps with new credentials.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Rotate Application Credentials
#############################################################################
#
# Applications with credential issues:
$($Finding.Findings | ForEach-Object { "# - $($_.DisplayName): $($_.ExpiredCredentials) expired, $($_.ExpiringCredentials) expiring" } | Out-String)
#
#############################################################################
# Step 1: List All Credential Expiration Dates
#############################################################################

Connect-MgGraph -Scopes "Application.Read.All"

# Get all apps with credential info
`$apps = Get-MgApplication -All -Property Id,DisplayName,PasswordCredentials,KeyCredentials

`$credentialReport = foreach (`$app in `$apps) {
    foreach (`$cred in `$app.PasswordCredentials) {
        [PSCustomObject]@{
            AppName = `$app.DisplayName
            AppId = `$app.Id
            Type = 'ClientSecret'
            Name = `$cred.DisplayName
            StartDate = `$cred.StartDateTime
            EndDate = `$cred.EndDateTime
            DaysUntilExpiry = ((`$cred.EndDateTime) - (Get-Date)).Days
            Status = if (((`$cred.EndDateTime) - (Get-Date)).Days -lt 0) { 'Expired' }
                     elseif (((`$cred.EndDateTime) - (Get-Date)).Days -le 30) { 'Expiring' }
                     else { 'Valid' }
        }
    }
    foreach (`$cred in `$app.KeyCredentials) {
        [PSCustomObject]@{
            AppName = `$app.DisplayName
            AppId = `$app.Id
            Type = 'Certificate'
            Name = `$cred.DisplayName
            StartDate = `$cred.StartDateTime
            EndDate = `$cred.EndDateTime
            DaysUntilExpiry = ((`$cred.EndDateTime) - (Get-Date)).Days
            Status = if (((`$cred.EndDateTime) - (Get-Date)).Days -lt 0) { 'Expired' }
                     elseif (((`$cred.EndDateTime) - (Get-Date)).Days -le 30) { 'Expiring' }
                     else { 'Valid' }
        }
    }
}

`$credentialReport | Where-Object { `$_.Status -in @('Expired', 'Expiring') } |
    Sort-Object DaysUntilExpiry |
    Format-Table -AutoSize

#############################################################################
# Step 2: Add New Secret (Before Removing Old)
#############################################################################

Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Add new secret with appropriate lifetime (max 2 years recommended)
`$appId = "your-app-object-id"  # Use Object ID, not App ID

`$secretParams = @{
    passwordCredential = @{
        displayName = "Rotated-$(Get-Date -Format 'yyyyMMdd')"
        endDateTime = (Get-Date).AddMonths(12)
    }
}

`$newSecret = Add-MgApplicationPassword -ApplicationId `$appId -BodyParameter `$secretParams
Write-Host "New secret value: `$(`$newSecret.SecretText)" -ForegroundColor Cyan
Write-Host "Save this value securely - it cannot be retrieved later!" -ForegroundColor Yellow

#############################################################################
# Step 3: Update Application with New Secret
#############################################################################

# Update your application code/configuration with the new secret
# This varies by application - common locations:
# - Azure Key Vault (recommended)
# - App Service Application Settings
# - Azure DevOps Library
# - Environment variables

#############################################################################
# Step 4: Remove Old Secrets
#############################################################################

# After confirming the new secret works, remove old secrets
`$app = Get-MgApplication -ApplicationId `$appId
`$oldSecrets = `$app.PasswordCredentials | Where-Object {
    `$_.DisplayName -ne "Rotated-$(Get-Date -Format 'yyyyMMdd')"
}

foreach (`$oldSecret in `$oldSecrets) {
    Remove-MgApplicationPassword -ApplicationId `$appId -KeyId `$oldSecret.KeyId
    Write-Host "Removed old secret: `$(`$oldSecret.DisplayName)"
}

#############################################################################
# Step 5: Consider Using Certificates Instead
#############################################################################

# Certificates are more secure than secrets:
# - Can't be accidentally exposed in logs
# - Tied to specific machines
# - Support for managed identities

# For Azure resources, use Managed Identity when possible (no credentials!)

Write-Host "Complete credential rotation for all affected apps." -ForegroundColor Yellow
"@
            return $commands
        }
    }
}
