function Test-RemediationScript {
    <#
    .SYNOPSIS
        Validates and assesses risk of a remediation script before execution.

    .DESCRIPTION
        Parses remediation scripts to detect potentially dangerous commands,
        assess risk level, and validate syntax before execution.

    .PARAMETER Script
        The remediation script text to validate.

    .PARAMETER Finding
        The finding object associated with the remediation.

    .PARAMETER Rule
        The rule that generated the remediation.

    .OUTPUTS
        PSCustomObject with validation results including risk score and warnings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Script,

        [Parameter()]
        [PSCustomObject]$Finding,

        [Parameter()]
        [hashtable]$Rule
    )

    $result = @{
        IsValid       = $true
        RiskLevel     = 'Low'
        RiskScore     = 0
        Warnings      = @()
        Errors        = @()
        Commands      = @()
        AffectedCount = 1
        RequiresApproval = $false
    }

    # High-risk command patterns with scores
    $highRiskPatterns = @{
        'Remove-ADUser'           = @{ Score = 100; Message = "Deletes user accounts permanently" }
        'Remove-ADComputer'       = @{ Score = 100; Message = "Deletes computer accounts permanently" }
        'Remove-ADGroup'          = @{ Score = 90;  Message = "Deletes groups permanently" }
        'Remove-ADObject'         = @{ Score = 100; Message = "Deletes AD objects permanently" }
        'Remove-ADOrganizationalUnit' = @{ Score = 100; Message = "Deletes OUs permanently" }
        'Set-ADAccountPassword'   = @{ Score = 70;  Message = "Resets account passwords" }
        'Remove-ADGroupMember.*Domain Admins' = @{ Score = 80; Message = "Modifies Domain Admins group" }
        'Remove-ADGroupMember.*Enterprise Admins' = @{ Score = 90; Message = "Modifies Enterprise Admins group" }
        'Remove-ADGroupMember.*Schema Admins' = @{ Score = 90; Message = "Modifies Schema Admins group" }
        'Set-Acl'                 = @{ Score = 60;  Message = "Modifies security permissions" }
        'Remove-Item.*ntds'       = @{ Score = 100; Message = "Potentially affects AD database" }
        'Stop-Service.*NTDS'      = @{ Score = 100; Message = "Stops AD DS service" }
        'ForEach-Object\s*{[^}]*Remove-' = @{ Score = 80; Message = "Bulk delete operation detected" }
        '\|\s*Remove-'            = @{ Score = 75;  Message = "Piped delete operation detected" }
    }

    # Medium-risk patterns
    $mediumRiskPatterns = @{
        'Disable-ADAccount'       = @{ Score = 40; Message = "Disables accounts" }
        'Set-ADUser.*-Enabled.*\$false' = @{ Score = 40; Message = "Disables user accounts" }
        'Remove-ADGroupMember'    = @{ Score = 35; Message = "Removes group memberships" }
        'Set-ADUser.*-AccountExpirationDate' = @{ Score = 30; Message = "Sets account expiration" }
        'Move-ADObject'           = @{ Score = 25; Message = "Moves AD objects between OUs" }
        'Rename-ADObject'         = @{ Score = 25; Message = "Renames AD objects" }
        'Set-ADObject'            = @{ Score = 20; Message = "Modifies AD object properties" }
    }

    # Low-risk patterns (informational)
    $lowRiskPatterns = @{
        'Set-ADUser.*-PasswordNeverExpires.*\$false' = @{ Score = 5; Message = "Enables password expiration" }
        'Set-ADUser.*-PasswordNotRequired.*\$false' = @{ Score = 5; Message = "Requires password" }
        'Add-ADGroupMember.*Protected Users' = @{ Score = 5; Message = "Adds to Protected Users (beneficial)" }
        'Enable-ADAccount'        = @{ Score = 10; Message = "Enables accounts" }
        'Unlock-ADAccount'        = @{ Score = 5;  Message = "Unlocks accounts" }
    }

    # Syntax validation
    try {
        $null = [System.Management.Automation.Language.Parser]::ParseInput(
            $Script,
            [ref]$null,
            [ref]$null
        )
    }
    catch {
        $result.IsValid = $false
        $result.Errors += "Syntax error: $($_.Exception.Message)"
    }

    # Check for high-risk patterns
    foreach ($pattern in $highRiskPatterns.Keys) {
        if ($Script -match $pattern) {
            $info = $highRiskPatterns[$pattern]
            $result.RiskScore += $info.Score
            $result.Warnings += "[HIGH RISK] $($info.Message)"
            $result.Commands += @{
                Pattern   = $pattern
                Risk      = 'High'
                Score     = $info.Score
                Message   = $info.Message
            }
        }
    }

    # Check for medium-risk patterns
    foreach ($pattern in $mediumRiskPatterns.Keys) {
        if ($Script -match $pattern) {
            $info = $mediumRiskPatterns[$pattern]
            $result.RiskScore += $info.Score
            $result.Warnings += "[MEDIUM RISK] $($info.Message)"
            $result.Commands += @{
                Pattern   = $pattern
                Risk      = 'Medium'
                Score     = $info.Score
                Message   = $info.Message
            }
        }
    }

    # Check for low-risk patterns
    foreach ($pattern in $lowRiskPatterns.Keys) {
        if ($Script -match $pattern) {
            $info = $lowRiskPatterns[$pattern]
            $result.RiskScore += $info.Score
            $result.Commands += @{
                Pattern   = $pattern
                Risk      = 'Low'
                Score     = $info.Score
                Message   = $info.Message
            }
        }
    }

    # Detect bulk operations
    if ($Script -match 'ForEach-Object|ForEach\s*\(|%\s*{|\|\s*ForEach') {
        $result.Warnings += "[INFO] Script contains loop/bulk operations"
        $result.RiskScore += 10
    }

    # Check for variable interpolation issues
    if ($Script -match '\$\w+\s*\|' -and $Script -notmatch '\$\w+\s*=') {
        $result.Warnings += "[INFO] Script uses undefined variables in pipeline"
    }

    # Determine risk level
    $result.RiskLevel = switch ($result.RiskScore) {
        { $_ -ge 80 } { 'Critical'; $result.RequiresApproval = $true; break }
        { $_ -ge 50 } { 'High'; $result.RequiresApproval = $true; break }
        { $_ -ge 25 } { 'Medium'; break }
        default { 'Low' }
    }

    # Estimate affected count if possible
    if ($Finding) {
        if ($Finding -is [array]) {
            $result.AffectedCount = $Finding.Count
        }
    }

    [PSCustomObject]$result
}

function Get-RemediationRiskSummary {
    <#
    .SYNOPSIS
        Generates a risk summary for a batch of remediations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$ValidationResults
    )

    $summary = @{
        TotalRemediations = $ValidationResults.Count
        CriticalRisk      = ($ValidationResults | Where-Object RiskLevel -eq 'Critical').Count
        HighRisk          = ($ValidationResults | Where-Object RiskLevel -eq 'High').Count
        MediumRisk        = ($ValidationResults | Where-Object RiskLevel -eq 'Medium').Count
        LowRisk           = ($ValidationResults | Where-Object RiskLevel -eq 'Low').Count
        TotalRiskScore    = ($ValidationResults | Measure-Object -Property RiskScore -Sum).Sum
        RequiresApproval  = ($ValidationResults | Where-Object RequiresApproval).Count
        InvalidScripts    = ($ValidationResults | Where-Object { -not $_.IsValid }).Count
        AllWarnings       = $ValidationResults | ForEach-Object { $_.Warnings } | Select-Object -Unique
    }

    $summary.OverallRisk = switch ($summary.TotalRiskScore / [Math]::Max(1, $summary.TotalRemediations)) {
        { $_ -ge 80 } { 'Critical'; break }
        { $_ -ge 50 } { 'High'; break }
        { $_ -ge 25 } { 'Medium'; break }
        default { 'Low' }
    }

    [PSCustomObject]$summary
}

function Confirm-RemediationApproval {
    <#
    .SYNOPSIS
        Prompts for approval of high-risk remediations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$RiskSummary,

        [Parameter()]
        [switch]$Force
    )

    if ($Force) {
        return $true
    }

    if ($RiskSummary.RequiresApproval -eq 0 -and $RiskSummary.CriticalRisk -eq 0) {
        return $true
    }

    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                         APPROVAL REQUIRED                                    ║" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
    Write-Host "║ High-risk operations detected in this remediation batch.                    ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

    Write-Host "`nRisk Summary:" -ForegroundColor Cyan
    Write-Host "  Critical Risk: $($RiskSummary.CriticalRisk)" -ForegroundColor $(if ($RiskSummary.CriticalRisk -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  High Risk:     $($RiskSummary.HighRisk)" -ForegroundColor $(if ($RiskSummary.HighRisk -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Medium Risk:   $($RiskSummary.MediumRisk)" -ForegroundColor Yellow
    Write-Host "  Low Risk:      $($RiskSummary.LowRisk)" -ForegroundColor Green

    if ($RiskSummary.AllWarnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in ($RiskSummary.AllWarnings | Select-Object -First 10)) {
            Write-Host "  • $warning" -ForegroundColor Yellow
        }
        if ($RiskSummary.AllWarnings.Count -gt 10) {
            Write-Host "  ... and $($RiskSummary.AllWarnings.Count - 10) more warnings" -ForegroundColor Gray
        }
    }

    Write-Host ""
    $response = Read-Host "Do you want to proceed with these remediations? (yes/no)"

    return $response -match '^y(es)?$'
}
