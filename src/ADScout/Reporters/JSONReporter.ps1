function Export-ADScoutJSONReport {
    <#
    .SYNOPSIS
        Exports AD-Scout results to JSON format.

    .DESCRIPTION
        Generates a structured JSON file suitable for automation and SIEM integration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Title = "AD-Scout Security Assessment",

        [Parameter()]
        [switch]$IncludeRemediation,

        [Parameter()]
        [switch]$Compress
    )

    $report = [ordered]@{
        meta = [ordered]@{
            title       = $Title
            generatedAt = (Get-Date).ToString('o')
            generator   = 'AD-Scout'
            version     = (Get-Module ADScout -ErrorAction SilentlyContinue).Version.ToString()
        }
        summary = [ordered]@{
            totalScore             = ($Results | Measure-Object -Property Score -Sum).Sum
            totalFindings          = ($Results | Measure-Object -Property FindingCount -Sum).Sum
            rulesWithFindings      = $Results.Count
            categorySummary        = @(
                $Results | Group-Object Category | ForEach-Object {
                    [ordered]@{
                        category  = $_.Name
                        ruleCount = $_.Count
                        findings  = ($_.Group | Measure-Object -Property FindingCount -Sum).Sum
                        score     = ($_.Group | Measure-Object -Property Score -Sum).Sum
                    }
                }
            )
        }
        results = @(
            $Results | ForEach-Object {
                $result = $_
                $entry = [ordered]@{
                    ruleId       = $result.RuleId
                    ruleName     = $result.RuleName
                    category     = $result.Category
                    description  = $result.Description
                    findingCount = $result.FindingCount
                    score        = $result.Score
                    maxScore     = $result.MaxScore
                    frameworks   = [ordered]@{
                        mitre = $result.MITRE
                        cis   = $result.CIS
                        stig  = $result.STIG
                    }
                    findings     = $result.Findings
                    executedAt   = if ($result.ExecutedAt) { $result.ExecutedAt.ToString('o') } else { $null }
                }

                if ($IncludeRemediation -and $result.TechnicalExplanation) {
                    $entry.technicalExplanation = $result.TechnicalExplanation
                    $entry.references = $result.References
                }

                $entry
            }
        )
    }

    $jsonParams = @{
        Depth = 10
    }

    if ($Compress) {
        $jsonParams.Compress = $true
    }

    $report | ConvertTo-Json @jsonParams | Out-File -FilePath $Path -Encoding UTF8

    Write-Verbose "JSON report saved to: $Path"
}
