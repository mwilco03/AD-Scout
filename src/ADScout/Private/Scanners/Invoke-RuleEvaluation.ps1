function Invoke-RuleEvaluation {
    <#
    .SYNOPSIS
        Evaluates a single rule against collected AD data.

    .DESCRIPTION
        Takes a normalized rule definition and the relevant collected data, executes the
        rule's ScriptBlock, and returns structured findings.

    .PARAMETER Rule
        The normalized rule object from Get-ADScoutRule.

    .PARAMETER Data
        The collected AD data to evaluate against.

    .PARAMETER Domain
        The domain being scanned.

    .OUTPUTS
        PSCustomObject with finding details or $null if no issues found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        [Alias('Data')]
        $ADData,

        [Parameter()]
        [string]$Domain
    )

    begin {
        Write-ADScoutLog -Message "Evaluating rule: $($Rule.Id)" -Level Verbose
    }

    process {
        try {
            # Skip if no data provided
            if ($null -eq $ADData) {
                Write-ADScoutLog -Message "No data provided for rule $($Rule.Id), skipping" -Level Verbose
                return $null
            }

            # Execute the detection scriptblock (rules expect -ADData parameter)
            $detectResult = & $Rule.ScriptBlock -ADData $ADData

            # Handle different return types
            $findings = @()

            if ($null -eq $detectResult) {
                return $null
            }

            # Normalize to array
            if ($detectResult -isnot [array]) {
                $detectResult = @($detectResult)
            }

            # Calculate score based on scoring type
            $score = Get-RuleScore -Rule $Rule -Findings $detectResult

            # Build finding object
            if ($detectResult.Count -gt 0) {
                $finding = [PSCustomObject]@{
                    PSTypeName    = 'ADScout.Finding'
                    RuleId        = $Rule.Id
                    RuleName      = $Rule.Name
                    Category      = $Rule.Category
                    Severity      = $Rule.Severity
                    Description   = $Rule.Description
                    Score         = $score
                    MaxScore      = $Rule.MaxPoints
                    FindingCount  = $detectResult.Count
                    Findings      = $detectResult
                    Remediation   = $Rule.Remediation
                    References    = $Rule.References
                    MITRE         = $Rule.MITRE
                    CIS           = $Rule.CIS
                    STIG          = $Rule.STIG
                    TechnicalExplanation = $Rule.TechnicalExplanation
                    ExecutedAt    = [datetime]::UtcNow
                    Domain        = $Domain
                }

                return $finding
            }

            return $null
        }
        catch {
            Write-ADScoutLog -Message "Error evaluating rule $($Rule.Id): $_" -Level Error

            # Return error finding
            return [PSCustomObject]@{
                PSTypeName  = 'ADScout.Finding'
                RuleId      = $Rule.Id
                RuleName    = $Rule.Name
                Category    = $Rule.Category
                Severity    = 'Error'
                Description = "Failed to evaluate rule: $_"
                Score       = 0
                MaxScore    = $Rule.MaxPoints
                FindingCount = 0
                Error       = $_.Exception.Message
                ExecutedAt  = [datetime]::UtcNow
                Domain      = $Domain
            }
        }
    }
}

function Get-RuleScore {
    <#
    .SYNOPSIS
        Calculates the score for a rule based on its scoring type.

    .DESCRIPTION
        Uses the normalized rule properties (Computation, Points, MaxPoints, Threshold)
        to calculate the appropriate score based on findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule,

        [Parameter()]
        [array]$Findings
    )

    $maxPoints = $Rule.MaxPoints
    $points = $Rule.Points
    $count = $Findings.Count
    $scoringType = $Rule.Computation

    switch ($scoringType) {
        'TriggerOnPresence' {
            # Full score if any finding exists
            if ($count -gt 0) { return $maxPoints } else { return 0 }
        }

        'PerDiscover' {
            # Score per finding, up to max
            return [Math]::Min($count * $points, $maxPoints)
        }

        'TriggerOnThreshold' {
            # Full score only if count exceeds threshold
            $threshold = $Rule.Threshold
            if ($threshold -and $count -ge $threshold) { return $maxPoints } else { return 0 }
        }

        'TriggerIfLessThan' {
            # Full score if count is below minimum
            $threshold = $Rule.Threshold
            if ($threshold -and $count -lt $threshold) { return $maxPoints } else { return 0 }
        }

        default {
            # Default to per-discovery scoring
            return [Math]::Min($count * $points, $maxPoints)
        }
    }
}
