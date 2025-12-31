function Get-ADScoutRemediation {
    <#
    .SYNOPSIS
        Gets remediation guidance for AD-Scout findings.

    .DESCRIPTION
        Retrieves remediation scripts and guidance for specific rules or findings.
        Can generate PowerShell commands to fix identified issues.

    .PARAMETER RuleId
        The rule ID to get remediation for.

    .PARAMETER Finding
        A specific finding object to generate remediation for.

    .PARAMETER Results
        Scan results from Invoke-ADScoutScan.

    .PARAMETER AsScript
        Output as executable PowerShell script.

    .EXAMPLE
        Get-ADScoutRemediation -RuleId "S-PwdNeverExpires"
        Gets general remediation guidance for the rule.

    .EXAMPLE
        Invoke-ADScoutScan | Get-ADScoutRemediation -AsScript | Out-File remediation.ps1
        Generates a remediation script for all findings.

    .EXAMPLE
        $results = Invoke-ADScoutScan -RuleId "S-PwdNeverExpires"
        Get-ADScoutRemediation -Results $results -AsScript
        Generates remediation for specific scan results.

    .OUTPUTS
        String or PSCustomObject
        Remediation guidance or script.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByRuleId')]
    param(
        [Parameter(ParameterSetName = 'ByRuleId', Mandatory)]
        [string]$RuleId,

        [Parameter(ParameterSetName = 'ByFinding')]
        [PSCustomObject]$Finding,

        [Parameter(ParameterSetName = 'ByResults', ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [switch]$AsScript
    )

    begin {
        $allResults = @()
    }

    process {
        if ($Results) {
            $allResults += $Results
        }
    }

    end {
        switch ($PSCmdlet.ParameterSetName) {
            'ByRuleId' {
                $rule = Get-ADScoutRule -Id $RuleId

                if (-not $rule) {
                    Write-Error "Rule not found: $RuleId"
                    return
                }

                [PSCustomObject]@{
                    RuleId       = $rule.Id
                    RuleName     = $rule.Name
                    Description  = $rule.Description
                    TechnicalExplanation = $rule.TechnicalExplanation
                    References   = $rule.References
                    GeneralGuidance = @"
# Remediation for: $($rule.Name)
# Category: $($rule.Category)
#
# $($rule.Description)
#
# Technical Details:
# $($rule.TechnicalExplanation)
#
# References:
$(($rule.References | ForEach-Object { "# - $_" }) -join "`n")

# Use Invoke-ADScoutScan to identify specific instances, then apply remediation.
"@
                }
            }

            'ByFinding' {
                $rule = Get-ADScoutRule -Id $Finding.RuleId

                if ($rule -and $rule.Remediation) {
                    $remediationScript = & $rule.Remediation -Finding $Finding
                    if ($AsScript) {
                        $remediationScript
                    }
                    else {
                        [PSCustomObject]@{
                            RuleId      = $rule.Id
                            Finding     = $Finding
                            Remediation = $remediationScript
                        }
                    }
                }
            }

            'ByResults' {
                $scriptHeader = @"
#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Scout Remediation Script

.DESCRIPTION
    Auto-generated remediation script for AD-Scout findings.
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

.NOTES
    Review each remediation before executing.
    Test in a non-production environment first.
#>

# Ensure you have appropriate permissions
#Requires -Modules ActiveDirectory

`$ErrorActionPreference = 'Stop'

"@

                $remediationBlocks = @()

                foreach ($result in $allResults) {
                    $rule = Get-ADScoutRule -Id $result.RuleId

                    if ($rule -and $rule.Remediation -and $result.Findings) {
                        $remediationBlocks += @"

# ==============================================================================
# Rule: $($result.RuleId) - $($result.RuleName)
# Findings: $($result.FindingCount)
# ==============================================================================

"@

                        foreach ($finding in $result.Findings) {
                            try {
                                $script = & $rule.Remediation -Finding $finding
                                $remediationBlocks += $script
                            }
                            catch {
                                $remediationBlocks += "# Error generating remediation for finding: $_"
                            }
                        }
                    }
                }

                if ($AsScript) {
                    $scriptHeader + ($remediationBlocks -join "`n")
                }
                else {
                    [PSCustomObject]@{
                        GeneratedAt = Get-Date
                        ResultCount = $allResults.Count
                        Script      = $scriptHeader + ($remediationBlocks -join "`n")
                    }
                }
            }
        }
    }
}
