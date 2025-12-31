function Get-ADScoutRule {
    <#
    .SYNOPSIS
        Gets available AD-Scout security rules.

    .DESCRIPTION
        Retrieves security rules available for scanning. Rules can be filtered
        by ID, category, or loaded from specific paths.

    .PARAMETER Id
        Filter by specific rule ID(s).

    .PARAMETER Category
        Filter by rule category.

    .PARAMETER Path
        Additional paths to search for rules.

    .EXAMPLE
        Get-ADScoutRule
        Returns all available rules.

    .EXAMPLE
        Get-ADScoutRule -Category StaleObjects
        Returns all rules in the StaleObjects category.

    .EXAMPLE
        Get-ADScoutRule -Id "S-PwdNeverExpires"
        Returns the specific rule by ID.

    .OUTPUTS
        PSCustomObject[]
        Collection of rule definitions.

    .NOTES
        Author: AD-Scout Contributors
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter()]
        [string[]]$Id,

        [Parameter()]
        [ValidateSet('Anomalies', 'StaleObjects', 'PrivilegedAccounts', 'Trusts')]
        [string[]]$Category,

        [Parameter()]
        [string[]]$Path
    )

    begin {
        Write-Verbose "Getting AD-Scout rules"
        $rules = @()
    }

    process {
        # Get all rule paths
        $rulePaths = Get-ADScoutRulePaths

        if ($Path) {
            $rulePaths += $Path
        }

        # Load rules from all paths
        foreach ($rulePath in $rulePaths) {
            if (-not (Test-Path $rulePath)) {
                Write-Verbose "Rule path not found: $rulePath"
                continue
            }

            $ruleFiles = Get-ChildItem -Path $rulePath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -ne '_RuleTemplate.ps1' }

            foreach ($file in $ruleFiles) {
                try {
                    Write-Verbose "Loading rule from: $($file.FullName)"
                    $rule = . $file.FullName

                    if ($rule -is [hashtable] -and $rule.Id) {
                        # Convert hashtable to PSCustomObject for better display
                        $ruleObject = [PSCustomObject]@{
                            PSTypeName    = 'ADScoutRule'
                            Id            = $rule.Id
                            Name          = $rule.Name
                            Category      = $rule.Category
                            Model         = $rule.Model
                            Version       = $rule.Version
                            Computation   = $rule.Computation
                            Points        = $rule.Points
                            MaxPoints     = $rule.MaxPoints
                            Threshold     = $rule.Threshold
                            MITRE         = $rule.MITRE
                            CIS           = $rule.CIS
                            STIG          = $rule.STIG
                            ANSSI         = $rule.ANSSI
                            ScriptBlock   = $rule.ScriptBlock
                            DetailProperties = $rule.DetailProperties
                            DetailFormat  = $rule.DetailFormat
                            Remediation   = $rule.Remediation
                            Description   = $rule.Description
                            TechnicalExplanation = $rule.TechnicalExplanation
                            References    = $rule.References
                            Prerequisites = $rule.Prerequisites
                            AppliesTo     = $rule.AppliesTo
                            SourceFile    = $file.FullName
                        }

                        $rules += $ruleObject
                    }
                }
                catch {
                    Write-Warning "Failed to load rule from $($file.FullName): $_"
                }
            }
        }
    }

    end {
        # Filter by ID if specified
        if ($Id) {
            $rules = $rules | Where-Object { $_.Id -in $Id }
        }

        # Filter by Category if specified
        if ($Category) {
            $rules = $rules | Where-Object { $_.Category -in $Category }
        }

        # Remove duplicates (later paths override earlier for same ID)
        $uniqueRules = @{}
        foreach ($rule in $rules) {
            $uniqueRules[$rule.Id] = $rule
        }

        Write-Verbose "Returning $($uniqueRules.Count) rules"

        # Return sorted by category then ID
        $uniqueRules.Values | Sort-Object Category, Id
    }
}
