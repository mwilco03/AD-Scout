function Test-RuleCondition {
    <#
    .SYNOPSIS
        Tests a single condition from a rule against an AD object.

    .DESCRIPTION
        Evaluates whether an AD object matches the specified condition.
        Used for simple property-based checks.

    .PARAMETER Object
        The AD object to test.

    .PARAMETER Property
        The property name to check.

    .PARAMETER Operator
        The comparison operator (eq, ne, gt, lt, ge, le, like, match, contains).

    .PARAMETER Value
        The value to compare against.

    .OUTPUTS
        Boolean indicating whether the condition is met.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$Property,

        [Parameter(Mandatory)]
        [ValidateSet('eq', 'ne', 'gt', 'lt', 'ge', 'le', 'like', 'match', 'contains', 'notcontains')]
        [string]$Operator,

        [Parameter()]
        [object]$Value
    )

    process {
        try {
            $propertyValue = $Object.$Property

            switch ($Operator) {
                'eq' { return $propertyValue -eq $Value }
                'ne' { return $propertyValue -ne $Value }
                'gt' { return $propertyValue -gt $Value }
                'lt' { return $propertyValue -lt $Value }
                'ge' { return $propertyValue -ge $Value }
                'le' { return $propertyValue -le $Value }
                'like' { return $propertyValue -like $Value }
                'match' { return $propertyValue -match $Value }
                'contains' { return $propertyValue -contains $Value }
                'notcontains' { return $propertyValue -notcontains $Value }
                default { return $false }
            }
        }
        catch {
            Write-ADScoutLog -Message "Error testing condition on property $Property : $_" -Level Warning
            return $false
        }
    }
}
