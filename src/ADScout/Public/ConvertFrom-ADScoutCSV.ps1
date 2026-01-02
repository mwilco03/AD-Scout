function ConvertFrom-ADScoutCSV {
    <#
    .SYNOPSIS
        Decodes URL-encoded CSV baseline/export files for Excel or manual inspection.

    .DESCRIPTION
        AD-Scout CSV exports use URL encoding for special characters (commas, apostrophes,
        quotes) to ensure compatibility with tools like Neo4j LOAD CSV. This function
        decodes those files into human-readable format suitable for Excel.

    .PARAMETER Path
        The path to the URL-encoded CSV file.

    .PARAMETER OutputPath
        Optional path to save the decoded CSV. If not specified, outputs to pipeline.

    .PARAMETER Delimiter
        The delimiter to use in the decoded output. Default is comma.
        Use Tab for better Excel compatibility with text containing commas.

    .EXAMPLE
        ConvertFrom-ADScoutCSV -Path ./baseline.csv -OutputPath ./baseline-excel.csv

    .EXAMPLE
        ConvertFrom-ADScoutCSV -Path ./export.csv | Export-Csv -Path ./decoded.csv

    .EXAMPLE
        ConvertFrom-ADScoutCSV -Path ./baseline.csv -Delimiter "`t" -OutputPath ./baseline.tsv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [char]$Delimiter = ','
    )

    Write-Verbose "Decoding URL-encoded CSV: $Path"

    $content = Get-Content -Path $Path -Encoding UTF8
    $decodedLines = @()
    $objects = @()

    # Process header
    $header = $content[0] -split ','
    $decodedHeader = $header | ForEach-Object { [System.Web.HttpUtility]::UrlDecode($_) }

    if ($OutputPath) {
        $decodedLines += $decodedHeader -join $Delimiter
    }

    # Process data rows
    for ($i = 1; $i -lt $content.Count; $i++) {
        $line = $content[$i]

        # Smart split that handles URL-encoded commas within fields
        $fields = $line -split ','
        $decodedFields = $fields | ForEach-Object { [System.Web.HttpUtility]::UrlDecode($_) }

        if ($OutputPath) {
            # For file output, escape delimiters in fields
            $escapedFields = $decodedFields | ForEach-Object {
                if ($_ -match "[$Delimiter`"']") {
                    "`"$($_ -replace '"', '""')`""
                }
                else {
                    $_
                }
            }
            $decodedLines += $escapedFields -join $Delimiter
        }

        # Build object for pipeline output
        $obj = @{}
        for ($j = 0; $j -lt [Math]::Min($decodedHeader.Count, $decodedFields.Count); $j++) {
            $obj[$decodedHeader[$j]] = $decodedFields[$j]
        }
        $objects += [PSCustomObject]$obj
    }

    if ($OutputPath) {
        $decodedLines | Set-Content -Path $OutputPath -Encoding UTF8
        Write-Host "Decoded CSV saved to: $OutputPath" -ForegroundColor Green
        Write-Host "Rows: $($objects.Count) | Columns: $($decodedHeader.Count)"
    }
    else {
        return $objects
    }
}

function ConvertTo-ADScoutCSV {
    <#
    .SYNOPSIS
        Encodes data to URL-encoded CSV format for storage or Neo4j import.

    .DESCRIPTION
        Converts PowerShell objects to URL-encoded CSV format where special
        characters are percent-encoded. This ensures compatibility with
        tools that have issues with embedded commas or quotes.

    .PARAMETER InputObject
        The objects to convert to CSV.

    .PARAMETER Path
        The path to save the encoded CSV file.

    .PARAMETER Property
        Specific properties to include. If not specified, all properties are included.

    .EXAMPLE
        $data | ConvertTo-ADScoutCSV -Path ./encoded.csv

    .EXAMPLE
        Get-ADUser -Filter * | Select Name, Description | ConvertTo-ADScoutCSV -Path ./users.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string[]]$Property
    )

    begin {
        $allObjects = @()
    }

    process {
        $allObjects += $InputObject
    }

    end {
        if ($allObjects.Count -eq 0) {
            Write-Warning "No objects to export"
            return
        }

        # Determine properties
        if (-not $Property) {
            $Property = $allObjects[0].PSObject.Properties.Name
        }

        $lines = @()

        # Header (URL-encode property names)
        $encodedHeader = $Property | ForEach-Object { [System.Web.HttpUtility]::UrlEncode($_) }
        $lines += $encodedHeader -join ','

        # Data rows
        foreach ($obj in $allObjects) {
            $encodedValues = foreach ($prop in $Property) {
                $value = $obj.$prop

                # Handle different value types
                if ($null -eq $value) {
                    ''
                }
                elseif ($value -is [array]) {
                    [System.Web.HttpUtility]::UrlEncode(($value -join '|'))
                }
                elseif ($value -is [datetime]) {
                    [System.Web.HttpUtility]::UrlEncode($value.ToString('o'))
                }
                elseif ($value -is [PSCustomObject] -or $value -is [hashtable]) {
                    [System.Web.HttpUtility]::UrlEncode(($value | ConvertTo-Json -Compress))
                }
                else {
                    [System.Web.HttpUtility]::UrlEncode($value.ToString())
                }
            }
            $lines += $encodedValues -join ','
        }

        $lines | Set-Content -Path $Path -Encoding UTF8
        Write-Verbose "Exported $($allObjects.Count) objects to URL-encoded CSV: $Path"
    }
}

function Test-ADScoutCSVEncoding {
    <#
    .SYNOPSIS
        Tests if a CSV file is URL-encoded.

    .DESCRIPTION
        Examines a CSV file to determine if it uses URL encoding for special characters.
        Useful for determining which import method to use.

    .PARAMETER Path
        The path to the CSV file to test.

    .EXAMPLE
        if (Test-ADScoutCSVEncoding -Path ./data.csv) { ConvertFrom-ADScoutCSV -Path ./data.csv }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path
    )

    $content = Get-Content -Path $Path -TotalCount 5 -Encoding UTF8

    # Look for URL encoding patterns
    foreach ($line in $content) {
        if ($line -match '%[0-9A-Fa-f]{2}') {
            return $true
        }
    }

    return $false
}
