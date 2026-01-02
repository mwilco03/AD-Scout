function Import-ADScoutBaseline {
    <#
    .SYNOPSIS
        Imports a previously saved baseline for comparison.

    .DESCRIPTION
        Loads a baseline file in any supported format (JSON, CSV, CLIXML, XML)
        for use with Compare-ADScoutBaseline.

    .PARAMETER Path
        The file path to the baseline file.

    .EXAMPLE
        $baseline = Import-ADScoutBaseline -Path ./baseline.json

    .EXAMPLE
        $baseline = Import-ADScoutBaseline -Path ./baseline.clixml.gz
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).TrimStart('.').ToLower()

    # Handle compressed CLIXML
    if ($Path.EndsWith('.clixml.gz') -or $Path.EndsWith('.gz')) {
        Write-Verbose "Importing compressed CLIXML baseline from: $Path"

        try {
            $tempPath = [System.IO.Path]::GetTempFileName()
            $sourceStream = [System.IO.File]::OpenRead($Path)
            $destStream = [System.IO.File]::Create($tempPath)
            $gzipStream = [System.IO.Compression.GZipStream]::new($sourceStream, [System.IO.Compression.CompressionMode]::Decompress)

            $gzipStream.CopyTo($destStream)

            $gzipStream.Close()
            $destStream.Close()
            $sourceStream.Close()

            $baseline = Import-Clixml -Path $tempPath
            Remove-Item $tempPath -Force

            return $baseline
        }
        catch {
            throw "Failed to decompress CLIXML baseline: $_"
        }
    }

    switch ($extension) {
        'json' {
            Write-Verbose "Importing JSON baseline from: $Path"
            $content = Get-Content -Path $Path -Raw -Encoding UTF8
            $baseline = $content | ConvertFrom-Json

            # Convert hashtables back from JSON
            if ($baseline.Summary.CategoryScores -is [PSCustomObject]) {
                $categoryScores = @{}
                $baseline.Summary.CategoryScores.PSObject.Properties | ForEach-Object {
                    $categoryScores[$_.Name] = $_.Value
                }
                $baseline.Summary.CategoryScores = $categoryScores
            }

            return $baseline
        }

        'csv' {
            Write-Verbose "Importing CSV baseline from: $Path"
            return Import-ADScoutBaselineCSV -Path $Path
        }

        'clixml' {
            Write-Verbose "Importing CLIXML baseline from: $Path"
            return Import-Clixml -Path $Path
        }

        'xml' {
            Write-Verbose "Importing XML baseline from: $Path"
            $xml = [xml](Get-Content -Path $Path -Raw -Encoding UTF8)
            # Convert XML back to PSObject
            return ConvertFrom-ADScoutXml -XmlNode $xml.DocumentElement
        }

        default {
            throw "Unsupported baseline format: $extension. Supported: json, csv, clixml, xml"
        }
    }
}

function Import-ADScoutBaselineCSV {
    <#
    .SYNOPSIS
        Internal function to import URL-encoded CSV baseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Load metadata
    $metaPath = [System.IO.Path]::ChangeExtension($Path, '.meta.json')
    if (Test-Path $metaPath) {
        $metadata = Get-Content -Path $metaPath -Raw | ConvertFrom-Json
    }
    else {
        $metadata = [PSCustomObject]@{
            Version = '1.0.0'
            Format = 'csv'
            CreatedAt = $null
            Summary = [PSCustomObject]@{
                TotalScore = 0
                TotalFindings = 0
                RuleCount = 0
                CategoryScores = @{}
            }
        }
    }

    # Load CSV with URL decoding
    $csvContent = Get-Content -Path $Path -Encoding UTF8
    $rules = @()

    # Skip header
    for ($i = 1; $i -lt $csvContent.Count; $i++) {
        $line = $csvContent[$i]
        $fields = $line -split ','

        if ($fields.Count -ge 4) {
            $ruleId = [System.Web.HttpUtility]::UrlDecode($fields[0])
            $category = [System.Web.HttpUtility]::UrlDecode($fields[1])
            $score = [int]$fields[2]
            $findingCount = [int]$fields[3]
            $hashes = if ($fields.Count -ge 5 -and $fields[4]) {
                ([System.Web.HttpUtility]::UrlDecode($fields[4])) -split '\|'
            }
            else { @() }

            $sampleFindings = @()
            if ($fields.Count -ge 6 -and $fields[5]) {
                try {
                    $decoded = [System.Web.HttpUtility]::UrlDecode($fields[5])
                    $sampleFindings = @($decoded | ConvertFrom-Json)
                }
                catch { }
            }

            $rules += [PSCustomObject]@{
                RuleId = $ruleId
                Category = $category
                Score = $score
                FindingCount = $findingCount
                FindingHashes = $hashes
                SampleFindings = $sampleFindings
            }
        }
    }

    # Reconstruct baseline object
    $baseline = [PSCustomObject]@{
        Version = $metadata.Version
        Format = 'csv'
        CreatedAt = $metadata.CreatedAt
        CreatedBy = $metadata.CreatedBy
        ComputerName = $metadata.ComputerName
        Domain = $metadata.Domain
        Summary = $metadata.Summary
        Rules = $rules
    }

    # Recalculate summary if not in metadata
    if ($baseline.Summary.RuleCount -eq 0) {
        $baseline.Summary.RuleCount = $rules.Count
        $baseline.Summary.TotalScore = ($rules | Measure-Object -Property Score -Sum).Sum
        $baseline.Summary.TotalFindings = ($rules | Measure-Object -Property FindingCount -Sum).Sum
    }

    return $baseline
}

function ConvertFrom-ADScoutXml {
    <#
    .SYNOPSIS
        Internal function to convert XML back to PSObject.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$XmlNode
    )

    # Simple XML to PSObject conversion
    $result = @{}

    foreach ($child in $XmlNode.ChildNodes) {
        if ($child.HasChildNodes -and $child.FirstChild.NodeType -ne 'Text') {
            $result[$child.Name] = ConvertFrom-ADScoutXml -XmlNode $child
        }
        else {
            $result[$child.Name] = $child.InnerText
        }
    }

    return [PSCustomObject]$result
}
