function Export-ADScoutBaseline {
    <#
    .SYNOPSIS
        Exports scan results as a baseline for future comparison.

    .DESCRIPTION
        Saves the current scan results in a format suitable for baseline comparison.
        Supports multiple formats: JSON (default), CSV (URL-encoded), CLIXML (compressed),
        and XML. The baseline captures finding signatures for delta detection.

    .PARAMETER Results
        The scan results from Invoke-ADScoutScan to save as baseline.

    .PARAMETER Path
        The file path to save the baseline. Extension determines format if -Format not specified.

    .PARAMETER Format
        The output format: json (default), csv, clixml, xml.
        - json: Human-readable, universal (default)
        - csv: URL-encoded special characters, compatible with Neo4j/Excel
        - clixml: Compressed binary, fastest for large environments
        - xml: Standard XML for enterprise tool integration

    .PARAMETER Force
        Overwrite existing baseline file without prompting.

    .PARAMETER PassThru
        Return the baseline object in addition to saving.

    .EXAMPLE
        Invoke-ADScoutScan | Export-ADScoutBaseline -Path ./baseline.json

    .EXAMPLE
        $results | Export-ADScoutBaseline -Path ./baseline.clixml -Format clixml

    .EXAMPLE
        Export-ADScoutBaseline -Results $results -Path ./baseline.csv -Format csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('json', 'csv', 'clixml', 'xml')]
        [string]$Format,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        # Determine format from extension if not specified
        if (-not $Format) {
            $extension = [System.IO.Path]::GetExtension($Path).TrimStart('.').ToLower()
            $Format = switch ($extension) {
                'json' { 'json' }
                'csv'  { 'csv' }
                'clixml' { 'clixml' }
                'xml' { 'xml' }
                default { 'json' }
            }
        }

        # Check if file exists
        if ((Test-Path $Path) -and -not $Force) {
            throw "Baseline file already exists: $Path. Use -Force to overwrite."
        }

        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        # Build baseline object
        $baseline = [PSCustomObject]@{
            Version        = '1.0.0'
            Format         = $Format
            CreatedAt      = (Get-Date).ToUniversalTime().ToString('o')
            CreatedBy      = $env:USERNAME
            ComputerName   = $env:COMPUTERNAME
            Domain         = if ($allResults[0].Domain) { $allResults[0].Domain } else { $env:USERDNSDOMAIN }

            # Summary statistics
            Summary        = [PSCustomObject]@{
                TotalScore       = ($allResults | Measure-Object -Property Score -Sum).Sum
                TotalFindings    = ($allResults | Measure-Object -Property FindingCount -Sum).Sum
                RuleCount        = $allResults.Count
                CategoryScores   = @{}
            }

            # Individual rule results with hashes for delta detection
            Rules          = @()
        }

        # Calculate category scores
        $categories = $allResults | Group-Object Category
        foreach ($cat in $categories) {
            $baseline.Summary.CategoryScores[$cat.Name] = ($cat.Group | Measure-Object -Property Score -Sum).Sum
        }

        # Process each rule result
        foreach ($result in $allResults) {
            $findingHashes = @()

            # Generate hash for each finding for change detection
            if ($result.Findings) {
                foreach ($finding in $result.Findings) {
                    # Create deterministic hash from finding properties
                    $hashInput = $finding | ConvertTo-Json -Compress -Depth 3
                    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($hashInput)
                    $sha256 = [System.Security.Cryptography.SHA256]::Create()
                    $hash = [Convert]::ToBase64String($sha256.ComputeHash($hashBytes)).Substring(0, 16)
                    $findingHashes += $hash
                }
            }

            $baseline.Rules += [PSCustomObject]@{
                RuleId         = $result.RuleId
                Category       = $result.Category
                Score          = $result.Score
                FindingCount   = $result.FindingCount
                FindingHashes  = $findingHashes
                # Store first few findings for reference (not all to save space)
                SampleFindings = if ($result.Findings.Count -gt 5) {
                    $result.Findings | Select-Object -First 5
                }
                else {
                    $result.Findings
                }
            }
        }

        # Size recommendation for CLIXML
        $userCount = ($allResults | Where-Object { $_.RuleId -match 'User|Account' } |
                     Measure-Object -Property FindingCount -Sum).Sum
        $totalFindings = $baseline.Summary.TotalFindings

        if ($Format -ne 'clixml' -and ($userCount -gt 10000 -or $totalFindings -gt 5000)) {
            Write-Warning @"
Large environment detected ($userCount user-related findings, $totalFindings total findings).
Consider using -Format clixml for faster storage and retrieval:
    Export-ADScoutBaseline -Path ./baseline.clixml -Format clixml
"@
        }

        # Export based on format
        switch ($Format) {
            'json' {
                $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
                Write-Verbose "Exported JSON baseline to: $Path"
            }

            'csv' {
                # Export as URL-encoded CSV
                Export-ADScoutBaselineCSV -Baseline $baseline -Path $Path
                Write-Verbose "Exported URL-encoded CSV baseline to: $Path"
            }

            'clixml' {
                # Compress with CLIXML + GZip
                $clixmlPath = $Path
                if (-not $Path.EndsWith('.clixml')) {
                    $clixmlPath = "$Path.clixml"
                }

                # Export to CLIXML then compress
                $tempPath = [System.IO.Path]::GetTempFileName()
                $baseline | Export-Clixml -Path $tempPath -Depth 10

                # Compress
                $gzipPath = if ($clixmlPath.EndsWith('.gz')) { $clixmlPath } else { "$clixmlPath.gz" }

                try {
                    $sourceStream = [System.IO.File]::OpenRead($tempPath)
                    $destStream = [System.IO.File]::Create($gzipPath)
                    $gzipStream = [System.IO.Compression.GZipStream]::new($destStream, [System.IO.Compression.CompressionMode]::Compress)

                    $sourceStream.CopyTo($gzipStream)

                    $gzipStream.Close()
                    $destStream.Close()
                    $sourceStream.Close()

                    Remove-Item $tempPath -Force
                    Write-Verbose "Exported compressed CLIXML baseline to: $gzipPath"
                }
                catch {
                    # Fallback to uncompressed CLIXML
                    $baseline | Export-Clixml -Path $clixmlPath -Depth 10
                    Write-Verbose "Exported CLIXML baseline to: $clixmlPath (compression failed)"
                }
            }

            'xml' {
                # Standard XML export
                $xmlContent = $baseline | ConvertTo-Xml -Depth 10 -As String
                $xmlContent | Set-Content -Path $Path -Encoding UTF8
                Write-Verbose "Exported XML baseline to: $Path"
            }
        }

        Write-Host "Baseline exported: $($baseline.Summary.RuleCount) rules, $($baseline.Summary.TotalFindings) findings, score: $($baseline.Summary.TotalScore)" -ForegroundColor Green

        if ($PassThru) {
            return $baseline
        }
    }
}

function Export-ADScoutBaselineCSV {
    <#
    .SYNOPSIS
        Internal function to export baseline as URL-encoded CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Baseline,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $csvLines = @()

    # Header
    $csvLines += 'RuleId,Category,Score,FindingCount,FindingHashes,SampleFinding'

    foreach ($rule in $Baseline.Rules) {
        # URL-encode fields that might contain special characters
        $ruleId = [System.Web.HttpUtility]::UrlEncode($rule.RuleId)
        $category = [System.Web.HttpUtility]::UrlEncode($rule.Category)
        $hashes = [System.Web.HttpUtility]::UrlEncode(($rule.FindingHashes -join '|'))

        # Encode sample finding as JSON then URL-encode
        $sampleFinding = ''
        if ($rule.SampleFindings -and $rule.SampleFindings.Count -gt 0) {
            $firstFinding = $rule.SampleFindings[0] | ConvertTo-Json -Compress
            $sampleFinding = [System.Web.HttpUtility]::UrlEncode($firstFinding)
        }

        $csvLines += "$ruleId,$category,$($rule.Score),$($rule.FindingCount),$hashes,$sampleFinding"
    }

    # Write CSV
    $csvLines | Set-Content -Path $Path -Encoding UTF8

    # Also write metadata file
    $metaPath = [System.IO.Path]::ChangeExtension($Path, '.meta.json')
    $Baseline | Select-Object Version, Format, CreatedAt, CreatedBy, ComputerName, Domain, Summary |
        ConvertTo-Json -Depth 5 | Set-Content -Path $metaPath -Encoding UTF8
}
