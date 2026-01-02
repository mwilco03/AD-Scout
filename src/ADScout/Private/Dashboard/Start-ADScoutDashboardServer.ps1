function Start-ADScoutDashboardServer {
    <#
    .SYNOPSIS
        Starts the AD-Scout web dashboard server.

    .DESCRIPTION
        Launches an HTTP listener to serve the AD-Scout dashboard.
        Uses PSP (PowerShell Server Pages) for dynamic content generation.
        Compatible with MScholtes/WebServer patterns.

    .PARAMETER Port
        TCP port to listen on (default: 8080).

    .PARAMETER DashboardData
        Pre-computed dashboard data object from Get-DashboardData.

    .PARAMETER Results
        Raw scan results. If DashboardData not provided, will compute it.

    .PARAMETER BaselinePath
        Path to baseline file for comparison.

    .PARAMETER TemplatesPath
        Path to PSP template directory.

    .PARAMETER Background
        Run server in background (returns immediately).

    .PARAMETER AutoRefresh
        Enable auto-refresh on dashboard pages.

    .PARAMETER RefreshInterval
        Auto-refresh interval in seconds.

    .OUTPUTS
        Returns server job object if -Background, otherwise blocks until stopped.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1024, 65535)]
        [int]$Port = 8080,

        [Parameter()]
        [PSCustomObject]$DashboardData,

        [Parameter()]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$BaselinePath,

        [Parameter()]
        [string]$TemplatesPath,

        [Parameter()]
        [switch]$Background,

        [Parameter()]
        [switch]$AutoRefresh,

        [Parameter()]
        [int]$RefreshInterval = 60
    )

    # Determine templates path
    if (-not $TemplatesPath) {
        $TemplatesPath = Join-Path $PSScriptRoot '..\..\Templates\Dashboard'
    }

    if (-not (Test-Path $TemplatesPath)) {
        throw "Templates directory not found: $TemplatesPath"
    }

    # Prepare dashboard data
    if (-not $DashboardData -and $Results) {
        $DashboardData = Get-DashboardData -Results $Results -BaselinePath $BaselinePath
    }

    if (-not $DashboardData) {
        throw "Either -DashboardData or -Results must be provided"
    }

    # Store in script scope for PSP access
    $script:ADScoutDashboard = @{
        Data = $DashboardData
        Results = $Results
        BaselinePath = $BaselinePath
        TemplatesPath = $TemplatesPath
        AutoRefresh = $AutoRefresh
        RefreshInterval = $RefreshInterval
        StartTime = Get-Date
        Port = $Port
    }

    $serverScriptBlock = {
        param(
            [int]$Port,
            [string]$TemplatesPath,
            [hashtable]$DashboardState,
            [bool]$AutoRefresh,
            [int]$RefreshInterval
        )

        # MIME types
        $mimeTypes = @{
            '.html' = 'text/html; charset=utf-8'
            '.htm'  = 'text/html; charset=utf-8'
            '.css'  = 'text/css; charset=utf-8'
            '.js'   = 'application/javascript; charset=utf-8'
            '.json' = 'application/json; charset=utf-8'
            '.png'  = 'image/png'
            '.jpg'  = 'image/jpeg'
            '.jpeg' = 'image/jpeg'
            '.gif'  = 'image/gif'
            '.svg'  = 'image/svg+xml'
            '.ico'  = 'image/x-icon'
            '.woff' = 'font/woff'
            '.woff2'= 'font/woff2'
            '.ttf'  = 'font/ttf'
            '.csv'  = 'text/csv'
            '.sarif'= 'application/json'
        }

        # Create HTTP listener
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:$Port/")
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")

        try {
            $listener.Start()
            Write-Host "AD-Scout Dashboard server started on http://localhost:$Port" -ForegroundColor Green
            Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray

            while ($listener.IsListening) {
                try {
                    $context = $listener.GetContext()
                    $request = $context.Request
                    $response = $context.Response

                    $path = $request.Url.LocalPath
                    $method = $request.HttpMethod
                    $query = @{}

                    # Parse query string
                    if ($request.Url.Query) {
                        $queryString = $request.Url.Query.TrimStart('?')
                        $queryString.Split('&') | ForEach-Object {
                            $parts = $_.Split('=', 2)
                            if ($parts.Count -eq 2) {
                                $query[$parts[0]] = [System.Web.HttpUtility]::UrlDecode($parts[1])
                            }
                        }
                    }

                    Write-Verbose "[$method] $path"

                    # Route handling
                    $content = $null
                    $contentType = 'text/html; charset=utf-8'
                    $statusCode = 200

                    switch -Regex ($path) {
                        '^/$' {
                            # Main dashboard - redirect to auditor view by default
                            $content = Invoke-PSPTemplate -TemplateName 'index.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $AutoRefresh -RefreshInterval $RefreshInterval
                        }

                        '^/auditor$' {
                            $content = Invoke-PSPTemplate -TemplateName 'auditor.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $AutoRefresh -RefreshInterval $RefreshInterval
                        }

                        '^/manager$' {
                            $content = Invoke-PSPTemplate -TemplateName 'manager.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $AutoRefresh -RefreshInterval $RefreshInterval
                        }

                        '^/technician$' {
                            $content = Invoke-PSPTemplate -TemplateName 'technician.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $AutoRefresh -RefreshInterval $RefreshInterval
                        }

                        '^/api/status$' {
                            $contentType = 'application/json; charset=utf-8'
                            $content = @{
                                status = 'running'
                                score = $DashboardState.Data.Summary.NormalizedScore
                                grade = $DashboardState.Data.Summary.Grade
                                totalFindings = $DashboardState.Data.Summary.TotalFindings
                                rulesWithFindings = $DashboardState.Data.Summary.RulesWithFindings
                                isFirstRun = $DashboardState.Data.State.IsFirstRun
                                scanTime = $DashboardState.Data.Meta.ScanTime.ToString('o')
                            } | ConvertTo-Json
                        }

                        '^/api/results$' {
                            $contentType = 'application/json; charset=utf-8'
                            $content = @{
                                meta = $DashboardState.Data.Meta
                                summary = $DashboardState.Data.Summary
                                categories = $DashboardState.Data.Categories
                                findings = $DashboardState.Data.AllFindings
                            } | ConvertTo-Json -Depth 10
                        }

                        '^/api/baseline$' {
                            $contentType = 'application/json; charset=utf-8'
                            $content = @{
                                hasBaseline = $DashboardState.Data.State.HasBaseline
                                comparison = $DashboardState.Data.Comparison
                                baseline = $DashboardState.Data.Baseline
                            } | ConvertTo-Json -Depth 10
                        }

                        '^/api/findings$' {
                            $contentType = 'application/json; charset=utf-8'
                            $findings = $DashboardState.Data.AllFindings

                            # Filter by category
                            if ($query['category']) {
                                $findings = $findings | Where-Object { $_.Category -eq $query['category'] }
                            }

                            # Filter by severity
                            if ($query['severity']) {
                                $findings = $findings | Where-Object { $_.Severity -eq $query['severity'] }
                            }

                            # Filter by search term
                            if ($query['search']) {
                                $term = $query['search']
                                $findings = $findings | Where-Object {
                                    $_.RuleId -like "*$term*" -or
                                    $_.RuleName -like "*$term*" -or
                                    $_.Description -like "*$term*"
                                }
                            }

                            $content = @{
                                count = ($findings | Measure-Object).Count
                                findings = @($findings)
                            } | ConvertTo-Json -Depth 10
                        }

                        '^/api/remediation/(.+)$' {
                            $contentType = 'application/json; charset=utf-8'
                            $ruleId = $Matches[1]

                            # Get remediation from module
                            try {
                                $remediation = Get-ADScoutRemediation -RuleId $ruleId -AsScript
                                $content = @{
                                    ruleId = $ruleId
                                    remediation = $remediation
                                    success = $true
                                } | ConvertTo-Json
                            } catch {
                                $content = @{
                                    ruleId = $ruleId
                                    remediation = $null
                                    success = $false
                                    error = $_.Exception.Message
                                } | ConvertTo-Json
                            }
                        }

                        '^/api/export/(.+)$' {
                            $format = $Matches[1].ToLower()

                            switch ($format) {
                                'json' {
                                    $contentType = 'application/json'
                                    $response.Headers.Add('Content-Disposition', 'attachment; filename="adscout-results.json"')
                                    $content = @{
                                        meta = $DashboardState.Data.Meta
                                        summary = $DashboardState.Data.Summary
                                        results = @($DashboardState.Data.RawResults | ForEach-Object {
                                            @{
                                                ruleId = $_.RuleId
                                                ruleName = $_.RuleName
                                                category = $_.Category
                                                score = $_.Score
                                                findingCount = $_.FindingCount
                                                description = $_.Description
                                                mitre = $_.MITRE
                                                cis = $_.CIS
                                                nist = $_.NIST
                                                stig = $_.STIG
                                            }
                                        })
                                    } | ConvertTo-Json -Depth 10
                                }

                                'csv' {
                                    $contentType = 'text/csv'
                                    $response.Headers.Add('Content-Disposition', 'attachment; filename="adscout-results.csv"')
                                    $csvData = $DashboardState.Data.AllFindings | ForEach-Object {
                                        [PSCustomObject]@{
                                            RuleId = $_.RuleId
                                            RuleName = $_.RuleName
                                            Category = $_.Category
                                            Severity = $_.Severity
                                            Score = $_.Score
                                            FindingCount = $_.FindingCount
                                            Description = $_.Description
                                            MITRE = $_.MITRE
                                            CIS = $_.CIS
                                            NIST = $_.NIST
                                            STIG = $_.STIG
                                        }
                                    }
                                    $content = ($csvData | ConvertTo-Csv -NoTypeInformation) -join "`n"
                                }

                                'html' {
                                    $contentType = 'text/html'
                                    $response.Headers.Add('Content-Disposition', 'attachment; filename="adscout-report.html"')
                                    $content = Invoke-PSPTemplate -TemplateName 'export-html.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $false -RefreshInterval 0
                                    if (-not $content) {
                                        # Fallback to auditor view if export template doesn't exist
                                        $content = Invoke-PSPTemplate -TemplateName 'auditor.psp' -TemplatesPath $TemplatesPath -DashboardState $DashboardState -AutoRefresh $false -RefreshInterval 0
                                    }
                                }

                                'sarif' {
                                    $contentType = 'application/json'
                                    $response.Headers.Add('Content-Disposition', 'attachment; filename="adscout-results.sarif"')
                                    $content = ConvertTo-Sarif -Results $DashboardState.Data.RawResults
                                }

                                default {
                                    $statusCode = 400
                                    $contentType = 'application/json'
                                    $content = @{
                                        error = "Unsupported format: $format"
                                        supportedFormats = @('json', 'csv', 'html', 'sarif')
                                    } | ConvertTo-Json
                                }
                            }
                        }

                        '^/api/scan$' {
                            if ($method -eq 'POST') {
                                $contentType = 'application/json; charset=utf-8'
                                try {
                                    $newResults = Invoke-ADScoutScan
                                    $DashboardState.Data = Get-DashboardData -Results $newResults -BaselinePath $DashboardState.BaselinePath
                                    $DashboardState.Results = $newResults

                                    $content = @{
                                        success = $true
                                        score = $DashboardState.Data.Summary.NormalizedScore
                                        totalFindings = $DashboardState.Data.Summary.TotalFindings
                                    } | ConvertTo-Json
                                } catch {
                                    $content = @{
                                        success = $false
                                        error = $_.Exception.Message
                                    } | ConvertTo-Json
                                }
                            } else {
                                $statusCode = 405
                                $contentType = 'application/json'
                                $content = @{ error = 'Method not allowed. Use POST.' } | ConvertTo-Json
                            }
                        }

                        '^/api/baseline$' {
                            if ($method -eq 'POST') {
                                $contentType = 'application/json; charset=utf-8'
                                try {
                                    $baselinePath = Save-ADScoutBaseline -Results $DashboardState.Results
                                    $DashboardState.BaselinePath = $baselinePath

                                    $content = @{
                                        success = $true
                                        path = $baselinePath
                                    } | ConvertTo-Json
                                } catch {
                                    $content = @{
                                        success = $false
                                        error = $_.Exception.Message
                                    } | ConvertTo-Json
                                }
                            }
                            # GET handled above
                        }

                        '^/dashboard\.css$' {
                            $cssPath = Join-Path $TemplatesPath 'dashboard.css'
                            if (Test-Path $cssPath) {
                                $content = Get-Content $cssPath -Raw
                                $contentType = 'text/css; charset=utf-8'
                            } else {
                                $statusCode = 404
                                $content = "/* CSS not found */"
                            }
                        }

                        '^/dashboard\.js$' {
                            $jsPath = Join-Path $TemplatesPath 'dashboard.js'
                            if (Test-Path $jsPath) {
                                $content = Get-Content $jsPath -Raw
                                $contentType = 'application/javascript; charset=utf-8'
                            } else {
                                $statusCode = 404
                                $content = "// JS not found"
                            }
                        }

                        default {
                            # Try to serve static file
                            $filePath = Join-Path $TemplatesPath $path.TrimStart('/')
                            if (Test-Path $filePath -PathType Leaf) {
                                $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
                                $contentType = $mimeTypes[$ext]
                                if (-not $contentType) {
                                    $contentType = 'application/octet-stream'
                                }

                                if ($ext -in @('.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf')) {
                                    # Binary file
                                    $bytes = [System.IO.File]::ReadAllBytes($filePath)
                                    $response.ContentType = $contentType
                                    $response.StatusCode = 200
                                    $response.ContentLength64 = $bytes.Length
                                    $response.OutputStream.Write($bytes, 0, $bytes.Length)
                                    $response.OutputStream.Close()
                                    continue
                                } else {
                                    $content = Get-Content $filePath -Raw
                                }
                            } else {
                                $statusCode = 404
                                $content = "<html><body><h1>404 Not Found</h1><p>Path: $path</p></body></html>"
                            }
                        }
                    }

                    # Send response
                    $response.StatusCode = $statusCode
                    $response.ContentType = $contentType

                    if ($content) {
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }

                    $response.OutputStream.Close()

                } catch {
                    Write-Warning "Request error: $_"
                }
            }
        } catch {
            Write-Error "Server error: $_"
        } finally {
            if ($listener.IsListening) {
                $listener.Stop()
            }
            $listener.Close()
            Write-Host "AD-Scout Dashboard server stopped" -ForegroundColor Yellow
        }
    }

    # Helper function to process PSP templates
    function Invoke-PSPTemplate {
        param(
            [string]$TemplateName,
            [string]$TemplatesPath,
            [hashtable]$DashboardState,
            [bool]$AutoRefresh,
            [int]$RefreshInterval
        )

        $templatePath = Join-Path $TemplatesPath $TemplateName
        if (-not (Test-Path $templatePath)) {
            return $null
        }

        $templateContent = Get-Content $templatePath -Raw

        # Set up variables for template
        $Data = $DashboardState.Data
        $Results = $DashboardState.Results
        $Meta = $Data.Meta
        $Summary = $Data.Summary
        $State = $Data.State
        $Comparison = $Data.Comparison
        $Categories = $Data.Categories
        $TopFindings = $Data.TopFindings
        $AllFindings = $Data.AllFindings
        $Frameworks = $Data.Frameworks
        $History = $Data.History
        $TopPriorities = $Data.TopPriorities
        $RiskHeatmap = $Data.RiskHeatmap
        $EnableAutoRefresh = $AutoRefresh
        $RefreshSeconds = $RefreshInterval

        # Process PSP template
        # Split on <% and %> markers
        $output = New-Object System.Text.StringBuilder

        $parts = $templateContent -split '(<%=?|%>)'
        $inCode = $false
        $isExpression = $false

        foreach ($part in $parts) {
            switch ($part) {
                '<%' {
                    $inCode = $true
                    $isExpression = $false
                }
                '<%=' {
                    $inCode = $true
                    $isExpression = $true
                }
                '%>' {
                    $inCode = $false
                    $isExpression = $false
                }
                default {
                    if ($inCode) {
                        try {
                            if ($isExpression) {
                                # Expression - output result
                                $result = Invoke-Expression $part
                                if ($null -ne $result) {
                                    [void]$output.Append([System.Web.HttpUtility]::HtmlEncode($result))
                                }
                            } else {
                                # Code block - execute
                                Invoke-Expression $part | Out-Null
                            }
                        } catch {
                            [void]$output.Append("<!-- Error: $($_.Exception.Message) -->")
                        }
                    } else {
                        # Plain HTML
                        [void]$output.Append($part)
                    }
                }
            }
        }

        return $output.ToString()
    }

    # Helper function to convert to SARIF format
    function ConvertTo-Sarif {
        param([PSCustomObject[]]$Results)

        $sarif = @{
            '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
            version = '2.1.0'
            runs = @(
                @{
                    tool = @{
                        driver = @{
                            name = 'AD-Scout'
                            version = $script:ADScoutVersion ?? '0.2.0'
                            informationUri = 'https://github.com/mwilco03/AD-Scout'
                            rules = @($Results | ForEach-Object {
                                @{
                                    id = $_.RuleId
                                    name = $_.RuleName
                                    shortDescription = @{ text = $_.Description }
                                }
                            })
                        }
                    }
                    results = @($Results | Where-Object { $_.FindingCount -gt 0 } | ForEach-Object {
                        @{
                            ruleId = $_.RuleId
                            level = switch ($_.Score) {
                                { $_ -ge 50 } { 'error'; break }
                                { $_ -ge 20 } { 'warning'; break }
                                default { 'note' }
                            }
                            message = @{
                                text = "$($_.RuleName): $($_.FindingCount) finding(s)"
                            }
                        }
                    })
                }
            )
        }

        return $sarif | ConvertTo-Json -Depth 15
    }

    if ($Background) {
        # Run in background job
        $job = Start-Job -ScriptBlock $serverScriptBlock -ArgumentList @(
            $Port,
            $TemplatesPath,
            $script:ADScoutDashboard,
            $AutoRefresh.IsPresent,
            $RefreshInterval
        )

        $script:ADScoutDashboard.Job = $job
        Write-Host "Dashboard server started in background. Job ID: $($job.Id)" -ForegroundColor Green
        Write-Host "URL: http://localhost:$Port" -ForegroundColor Cyan
        Write-Host "Use Stop-ADScoutDashboardServer to stop." -ForegroundColor Gray

        return $job
    } else {
        # Run in foreground
        & $serverScriptBlock -Port $Port -TemplatesPath $TemplatesPath -DashboardState $script:ADScoutDashboard -AutoRefresh $AutoRefresh.IsPresent -RefreshInterval $RefreshInterval
    }
}
