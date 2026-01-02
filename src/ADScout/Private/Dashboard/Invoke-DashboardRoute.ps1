function Invoke-DashboardRoute {
    <#
    .SYNOPSIS
        Routes and processes dashboard HTTP requests.

    .DESCRIPTION
        Handles routing logic for the AD-Scout dashboard web server.
        Processes PSP templates and API endpoints.

    .PARAMETER Request
        The HTTP request object.

    .PARAMETER Response
        The HTTP response object.

    .PARAMETER DashboardState
        Hashtable containing dashboard configuration and data.

    .PARAMETER TemplatesPath
        Path to PSP template directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerRequest]$Request,

        [Parameter(Mandatory)]
        [System.Net.HttpListenerResponse]$Response,

        [Parameter(Mandatory)]
        [hashtable]$DashboardState,

        [Parameter(Mandatory)]
        [string]$TemplatesPath
    )

    $path = $Request.Url.LocalPath
    $method = $Request.HttpMethod

    # Parse query parameters
    $query = @{}
    if ($Request.Url.Query) {
        $queryString = $Request.Url.Query.TrimStart('?')
        $queryString.Split('&') | ForEach-Object {
            $parts = $_.Split('=', 2)
            if ($parts.Count -eq 2) {
                $query[$parts[0]] = [System.Web.HttpUtility]::UrlDecode($parts[1])
            }
        }
    }

    # Parse POST body if present
    $body = $null
    if ($Request.HasEntityBody) {
        $reader = New-Object System.IO.StreamReader($Request.InputStream)
        $bodyText = $reader.ReadToEnd()
        $reader.Close()

        if ($Request.ContentType -like '*json*') {
            try {
                $body = $bodyText | ConvertFrom-Json
            } catch {
                $body = $bodyText
            }
        } else {
            $body = $bodyText
        }
    }

    # Build route context
    $routeContext = [PSCustomObject]@{
        Path = $path
        Method = $method
        Query = $query
        Body = $body
        DashboardState = $DashboardState
        TemplatesPath = $TemplatesPath
        Data = $DashboardState.Data
        AutoRefresh = $DashboardState.AutoRefresh
        RefreshInterval = $DashboardState.RefreshInterval
    }

    # Route to handler
    $result = switch -Regex ($path) {
        # View routes
        '^/$'           { Invoke-ViewRoute -View 'index' -Context $routeContext }
        '^/auditor$'    { Invoke-ViewRoute -View 'auditor' -Context $routeContext }
        '^/manager$'    { Invoke-ViewRoute -View 'manager' -Context $routeContext }
        '^/technician$' { Invoke-ViewRoute -View 'technician' -Context $routeContext }

        # API routes
        '^/api/(.+)$'   { Invoke-ApiRoute -Endpoint $Matches[1] -Context $routeContext }

        # Static files
        default         { Invoke-StaticRoute -Context $routeContext }
    }

    return $result
}

function Invoke-ViewRoute {
    <#
    .SYNOPSIS
        Handles view route requests and renders PSP templates.
    #>
    param(
        [string]$View,
        [PSCustomObject]$Context
    )

    $templatePath = Join-Path $Context.TemplatesPath "$View.psp"

    if (-not (Test-Path $templatePath)) {
        return @{
            StatusCode = 404
            ContentType = 'text/html; charset=utf-8'
            Content = "<html><body><h1>404 Not Found</h1><p>View '$View' not found.</p></body></html>"
        }
    }

    try {
        $content = Invoke-PSPProcessor -TemplatePath $templatePath -Context $Context
        return @{
            StatusCode = 200
            ContentType = 'text/html; charset=utf-8'
            Content = $content
        }
    } catch {
        return @{
            StatusCode = 500
            ContentType = 'text/html; charset=utf-8'
            Content = "<html><body><h1>500 Internal Server Error</h1><pre>$($_.Exception.Message)</pre></body></html>"
        }
    }
}

function Invoke-ApiRoute {
    <#
    .SYNOPSIS
        Handles API endpoint requests and returns JSON.
    #>
    param(
        [string]$Endpoint,
        [PSCustomObject]$Context
    )

    $data = $Context.Data
    $query = $Context.Query
    $method = $Context.Method

    $result = switch -Regex ($Endpoint) {
        '^status$' {
            @{
                status = 'running'
                score = $data.Summary.NormalizedScore
                grade = $data.Summary.Grade
                totalFindings = $data.Summary.TotalFindings
                rulesWithFindings = $data.Summary.RulesWithFindings
                isFirstRun = $data.State.IsFirstRun
                scanTime = $data.Meta.ScanTime.ToString('o')
                domain = $data.Meta.Domain
            }
        }

        '^results$' {
            @{
                meta = $data.Meta
                summary = $data.Summary
                categories = $data.Categories
                findings = $data.AllFindings
            }
        }

        '^baseline$' {
            if ($method -eq 'POST') {
                # Save new baseline
                try {
                    $baselinePath = Save-ADScoutBaseline -Results $Context.DashboardState.Results
                    $Context.DashboardState.BaselinePath = $baselinePath
                    @{ success = $true; path = $baselinePath }
                } catch {
                    @{ success = $false; error = $_.Exception.Message }
                }
            } else {
                @{
                    hasBaseline = $data.State.HasBaseline
                    comparison = $data.Comparison
                    baseline = $data.Baseline
                }
            }
        }

        '^findings$' {
            $findings = $data.AllFindings

            if ($query['category']) {
                $findings = $findings | Where-Object { $_.Category -eq $query['category'] }
            }
            if ($query['severity']) {
                $findings = $findings | Where-Object { $_.Severity -eq $query['severity'] }
            }
            if ($query['search']) {
                $term = $query['search']
                $findings = $findings | Where-Object {
                    $_.RuleId -like "*$term*" -or
                    $_.RuleName -like "*$term*" -or
                    $_.Description -like "*$term*"
                }
            }

            @{
                count = @($findings).Count
                findings = @($findings)
            }
        }

        '^remediation/(.+)$' {
            $ruleId = $Matches[1]
            try {
                $remediation = Get-ADScoutRemediation -RuleId $ruleId -AsScript
                @{ ruleId = $ruleId; remediation = $remediation; success = $true }
            } catch {
                @{ ruleId = $ruleId; remediation = $null; success = $false; error = $_.Exception.Message }
            }
        }

        '^export/(.+)$' {
            $format = $Matches[1].ToLower()
            return Invoke-ExportRoute -Format $format -Context $Context
        }

        '^scan$' {
            if ($method -eq 'POST') {
                try {
                    $newResults = Invoke-ADScoutScan
                    $Context.DashboardState.Data = Get-DashboardData -Results $newResults -BaselinePath $Context.DashboardState.BaselinePath
                    $Context.DashboardState.Results = $newResults
                    @{
                        success = $true
                        score = $Context.DashboardState.Data.Summary.NormalizedScore
                        totalFindings = $Context.DashboardState.Data.Summary.TotalFindings
                    }
                } catch {
                    @{ success = $false; error = $_.Exception.Message }
                }
            } else {
                return @{
                    StatusCode = 405
                    ContentType = 'application/json; charset=utf-8'
                    Content = '{"error":"Method not allowed. Use POST."}'
                }
            }
        }

        '^categories$' {
            @{ categories = $data.Categories }
        }

        '^history$' {
            @{ history = $data.History }
        }

        '^frameworks$' {
            @{ frameworks = $data.Frameworks }
        }

        '^heatmap$' {
            @{ heatmap = $data.RiskHeatmap }
        }

        default {
            return @{
                StatusCode = 404
                ContentType = 'application/json; charset=utf-8'
                Content = '{"error":"Endpoint not found"}'
            }
        }
    }

    return @{
        StatusCode = 200
        ContentType = 'application/json; charset=utf-8'
        Content = $result | ConvertTo-Json -Depth 10
    }
}

function Invoke-ExportRoute {
    <#
    .SYNOPSIS
        Handles export format requests.
    #>
    param(
        [string]$Format,
        [PSCustomObject]$Context
    )

    $data = $Context.Data

    switch ($Format) {
        'json' {
            $content = @{
                meta = $data.Meta
                summary = $data.Summary
                results = @($data.RawResults | ForEach-Object {
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

            return @{
                StatusCode = 200
                ContentType = 'application/json'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="adscout-results.json"' }
                Content = $content
            }
        }

        'csv' {
            $csvData = $data.AllFindings | ForEach-Object {
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

            return @{
                StatusCode = 200
                ContentType = 'text/csv'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="adscout-results.csv"' }
                Content = ($csvData | ConvertTo-Csv -NoTypeInformation) -join "`n"
            }
        }

        'sarif' {
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
                                rules = @($data.RawResults | ForEach-Object {
                                    @{
                                        id = $_.RuleId
                                        name = $_.RuleName
                                        shortDescription = @{ text = $_.Description }
                                    }
                                })
                            }
                        }
                        results = @($data.RawResults | Where-Object { $_.FindingCount -gt 0 } | ForEach-Object {
                            @{
                                ruleId = $_.RuleId
                                level = switch ($_.Score) {
                                    { $_ -ge 50 } { 'error'; break }
                                    { $_ -ge 20 } { 'warning'; break }
                                    default { 'note' }
                                }
                                message = @{ text = "$($_.RuleName): $($_.FindingCount) finding(s)" }
                            }
                        })
                    }
                )
            }

            return @{
                StatusCode = 200
                ContentType = 'application/json'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="adscout-results.sarif"' }
                Content = $sarif | ConvertTo-Json -Depth 15
            }
        }

        'html' {
            $templatePath = Join-Path $Context.TemplatesPath 'auditor.psp'
            $content = Invoke-PSPProcessor -TemplatePath $templatePath -Context $Context

            return @{
                StatusCode = 200
                ContentType = 'text/html'
                Headers = @{ 'Content-Disposition' = 'attachment; filename="adscout-report.html"' }
                Content = $content
            }
        }

        default {
            return @{
                StatusCode = 400
                ContentType = 'application/json'
                Content = (@{ error = "Unsupported format: $Format"; supportedFormats = @('json', 'csv', 'html', 'sarif') } | ConvertTo-Json)
            }
        }
    }
}

function Invoke-StaticRoute {
    <#
    .SYNOPSIS
        Serves static files from the templates directory.
    #>
    param(
        [PSCustomObject]$Context
    )

    $mimeTypes = @{
        '.html' = 'text/html; charset=utf-8'
        '.css'  = 'text/css; charset=utf-8'
        '.js'   = 'application/javascript; charset=utf-8'
        '.json' = 'application/json; charset=utf-8'
        '.png'  = 'image/png'
        '.jpg'  = 'image/jpeg'
        '.gif'  = 'image/gif'
        '.svg'  = 'image/svg+xml'
        '.ico'  = 'image/x-icon'
        '.woff' = 'font/woff'
        '.woff2'= 'font/woff2'
    }

    $filePath = Join-Path $Context.TemplatesPath $Context.Path.TrimStart('/')

    if (-not (Test-Path $filePath -PathType Leaf)) {
        return @{
            StatusCode = 404
            ContentType = 'text/html; charset=utf-8'
            Content = "<html><body><h1>404 Not Found</h1></body></html>"
        }
    }

    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    $contentType = $mimeTypes[$ext]
    if (-not $contentType) {
        $contentType = 'application/octet-stream'
    }

    # Binary files
    if ($ext -in @('.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2')) {
        return @{
            StatusCode = 200
            ContentType = $contentType
            Binary = [System.IO.File]::ReadAllBytes($filePath)
        }
    }

    # Text files
    return @{
        StatusCode = 200
        ContentType = $contentType
        Content = Get-Content $filePath -Raw
    }
}

function Invoke-PSPProcessor {
    <#
    .SYNOPSIS
        Processes a PSP template file and returns rendered HTML.
    #>
    param(
        [string]$TemplatePath,
        [PSCustomObject]$Context
    )

    if (-not (Test-Path $TemplatePath)) {
        throw "Template not found: $TemplatePath"
    }

    $templateContent = Get-Content $TemplatePath -Raw

    # Set up variables for template scope
    $Data = $Context.Data
    $Results = $Context.DashboardState.Results
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
    $EnableAutoRefresh = $Context.AutoRefresh
    $RefreshSeconds = $Context.RefreshInterval
    $Query = $Context.Query

    # Process PSP template using regex to split on delimiters
    $output = New-Object System.Text.StringBuilder

    # Use a state machine to process the template
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
                            $result = Invoke-Expression $part
                            if ($null -ne $result) {
                                [void]$output.Append([string]$result)
                            }
                        } else {
                            # Execute code block, capture any Write-Output
                            $codeResult = Invoke-Expression $part
                            if ($null -ne $codeResult) {
                                [void]$output.Append([string]$codeResult)
                            }
                        }
                    } catch {
                        [void]$output.Append("<!-- PSP Error: $($_.Exception.Message) -->")
                    }
                } else {
                    [void]$output.Append($part)
                }
            }
        }
    }

    return $output.ToString()
}
