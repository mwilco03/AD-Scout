function Test-ADScoutPrerequisites {
    <#
    .SYNOPSIS
        Validates environment prerequisites before running a scan.

    .DESCRIPTION
        Performs pre-flight checks to identify potential issues before scanning:
        - AD connectivity and permissions
        - EDR/security tool detection with alert warnings
        - Estimated scan duration
        - Required module availability
        - Network accessibility to DCs

    .PARAMETER Domain
        Target domain to validate.

    .PARAMETER Credential
        Credentials to test with.

    .PARAMETER ScanProfile
        Intended scan profile to validate against detected security tools.

    .PARAMETER Quiet
        Only return pass/fail without detailed output.

    .EXAMPLE
        Test-ADScoutPrerequisites -Domain "customer.local"

    .EXAMPLE
        Test-ADScoutPrerequisites -Domain "customer.local" -ScanProfile Comprehensive
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [ValidateSet('Stealth', 'Standard', 'Comprehensive', 'DCOnly', 'EndpointAudit')]
        [string]$ScanProfile = 'Standard',

        [Parameter()]
        [switch]$Quiet
    )

    $results = [ordered]@{
        Timestamp        = Get-Date
        Domain           = $Domain
        OverallStatus    = 'Unknown'
        Checks           = @()
        Warnings         = @()
        Recommendations  = @()
        DetectedEDR      = @()
        EstimatedRuntime = $null
        SafeToRun        = $false
    }

    # Helper to add check results
    function Add-CheckResult {
        param($Name, $Status, $Message, $Details = $null)
        $results.Checks += [PSCustomObject]@{
            Name    = $Name
            Status  = $Status  # Pass, Fail, Warning
            Message = $Message
            Details = $Details
        }
        if (-not $Quiet) {
            $color = switch ($Status) {
                'Pass'    { 'Green' }
                'Fail'    { 'Red' }
                'Warning' { 'Yellow' }
                default   { 'Gray' }
            }
            $symbol = switch ($Status) {
                'Pass'    { '[+]' }
                'Fail'    { '[-]' }
                'Warning' { '[!]' }
                default   { '[?]' }
            }
            Write-Host "$symbol $Name`: $Message" -ForegroundColor $color
        }
    }

    if (-not $Quiet) {
        Write-Host "`nAD-Scout Pre-Flight Checks" -ForegroundColor Cyan
        Write-Host ("=" * 40) -ForegroundColor Cyan
        Write-Host "Target: $(if ($Domain) { $Domain } else { 'Current Domain' })" -ForegroundColor Gray
        Write-Host "Profile: $ScanProfile`n" -ForegroundColor Gray
    }

    # =========================================================================
    # Check 1: PowerShell Version
    # =========================================================================
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Add-CheckResult -Name "PowerShell Version" -Status "Pass" -Message "v$($psVersion.ToString())"
    } else {
        Add-CheckResult -Name "PowerShell Version" -Status "Fail" -Message "v$($psVersion.ToString()) - Requires 5.1+"
    }

    # =========================================================================
    # Check 2: AD Module / Connectivity
    # =========================================================================
    $adModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
    if ($adModuleAvailable) {
        Add-CheckResult -Name "AD Module" -Status "Pass" -Message "ActiveDirectory module available"
    } else {
        Add-CheckResult -Name "AD Module" -Status "Warning" -Message "Not installed - will use ADSI fallback"
        $results.Warnings += "AD module not available; LDAP queries may be slower"
    }

    # =========================================================================
    # Check 3: Domain Connectivity
    # =========================================================================
    try {
        $targetDomain = if ($Domain) { $Domain } else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        $results.Domain = $targetDomain

        # Try to get a DC
        $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $targetDomain)
        $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
        $dc = $domainObj.FindDomainController()

        Add-CheckResult -Name "Domain Connectivity" -Status "Pass" -Message "Connected to $($dc.Name)"
    }
    catch {
        Add-CheckResult -Name "Domain Connectivity" -Status "Fail" -Message "Cannot reach domain: $_"
        $results.OverallStatus = 'Fail'
        $results.SafeToRun = $false
        return [PSCustomObject]$results
    }

    # =========================================================================
    # Check 4: Permissions Test
    # =========================================================================
    try {
        $ldapPath = "LDAP://$targetDomain"
        if ($Credential) {
            $de = New-Object DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            $de = [ADSI]$ldapPath
        }
        $searcher = New-Object DirectoryServices.DirectorySearcher($de)
        $searcher.Filter = "(objectClass=user)"
        $searcher.PageSize = 1
        $testResult = $searcher.FindOne()

        if ($testResult) {
            Add-CheckResult -Name "Read Permissions" -Status "Pass" -Message "Can query AD objects"
        } else {
            Add-CheckResult -Name "Read Permissions" -Status "Warning" -Message "Query returned no results"
        }
    }
    catch {
        Add-CheckResult -Name "Read Permissions" -Status "Fail" -Message "Access denied: $_"
    }

    # =========================================================================
    # Check 5: EDR/Security Tool Detection
    # =========================================================================
    if (-not $Quiet) {
        Write-Host "`nDetecting security tools..." -ForegroundColor Gray
    }

    $edrProducts = @{
        'CrowdStrike'     = @{ Process = 'CSFalcon|csagent'; Service = 'CSFalconService'; AlertLevel = 'High' }
        'CarbonBlack'     = @{ Process = 'cb'; Service = 'CbDefense'; AlertLevel = 'High' }
        'SentinelOne'     = @{ Process = 'SentinelAgent'; Service = 'SentinelAgent'; AlertLevel = 'High' }
        'Defender ATP'    = @{ Process = 'MsSense'; Service = 'Sense'; AlertLevel = 'Medium' }
        'Cylance'         = @{ Process = 'CylanceSvc'; Service = 'CylanceSvc'; AlertLevel = 'High' }
        'Tanium'          = @{ Process = 'TaniumClient'; Service = 'Tanium Client'; AlertLevel = 'Medium' }
        'Elastic Agent'   = @{ Process = 'elastic-agent'; Service = 'Elastic Agent'; AlertLevel = 'Medium' }
        'Cortex XDR'      = @{ Process = 'cyserver'; Service = 'CortexXDR'; AlertLevel = 'High' }
    }

    $detectedEDR = @()
    foreach ($edr in $edrProducts.GetEnumerator()) {
        try {
            $processMatch = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $edr.Value.Process }
            $serviceMatch = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $edr.Value.Service -or $_.DisplayName -match $edr.Key }

            if ($processMatch -or $serviceMatch) {
                $detectedEDR += [PSCustomObject]@{
                    Name       = $edr.Key
                    AlertLevel = $edr.Value.AlertLevel
                    Running    = [bool]$processMatch
                }
            }
        } catch { }
    }

    $results.DetectedEDR = $detectedEDR

    if ($detectedEDR.Count -gt 0) {
        $highAlertEDR = $detectedEDR | Where-Object { $_.AlertLevel -eq 'High' }

        foreach ($edr in $detectedEDR) {
            $status = if ($edr.AlertLevel -eq 'High') { 'Warning' } else { 'Pass' }
            Add-CheckResult -Name "EDR: $($edr.Name)" -Status $status -Message "Detected (Alert Level: $($edr.AlertLevel))"
        }

        if ($highAlertEDR -and $ScanProfile -in @('Comprehensive', 'EndpointAudit')) {
            $results.Warnings += "High-alert EDR detected with $ScanProfile profile - expect SOC alerts"
            $results.Recommendations += "Consider using -ScanProfile Stealth or notify SOC before scanning"
        }
    } else {
        Add-CheckResult -Name "EDR Detection" -Status "Pass" -Message "No EDR agents detected on scan host"
    }

    # =========================================================================
    # Check 6: Estimate Object Counts & Runtime
    # =========================================================================
    try {
        $searcher.Filter = "(objectClass=user)"
        $searcher.PageSize = 0  # Just get count hint
        $userCount = 0
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        try {
            # This is approximate
            $results_all = $searcher.FindAll()
            $userCount = $results_all.Count
            $results_all.Dispose()
        } catch { $userCount = 1000 }  # Estimate

        # Rough runtime estimate: ~2 seconds per 100 objects for full scan
        $estimatedSeconds = switch ($ScanProfile) {
            'Stealth'       { [math]::Max(30, $userCount / 100 * 1) }
            'Standard'      { [math]::Max(60, $userCount / 100 * 2) }
            'Comprehensive' { [math]::Max(120, $userCount / 100 * 5) }
            'EndpointAudit' { [math]::Max(180, $userCount / 100 * 10) }
            default         { [math]::Max(60, $userCount / 100 * 2) }
        }

        $estimatedTime = [TimeSpan]::FromSeconds($estimatedSeconds)
        $results.EstimatedRuntime = $estimatedTime

        Add-CheckResult -Name "Environment Size" -Status "Pass" -Message "~$userCount users, estimated runtime: $($estimatedTime.ToString('mm\:ss'))"
    }
    catch {
        Add-CheckResult -Name "Environment Size" -Status "Warning" -Message "Could not estimate size"
    }

    # =========================================================================
    # Check 7: Profile-Specific Warnings
    # =========================================================================
    $profileRuleCount = switch ($ScanProfile) {
        'Stealth'       { 85 }
        'Standard'      { 180 }
        'Comprehensive' { 270 }
        'DCOnly'        { 45 }
        'EndpointAudit' { 25 }
    }

    $noisyRuleCount = switch ($ScanProfile) {
        'Stealth'       { 0 }
        'Standard'      { 15 }
        'Comprehensive' { 65 }
        'DCOnly'        { 20 }
        'EndpointAudit' { 25 }
    }

    if ($noisyRuleCount -gt 0 -and $detectedEDR.Count -gt 0) {
        $results.Warnings += "$noisyRuleCount rules in '$ScanProfile' profile may trigger EDR alerts"
    }

    # =========================================================================
    # Final Assessment
    # =========================================================================
    $failedChecks = $results.Checks | Where-Object { $_.Status -eq 'Fail' }
    $warningChecks = $results.Checks | Where-Object { $_.Status -eq 'Warning' }

    if ($failedChecks.Count -gt 0) {
        $results.OverallStatus = 'Fail'
        $results.SafeToRun = $false
    }
    elseif ($warningChecks.Count -gt 0) {
        $results.OverallStatus = 'Warning'
        $results.SafeToRun = $true
    }
    else {
        $results.OverallStatus = 'Pass'
        $results.SafeToRun = $true
    }

    if (-not $Quiet) {
        Write-Host "`n" + ("=" * 40) -ForegroundColor Cyan

        $statusColor = switch ($results.OverallStatus) {
            'Pass'    { 'Green' }
            'Fail'    { 'Red' }
            'Warning' { 'Yellow' }
        }
        Write-Host "Overall: $($results.OverallStatus)" -ForegroundColor $statusColor

        if ($results.Warnings.Count -gt 0) {
            Write-Host "`nWarnings:" -ForegroundColor Yellow
            $results.Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        }

        if ($results.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            $results.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
        }

        if ($results.SafeToRun) {
            Write-Host "`nSafe to proceed with scan." -ForegroundColor Green
        } else {
            Write-Host "`nResolve issues before scanning." -ForegroundColor Red
        }
    }

    return [PSCustomObject]$results
}
