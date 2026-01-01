#Requires -Version 5.1
<#
.SYNOPSIS
    Examples of AD-Scout remote execution via IWR (Invoke-WebRequest).

.DESCRIPTION
    This file demonstrates various ways to execute AD-Scout remotely
    without installing the module locally. This is useful for:
    - Quick security assessments
    - Incident response
    - Red team operations
    - Environments where module installation isn't feasible

.NOTES
    Author: AD-Scout Contributors
    License: MIT

    SECURITY: Ensure you have authorization before running security scans.
    Always verify script integrity when downloading from the internet.
#>

# =============================================================================
# BASIC REMOTE EXECUTION
# =============================================================================

# Method 1: Simple IWR | IEX (Invoke-WebRequest | Invoke-Expression)
# This downloads and executes the launcher script which handles everything
iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex

# Method 2: Download bundle directly and run scan
iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1 | iex
Invoke-ADScoutScan | Export-ADScoutReport -Format Console


# =============================================================================
# PARAMETERIZED EXECUTION
# =============================================================================

# Run with specific categories
$script = (iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/src/Invoke-ADScoutRemote.ps1).Content
& ([scriptblock]::Create($script)) -Category PrivilegedAccounts, Kerberos

# Quick scan (Critical and High severity only)
& ([scriptblock]::Create($script)) -QuickScan

# Output to JSON file
& ([scriptblock]::Create($script)) -Format JSON -OutFile "C:\Temp\ad-report.json"

# Target specific domain with credentials
$cred = Get-Credential
& ([scriptblock]::Create($script)) -Domain "target.corp" -Credential $cred


# =============================================================================
# ALTERNATIVE EXECUTION PATTERNS
# =============================================================================

# Pattern 1: Using DownloadString (legacy, but works in constrained environments)
$wc = New-Object System.Net.WebClient
$script = $wc.DownloadString('https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1')
Invoke-Expression $script
Invoke-ADScoutScan | Export-ADScoutReport

# Pattern 2: Save and execute (when you need to review first)
$bundlePath = "$env:TEMP\ADScout.bundle.ps1"
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1' -OutFile $bundlePath
# Review the script content
Get-Content $bundlePath | Select-Object -First 50
# Execute if satisfied
. $bundlePath
Invoke-ADScoutScan | Export-ADScoutReport

# Pattern 3: Encoded command for one-liner execution
# Useful for passing through systems that escape special characters
$cmd = 'iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
# Execute with: powershell -EncodedCommand <encoded>
Write-Host "Encoded command: powershell -EncodedCommand $encoded"


# =============================================================================
# PIPELINE INTEGRATION
# =============================================================================

# Capture results for further processing
$script = (iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1).Content
Invoke-Expression $script
$results = Invoke-ADScoutScan

# Filter critical findings
$critical = $results | Where-Object { $_.Score -ge 50 }
$critical | ForEach-Object {
    Write-Host "CRITICAL: $($_.RuleName) - $($_.FindingCount) findings" -ForegroundColor Red
}

# Export to multiple formats
$results | Export-ADScoutReport -Format JSON -Path ".\findings.json"
$results | Export-ADScoutReport -Format HTML -Path ".\report.html"
$results | Export-ADScoutReport -Format CSV -Path ".\findings.csv"

# Send to SIEM/logging endpoint
$jsonResults = $results | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri "https://siem.company.com/api/ingest" -Method Post -Body $jsonResults -ContentType "application/json"


# =============================================================================
# SCHEDULED/AUTOMATED EXECUTION
# =============================================================================

# Create a scheduled task for regular assessments
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument @"
-NoProfile -ExecutionPolicy Bypass -Command "& {
    `$ErrorActionPreference = 'SilentlyContinue'
    iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex
}" -RedirectStandardOutput "C:\Logs\ADScout-$(Get-Date -Format 'yyyyMMdd').log"
"@
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
# Register-ScheduledTask -TaskName "ADScout-WeeklyAssessment" -Action $action -Trigger $trigger


# =============================================================================
# PROXY AND AUTHENTICATION SCENARIOS
# =============================================================================

# Through corporate proxy
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$wc = New-Object System.Net.WebClient
$wc.Proxy = $proxy
$script = $wc.DownloadString('https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1')
Invoke-Expression $script

# With specific proxy credentials
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy('http://proxy:8080', $true)
[System.Net.WebRequest]::DefaultWebProxy.Credentials = Get-Credential
iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/src/Invoke-ADScoutRemote.ps1 | iex


# =============================================================================
# SECURITY VERIFICATION
# =============================================================================

# Verify script hash before execution (recommended for production)
$expectedHash = "SHA256_HASH_FROM_RELEASE_NOTES"  # Get this from official release
$script = (iwr https://raw.githubusercontent.com/mwilco03/AD-Scout/main/dist/ADScout.bundle.ps1).Content
$actualHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($script))) -Algorithm SHA256).Hash

if ($actualHash -eq $expectedHash) {
    Write-Host "Hash verified. Executing..." -ForegroundColor Green
    Invoke-Expression $script
}
else {
    Write-Host "HASH MISMATCH! Script may have been tampered with." -ForegroundColor Red
    Write-Host "Expected: $expectedHash"
    Write-Host "Actual:   $actualHash"
}
