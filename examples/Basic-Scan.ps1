<#
.SYNOPSIS
    Basic AD-Scout scan example.

.DESCRIPTION
    Demonstrates basic usage of AD-Scout for scanning Active Directory.

.NOTES
    Run this script with appropriate permissions on a domain-joined machine.
#>

#Requires -Version 5.1

# Import the module
Import-Module ADScout -Force

Write-Host "AD-Scout Basic Scan Example" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan

# Example 1: Basic scan with console output
Write-Host "`n1. Running basic scan with console output..." -ForegroundColor Yellow
Invoke-ADScoutScan | Export-ADScoutReport -Format Console

# Example 2: Scan specific categories
Write-Host "`n2. Scanning only StaleObjects category..." -ForegroundColor Yellow
Invoke-ADScoutScan -Category StaleObjects | Export-ADScoutReport -Format Console

# Example 3: Run specific rules
Write-Host "`n3. Running specific rule (S-PwdNeverExpires)..." -ForegroundColor Yellow
Invoke-ADScoutScan -RuleId 'S-PwdNeverExpires' | Export-ADScoutReport -Format Console

# Example 4: Export to HTML
Write-Host "`n4. Exporting to HTML report..." -ForegroundColor Yellow
$results = Invoke-ADScoutScan
$results | Export-ADScoutReport -Format HTML -Path './ADScout-Report.html'
Write-Host "Report saved to: ./ADScout-Report.html" -ForegroundColor Green

# Example 5: Export to JSON for automation
Write-Host "`n5. Exporting to JSON..." -ForegroundColor Yellow
$results | Export-ADScoutReport -Format JSON -Path './ADScout-Results.json'
Write-Host "JSON saved to: ./ADScout-Results.json" -ForegroundColor Green

# Example 6: Get remediation guidance
Write-Host "`n6. Getting remediation guidance for a rule..." -ForegroundColor Yellow
Get-ADScoutRemediation -RuleId 'S-PwdNeverExpires'

# Example 7: List all available rules
Write-Host "`n7. Available rules:" -ForegroundColor Yellow
Get-ADScoutRule | Format-Table Id, Name, Category -AutoSize

Write-Host "`nScan complete!" -ForegroundColor Green
