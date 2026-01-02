@{
    Id          = 'S-DC-NotUpdated'
    Version     = '1.0.0'
    Category    = 'StaleObjects'
    Title       = 'Domain Controllers Not Recently Updated'
    Description = 'Detects Domain Controllers that have not been updated (patched) within the recommended timeframe. Unpatched DCs are vulnerable to known exploits and security issues.'
    Severity    = 'High'
    Weight      = 35
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Windows Update Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows/deployment/update/best-practices' }
        @{ Title = 'Critical DC Vulnerabilities'; Url = 'https://msrc.microsoft.com/update-guide' }
        @{ Title = 'PingCastle Rule S-DC-NotUpdated'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0001', 'TA0004')  # Initial Access, Privilege Escalation
        Techniques = @('T1190', 'T1068')    # Exploit Public-Facing Application, Exploitation for Privilege Escalation
    }

    CIS   = @()  # Patching requirements vary by OS version
    STIG  = @()  # Patching STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('SI-2', 'RA-5')  # Flaw Remediation, Vulnerability Scanning

    Scoring = @{
        Type      = 'PerDiscover'
        Points    = 10
        MaxPoints = 35
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Thresholds
        $criticalDays = 90    # Critical if not updated in 90 days
        $warningDays = 45     # Warning if not updated in 45 days
        $recommendedDays = 30 # Recommended update cycle

        try {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                $lastUpdate = $null
                $osVersion = $null
                $hotfixInfo = @()

                try {
                    # Try to get last update time via WMI/CIM
                    $updateSession = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        # Get last Windows Update installation time
                        $session = New-Object -ComObject Microsoft.Update.Session
                        $searcher = $session.CreateUpdateSearcher()
                        $history = $searcher.QueryHistory(0, 1)

                        if ($history.Count -gt 0) {
                            return @{
                                LastUpdate = $history[0].Date
                                Title = $history[0].Title
                            }
                        }

                        # Fallback: Check hotfix installation dates
                        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
                        if ($hotfixes) {
                            return @{
                                LastUpdate = ($hotfixes | Select-Object -First 1).InstalledOn
                                Hotfixes = $hotfixes | Select-Object HotFixID, InstalledOn
                            }
                        }

                        return $null
                    } -ErrorAction SilentlyContinue

                    if ($updateSession) {
                        $lastUpdate = $updateSession.LastUpdate
                        if ($updateSession.Hotfixes) {
                            $hotfixInfo = $updateSession.Hotfixes
                        }
                    }

                    # Get OS version
                    $osInfo = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime
                    } -ErrorAction SilentlyContinue

                    if ($osInfo) {
                        $osVersion = "$($osInfo.Caption) Build $($osInfo.BuildNumber)"
                    }

                } catch {
                    Write-Verbose "S-DC-NotUpdated: Cannot query $dcName - $_"
                }

                # If we couldn't get update info, check AD object timestamps
                if (-not $lastUpdate) {
                    try {
                        $dcObj = [ADSI]"LDAP://$($dc.DistinguishedName)"
                        $whenChanged = $dcObj.whenChanged
                        if ($whenChanged) {
                            # Use whenChanged as a proxy (not ideal, but better than nothing)
                            $lastUpdate = [datetime]$whenChanged[0]
                        }
                    } catch { }
                }

                if ($lastUpdate) {
                    $daysSinceUpdate = ((Get-Date) - $lastUpdate).Days

                    if ($daysSinceUpdate -gt $recommendedDays) {
                        $severity = 'Low'
                        if ($daysSinceUpdate -gt $criticalDays) {
                            $severity = 'Critical'
                        } elseif ($daysSinceUpdate -gt $warningDays) {
                            $severity = 'High'
                        } elseif ($daysSinceUpdate -gt $recommendedDays) {
                            $severity = 'Medium'
                        }

                        $findings += [PSCustomObject]@{
                            DCName              = $dcName
                            DNSHostName         = $dc.DNSHostName
                            OperatingSystem     = $osVersion ?? $dc.OperatingSystem
                            LastUpdateDate      = $lastUpdate.ToString('yyyy-MM-dd')
                            DaysSinceUpdate     = $daysSinceUpdate
                            RecentHotfixes      = ($hotfixInfo | ForEach-Object { $_.HotFixID }) -join ', '
                            Severity            = $severity
                            Risk                = "DC not updated in $daysSinceUpdate days"
                            Impact              = 'Vulnerable to known exploits and security issues'
                            Recommendation      = 'Apply latest security updates'
                        }
                    }
                } else {
                    # Couldn't determine update status
                    $findings += [PSCustomObject]@{
                        DCName              = $dcName
                        DNSHostName         = $dc.DNSHostName
                        OperatingSystem     = $dc.OperatingSystem
                        LastUpdateDate      = 'Unknown'
                        DaysSinceUpdate     = 'Unknown'
                        Severity            = 'Medium'
                        Risk                = 'Unable to determine update status'
                        Impact              = 'Patch compliance unknown'
                        Recommendation      = 'Verify Windows Update service and connectivity'
                    }
                }
            }

        } catch {
            Write-Verbose "S-DC-NotUpdated: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Apply all pending security updates to Domain Controllers. Implement a regular patching schedule with proper testing.'
        Impact      = 'Medium - Requires DC restart. Schedule during maintenance windows and ensure redundancy.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Domain Controller Update Remediation
#
# DCs needing updates:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): Last updated $($_.LastUpdateDate) ($($_.DaysSinceUpdate) days ago)" } | Out-String)

# CRITICAL: Always test updates before deploying to production DCs
# Follow the order: RODC first, then non-PDC DCs, then PDC last

# STEP 1: Check current update status on all DCs
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Write-Host "`n=== `$(`$dc.Name) ===" -ForegroundColor Yellow

    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Last update
        `$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
        Write-Host "Recent hotfixes:"
        `$hotfixes | Format-Table HotFixID, Description, InstalledOn

        # Pending updates
        `$updateSession = New-Object -ComObject Microsoft.Update.Session
        `$updateSearcher = `$updateSession.CreateUpdateSearcher()
        `$pendingUpdates = `$updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates

        if (`$pendingUpdates.Count -gt 0) {
            Write-Host "Pending updates: `$(`$pendingUpdates.Count)" -ForegroundColor Red
            `$pendingUpdates | ForEach-Object {
                Write-Host "  - `$(`$_.Title)"
            }
        } else {
            Write-Host "No pending updates" -ForegroundColor Green
        }
    }
}

# STEP 2: WSUS/SCCM status check (if applicable)
# Get-WsusComputer -NameIncludes "DC" | Get-WsusUpdateStatus

# STEP 3: Install updates on a specific DC
# Choose the order carefully:
# 1. RODC (Read-Only DC) - least critical
# 2. Non-PDC domain controllers
# 3. PDC Emulator - last (most critical)

function Install-DCUpdates {
    param([string]`$DCName)

    Write-Host "`nInstalling updates on `$DCName..." -ForegroundColor Yellow

    Invoke-Command -ComputerName `$DCName -ScriptBlock {
        # Create update session
        `$updateSession = New-Object -ComObject Microsoft.Update.Session
        `$updateSearcher = `$updateSession.CreateUpdateSearcher()

        # Search for updates
        Write-Host "Searching for updates..."
        `$searchResult = `$updateSearcher.Search("IsInstalled=0 and Type='Software'")

        if (`$searchResult.Updates.Count -eq 0) {
            Write-Host "No updates needed"
            return
        }

        Write-Host "Found `$(`$searchResult.Updates.Count) updates"

        # Download updates
        `$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        `$searchResult.Updates | ForEach-Object { `$updatesToDownload.Add(`$_) }

        `$downloader = `$updateSession.CreateUpdateDownloader()
        `$downloader.Updates = `$updatesToDownload
        Write-Host "Downloading updates..."
        `$downloader.Download()

        # Install updates
        `$updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        `$searchResult.Updates | Where-Object { `$_.IsDownloaded } | ForEach-Object { `$updatesToInstall.Add(`$_) }

        `$installer = `$updateSession.CreateUpdateInstaller()
        `$installer.Updates = `$updatesToInstall
        Write-Host "Installing updates..."
        `$result = `$installer.Install()

        Write-Host "Installation complete. Reboot required: `$(`$result.RebootRequired)"
    }
}

# STEP 4: Schedule restart during maintenance window
# Example: Restart DC after confirming other DCs are healthy
function Restart-DCGracefully {
    param([string]`$DCName)

    # Verify other DCs are healthy
    `$otherDCs = Get-ADDomainController -Filter { Name -ne `$DCName }
    `$allHealthy = `$true

    foreach (`$dc in `$otherDCs) {
        `$result = Test-Connection -ComputerName `$dc.HostName -Count 1 -Quiet
        if (-not `$result) {
            Write-Host "WARNING: `$(`$dc.Name) not responding!" -ForegroundColor Red
            `$allHealthy = `$false
        }
    }

    if (`$allHealthy) {
        Write-Host "All other DCs healthy. Restarting `$DCName..."
        Restart-Computer -ComputerName `$DCName -Force
    } else {
        Write-Host "Aborting restart - not all DCs are healthy" -ForegroundColor Red
    }
}

# STEP 5: Verify AD replication after restart
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    repadmin /showrepl `$dc.HostName
}

# STEP 6: Set up automatic updates (with approval)
# Via GPO for DCs:
# Computer Configuration > Administrative Templates > Windows Components > Windows Update
# - Configure Automatic Updates: 4 - Auto download and schedule install
# - Scheduled install day/time: Choose maintenance window

Write-Host @"

DC PATCHING BEST PRACTICES:
1. Test updates in lab environment first
2. Backup System State before patching
3. Update RODCs first, PDC last
4. Wait for AD replication between DCs
5. Monitor event logs after reboot
6. Keep at least one DC online at all times

"@ -ForegroundColor Cyan

"@
            return $commands
        }
    }
}
