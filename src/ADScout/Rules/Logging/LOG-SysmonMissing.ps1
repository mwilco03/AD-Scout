<#
.SYNOPSIS
    Detects Domain Controllers without Sysmon deployed.

.DESCRIPTION
    Sysmon provides detailed process, network, and file activity logging that
    is essential for threat detection. This rule checks for Sysmon deployment
    on Domain Controllers.

.NOTES
    Rule ID    : LOG-SysmonMissing
    Category   : Logging
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'LOG-SysmonMissing'
    Version     = '1.0.0'
    Category    = 'Logging'
    Title       = 'Sysmon Not Deployed on DCs'
    Description = 'Identifies Domain Controllers without Sysmon installed, reducing visibility into process execution, network connections, and file operations.'
    Severity    = 'Medium'
    Weight      = 35
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'Sysmon'; Url = 'https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon' }
        @{ Title = 'Sysmon Config'; Url = 'https://github.com/SwiftOnSecurity/sysmon-config' }
        @{ Title = 'Sysmon Detection'; Url = 'https://github.com/olafhartong/sysmon-modular' }
    )

    MITRE = @{
        Tactics    = @('TA0005')  # Defense Evasion
        Techniques = @('T1562.001')  # Disable or Modify Tools
    }

    CIS   = @('8.5')
    STIG  = @('V-254458')
    ANSSI = @('R52')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 10
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                try {
                    $sysmonStatus = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        $result = @{
                            SysmonInstalled = $false
                            SysmonRunning = $false
                            SysmonVersion = $null
                            ConfigHash = $null
                            DriverLoaded = $false
                            EventLogExists = $false
                            RecentEvents = 0
                        }

                        # Check if Sysmon service exists
                        $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
                        if ($sysmonService) {
                            $result.SysmonInstalled = $true
                            $result.SysmonRunning = $sysmonService.Status -eq 'Running'
                        }

                        # Check Sysmon driver
                        $sysmonDriver = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like 'Sysmon*' }
                        if ($sysmonDriver) {
                            $result.DriverLoaded = $sysmonDriver.State -eq 'Running'
                        }

                        # Get Sysmon version if installed
                        $sysmonPath = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
                        if ($sysmonPath) {
                            $result.EventLogExists = $true
                        }

                        # Check for Sysmon executable
                        $sysmonExe = Get-ChildItem 'C:\Windows\Sysmon*.exe' -ErrorAction SilentlyContinue
                        if ($sysmonExe) {
                            $result.SysmonVersion = (Get-Item $sysmonExe[0].FullName).VersionInfo.FileVersion
                        }

                        # Check for recent events (indicates active logging)
                        try {
                            $recentEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 -ErrorAction SilentlyContinue
                            $result.RecentEvents = $recentEvents.Count
                        } catch {}

                        # Get config hash if available
                        try {
                            $configEvent = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=16]]" -MaxEvents 1 -ErrorAction SilentlyContinue
                            if ($configEvent) {
                                $result.ConfigHash = ($configEvent.Message -split "`n" | Where-Object { $_ -match 'Hash' }) -replace '.*Hash:\s*', ''
                            }
                        } catch {}

                        return $result
                    } -ErrorAction SilentlyContinue

                    $issues = @()
                    $riskLevel = 'Low'

                    if (-not $sysmonStatus.SysmonInstalled) {
                        $issues += 'Sysmon NOT installed'
                        $riskLevel = 'Medium'
                    } elseif (-not $sysmonStatus.SysmonRunning) {
                        $issues += 'Sysmon installed but NOT running'
                        $riskLevel = 'Medium'
                    } elseif (-not $sysmonStatus.DriverLoaded) {
                        $issues += 'Sysmon driver not loaded'
                        $riskLevel = 'Medium'
                    } elseif ($sysmonStatus.RecentEvents -eq 0) {
                        $issues += 'Sysmon running but no recent events (config issue?)'
                        $riskLevel = 'Low'
                    }

                    # Check version (recommend latest)
                    if ($sysmonStatus.SysmonVersion) {
                        $version = [Version]($sysmonStatus.SysmonVersion -replace '[^\d\.]', '')
                        if ($version -lt [Version]'14.0') {
                            $issues += "Outdated Sysmon version: $($sysmonStatus.SysmonVersion)"
                        }
                    }

                    if ($issues.Count -gt 0) {
                        $findings += [PSCustomObject]@{
                            DomainController  = $dcName
                            SysmonInstalled   = $sysmonStatus.SysmonInstalled
                            SysmonRunning     = $sysmonStatus.SysmonRunning
                            SysmonVersion     = $sysmonStatus.SysmonVersion
                            DriverLoaded      = $sysmonStatus.DriverLoaded
                            RecentEvents      = $sysmonStatus.RecentEvents
                            ConfigHash        = $sysmonStatus.ConfigHash
                            Issues            = ($issues -join '; ')
                            RiskLevel         = $riskLevel
                            Impact            = 'Reduced visibility into process and network activity'
                            DistinguishedName = $dc.DistinguishedName
                        }
                    }

                } catch {
                    $findings += [PSCustomObject]@{
                        DomainController  = $dcName
                        SysmonInstalled   = 'Unknown'
                        SysmonRunning     = 'Unknown'
                        SysmonVersion     = 'Unknown'
                        DriverLoaded      = 'Unknown'
                        RecentEvents      = 0
                        ConfigHash        = 'Unknown'
                        Issues            = "Check failed: $_"
                        RiskLevel         = 'Unknown'
                        Impact            = 'Manual verification required'
                        DistinguishedName = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Deploy Sysmon with appropriate configuration on all Domain Controllers.'
        Impact      = 'Low - Sysmon has minimal performance impact with proper configuration.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Sysmon Deployment
#############################################################################
#
# Sysmon provides critical visibility into:
# - Process creation and command lines
# - Network connections
# - File creation and modifications
# - Registry changes
# - DLL loading
# - Named pipe activity
#
# Missing Sysmon on:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.Issues)" } | Out-String)

#############################################################################
# Step 1: Download Sysmon
#############################################################################

# Download from Microsoft Sysinternals:
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Or via PowerShell:
`$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
`$downloadPath = 'C:\Temp\Sysmon.zip'
`$extractPath = 'C:\Temp\Sysmon'

# Invoke-WebRequest -Uri `$sysmonUrl -OutFile `$downloadPath
# Expand-Archive -Path `$downloadPath -DestinationPath `$extractPath

#############################################################################
# Step 2: Get Sysmon Configuration
#############################################################################

# Use a well-tested config like SwiftOnSecurity's:
# https://github.com/SwiftOnSecurity/sysmon-config

# Or Olaf Hartong's modular config:
# https://github.com/olafhartong/sysmon-modular

# Example: Download SwiftOnSecurity config
`$configUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
# Invoke-WebRequest -Uri `$configUrl -OutFile 'C:\Temp\sysmon-config.xml'

#############################################################################
# Step 3: Install Sysmon on DCs
#############################################################################

`$dcs = Get-ADDomainController -Filter *

# Copy files to each DC:
foreach (`$dc in `$dcs) {
    # Copy Sysmon and config to DC
    Copy-Item -Path 'C:\Temp\Sysmon\Sysmon64.exe' -Destination "\\`$(`$dc.HostName)\C$\Windows\Sysmon64.exe"
    Copy-Item -Path 'C:\Temp\sysmon-config.xml' -Destination "\\`$(`$dc.HostName)\C$\Windows\sysmon-config.xml"

    # Install Sysmon
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        # Accept EULA and install with config
        & C:\Windows\Sysmon64.exe -accepteula -i C:\Windows\sysmon-config.xml

        Write-Host "Installed Sysmon on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 4: Key Sysmon Event IDs
#############################################################################

# Event ID 1: Process creation (most important)
# Event ID 3: Network connection
# Event ID 7: Image loaded (DLL)
# Event ID 8: CreateRemoteThread
# Event ID 10: ProcessAccess (credential dumping)
# Event ID 11: FileCreate
# Event ID 12/13/14: Registry events
# Event ID 17/18: Named pipe
# Event ID 22: DNS query
# Event ID 23: FileDelete

#############################################################################
# Step 5: Configure Event Forwarding
#############################################################################

# Forward Sysmon events to SIEM:
# Configure Windows Event Forwarding subscription

# Or use agent-based collection:
# - Winlogbeat
# - NXLog
# - Splunk Universal Forwarder

#############################################################################
# Step 6: Tune Configuration
#############################################################################

# Update Sysmon config (without reinstalling):
Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
    & C:\Windows\Sysmon64.exe -c C:\Windows\sysmon-config.xml
}

# Verify configuration:
Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
    & C:\Windows\Sysmon64.exe -c
}

#############################################################################
# Step 7: Verify Logging
#############################################################################

# Check Sysmon events on each DC:
foreach (`$dc in `$dcs) {
    `$events = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 -ErrorAction SilentlyContinue
    }

    Write-Host "`$(`$dc.HostName): `$(`$events.Count) recent events" -ForegroundColor Cyan
}

#############################################################################
# Step 8: High-Value Detection Queries
#############################################################################

# Detect Mimikatz-like activity (Event ID 10):
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=10]]" -MaxEvents 100 |
    Where-Object { `$_.Message -match 'lsass.exe' }

# Detect suspicious process creation (Event ID 1):
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" -MaxEvents 100 |
    Where-Object { `$_.Message -match 'powershell.*-enc|-nop.*-w hidden|certutil.*-urlcache' }

# Detect DCSync (network connection to DC on 445/135):
# Combine with Windows Security Event 4662

#############################################################################
# Verification
#############################################################################

foreach (`$dc in `$dcs) {
    `$status = Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$svc = Get-Service 'Sysmon*' -ErrorAction SilentlyContinue
        `$events = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue)
        @{
            Name = `$env:COMPUTERNAME
            Status = `$svc.Status
            LastEvent = `$events.TimeCreated
        }
    }
    `$color = if (`$status.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "`$(`$status.Name): `$(`$status.Status), Last Event: `$(`$status.LastEvent)" -ForegroundColor `$color
}

"@
            return $commands
        }
    }
}
