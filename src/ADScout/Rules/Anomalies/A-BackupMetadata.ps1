@{
    Id          = 'A-BackupMetadata'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'No Recent Active Directory Backup'
    Description = 'Detects when Active Directory has not been backed up recently based on the backup metadata. Regular AD backups are essential for disaster recovery and ransomware resilience.'
    Severity    = 'High'
    Weight      = 25
    DataSource  = 'Domain'

    References  = @(
        @{ Title = 'AD Backup and Recovery'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-backup-recovery' }
        @{ Title = 'Backup Best Practices'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' }
        @{ Title = 'PingCastle Rule A-BackupMetadata'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0040')  # Impact
        Techniques = @('T1490')   # Inhibit System Recovery
    }

    CIS   = @()  # Backup requirements vary by organization policy
    STIG  = @()  # Backup STIGs are environment-specific
    ANSSI = @()
    NIST  = @('CP-9', 'CP-10')  # Information System Backup, Recovery

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Threshold for backup age (in days)
        $maxBackupAgeDays = 7
        $warningBackupAgeDays = 3

        try {
            # Method 1: Check repadmin showbackup
            # The backup metadata is stored in the domain partition

            # Get the domain's distinguishedName
            $domainDN = $Domain.DistinguishedName
            if (-not $domainDN) {
                $domainDN = "DC=$($Domain.Name.Replace('.', ',DC='))"
            }

            # Check via ADSI for backup metadata
            $lastBackupTime = $null

            try {
                # The backup info is stored in the domain object's replPropertyMetaData
                # Attribute: backupLatency or via repadmin
                $domainObj = [ADSI]"LDAP://$domainDN"

                # Try to get DSASignature which contains backup info
                # This requires more complex LDAP queries or repadmin

            } catch { }

            # Method 2: Check each DC's last backup via WMI/remote
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $backupInfo = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        # Check Windows Server Backup status
                        $wbPolicy = Get-WBPolicy -ErrorAction SilentlyContinue
                        $lastBackup = $null

                        if ($wbPolicy) {
                            $summary = Get-WBSummary -ErrorAction SilentlyContinue
                            if ($summary) {
                                $lastBackup = $summary.LastSuccessfulBackupTime
                            }
                        }

                        # Also check system state backup via wbadmin
                        $wbadminOutput = wbadmin get status 2>&1

                        return @{
                            HasPolicy = ($null -ne $wbPolicy)
                            LastBackup = $lastBackup
                            WBAdminOutput = $wbadminOutput
                        }
                    } -ErrorAction SilentlyContinue

                    if ($backupInfo) {
                        if (-not $backupInfo.HasPolicy) {
                            $findings += [PSCustomObject]@{
                                DCName              = $dc.Name
                                HostName            = $dc.DNSHostName
                                Issue               = 'No backup policy configured'
                                LastBackup          = 'Never'
                                BackupAge           = 'N/A'
                                Severity            = 'Critical'
                                Risk                = 'No AD backup configured on this DC'
                                Impact              = 'Cannot recover from AD corruption or ransomware'
                            }
                        } elseif ($backupInfo.LastBackup) {
                            $backupAge = (Get-Date) - $backupInfo.LastBackup
                            if ($backupAge.TotalDays -gt $maxBackupAgeDays) {
                                $findings += [PSCustomObject]@{
                                    DCName              = $dc.Name
                                    HostName            = $dc.DNSHostName
                                    Issue               = 'Backup too old'
                                    LastBackup          = $backupInfo.LastBackup.ToString('yyyy-MM-dd HH:mm')
                                    BackupAge           = "$([int]$backupAge.TotalDays) days"
                                    Severity            = 'High'
                                    Risk                = 'AD backup is older than threshold'
                                    Impact              = 'May lose recent changes if recovery needed'
                                }
                            }
                        }
                    }
                } catch {
                    # Cannot check remotely
                }
            }

            # If we couldn't get backup info, report as unknown
            if ($findings.Count -eq 0 -and $Data.DomainControllers.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    DCName              = 'All Domain Controllers'
                    Issue               = 'Backup status unknown'
                    LastBackup          = 'Could not determine'
                    Severity            = 'Medium'
                    Risk                = 'Unable to verify AD backup status'
                    Recommendation      = 'Manually verify backups using wbadmin or backup software'
                }
            }

        } catch {
            Write-Verbose "A-BackupMetadata: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Configure Windows Server Backup or third-party backup solution to regularly backup Active Directory. Perform system state backups on at least one DC.'
        Impact      = 'Low - Backup operations may use system resources but do not affect AD operations.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Active Directory Backup Remediation
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): $($_.Issue) - Last backup: $($_.LastBackup)" } | Out-String)

# Active Directory should be backed up at least daily
# System State backup includes AD, SYSVOL, and registry

# STEP 1: Install Windows Server Backup feature
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        if (-not (Get-WindowsFeature -Name Windows-Server-Backup).Installed) {
            Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools
            Write-Host "Installed Windows Server Backup on `$env:COMPUTERNAME"
        } else {
            Write-Host "Windows Server Backup already installed on `$env:COMPUTERNAME"
        }
    }
}

# STEP 2: Configure daily system state backup
# Run on each DC or primary backup DC:

`$backupPolicy = New-WBPolicy

# Add system state to backup
Add-WBSystemState -Policy `$backupPolicy

# Set backup target (local disk, network share, or external drive)
`$backupTarget = New-WBBackupTarget -VolumePath "E:"  # Change to your backup drive
# OR for network: New-WBBackupTarget -NetworkPath "\\backup-server\AD-Backups" -Credential (Get-Credential)

Add-WBBackupTarget -Policy `$backupPolicy -Target `$backupTarget

# Set schedule (daily at 2 AM)
Set-WBSchedule -Policy `$backupPolicy -Schedule 02:00

# Apply the policy
Set-WBPolicy -Policy `$backupPolicy -Force

Write-Host "Backup policy configured"

# STEP 3: Perform immediate backup
Start-WBBackup -Policy (Get-WBPolicy) -AllowDeleteOldBackups

# STEP 4: Alternative - use wbadmin command line
# wbadmin start systemstatebackup -backupTarget:E: -quiet

# STEP 5: Verify backup status
Get-WBSummary | Format-List *

# STEP 6: Test backup restore procedure (in lab)
# wbadmin start systemstaterecovery -version:<version> -backupTarget:E:

# STEP 7: Set up monitoring for backup failures
# Create scheduled task to check backup status and alert:
`$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument @'
`$summary = Get-WBSummary
if (`$summary.LastBackupResultHR -ne 0) {
    Send-MailMessage -To "admin@domain.com" -Subject "AD Backup Failed" -Body "Backup failed on `$env:COMPUTERNAME"
}
'@
`$trigger = New-ScheduledTaskTrigger -Daily -At 7am
Register-ScheduledTask -TaskName "CheckADBackup" -Action `$action -Trigger `$trigger

# STEP 8: Best practices
# - Keep multiple backup copies (3-2-1 rule)
# - Store backups offline/offsite for ransomware protection
# - Test restore procedures regularly
# - Document recovery procedures

"@
            return $commands
        }
    }
}
