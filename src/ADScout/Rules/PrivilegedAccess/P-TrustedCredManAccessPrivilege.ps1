@{
    Id          = 'P-TrustedCredManAccessPrivilege'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Access Credential Manager as Trusted Caller Assigned'
    Description = 'Detects when the "Access Credential Manager as a trusted caller" (SeTrustedCredManAccessPrivilege) user right is assigned. This privilege allows the holder to back up and restore credentials from Credential Manager, potentially accessing stored passwords.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'STIG V-63843'; Url = 'https://www.stigviewer.com/stig/windows_server_2016/2020-06-16/finding/V-73783' }
        @{ Title = 'Credential Manager Privilege'; Url = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-credential-manager-as-a-trusted-caller' }
        @{ Title = 'PingCastle Rule P-TrustedCredManAccessPrivilege'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0004')  # Credential Access, Privilege Escalation
        Techniques = @('T1555.004', 'T1003')  # Credentials from Password Stores, OS Credential Dumping
    }

    CIS   = @()  # User rights covered in OS-specific CIS benchmarks
    STIG  = @()  # Credential Manager STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('AC-3', 'AC-6', 'IA-5')  # Access Enforcement, Least Privilege, Authenticator Management

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # SeTrustedCredManAccessPrivilege should not be assigned to anyone
        # Default: No one
        # This privilege is used by Credential Manager backup/restore
        $privilegeName = 'SeTrustedCredManAccessPrivilege'
        $privilegeDisplayName = 'Access Credential Manager as a trusted caller'

        try {
            # Check GPOs for user rights assignments
            foreach ($gpo in $Data.GPOs) {
                $gpoName = $gpo.DisplayName

                # Check if GPO has user rights assignments
                if ($gpo.UserRightsAssignment) {
                    $credManAssignment = $gpo.UserRightsAssignment | Where-Object {
                        $_.Privilege -eq $privilegeName -or
                        $_.Name -eq $privilegeName -or
                        $_.Setting -match 'TrustedCredManAccess'
                    }

                    if ($credManAssignment -and $credManAssignment.Members) {
                        foreach ($member in $credManAssignment.Members) {
                            $findings += [PSCustomObject]@{
                                GPOName             = $gpoName
                                Privilege           = $privilegeName
                                PrivilegeDisplay    = $privilegeDisplayName
                                AssignedTo          = $member
                                Severity            = 'High'
                                Risk                = 'User can backup/restore Credential Manager credentials'
                                Impact              = 'Access to stored passwords, certificates, and secrets'
                                STIG                = 'V-63843'
                            }
                        }
                    }
                }

                # Also check GptTmpl.inf in SYSVOL
                $securityInfPath = "$($gpo.Path)\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (Test-Path $securityInfPath -ErrorAction SilentlyContinue) {
                    try {
                        $content = Get-Content $securityInfPath -Raw -ErrorAction SilentlyContinue

                        if ($content -match "$privilegeName\s*=\s*(.+)") {
                            $assignees = $Matches[1] -split ','

                            foreach ($assignee in $assignees) {
                                $assignee = $assignee.Trim()
                                if ($assignee -and $assignee -ne '') {
                                    # Resolve SID to name if possible
                                    $displayName = $assignee
                                    if ($assignee -match '^\*S-') {
                                        $sid = $assignee.TrimStart('*')
                                        try {
                                            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                                            $displayName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                                        } catch {
                                            $displayName = $sid
                                        }
                                    }

                                    $findings += [PSCustomObject]@{
                                        GPOName             = $gpoName
                                        GPOPath             = $gpo.Path
                                        Privilege           = $privilegeName
                                        PrivilegeDisplay    = $privilegeDisplayName
                                        AssignedTo          = $displayName
                                        RawValue            = $assignee
                                        Severity            = 'High'
                                        Risk                = 'User can access Credential Manager as trusted caller'
                                        Impact              = 'Backup/restore of all stored credentials'
                                        STIG                = 'V-63843'
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }

            # Check local policy on DCs directly
            foreach ($dc in $Data.DomainControllers) {
                try {
                    $localPolicy = Invoke-Command -ComputerName $dc.DNSHostName -ScriptBlock {
                        # Export security policy
                        $tempFile = [System.IO.Path]::GetTempFileName()
                        secedit /export /cfg $tempFile /areas USER_RIGHTS 2>$null | Out-Null

                        $content = Get-Content $tempFile -Raw -ErrorAction SilentlyContinue
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

                        if ($content -match 'SeTrustedCredManAccessPrivilege\s*=\s*(.+)') {
                            return $Matches[1]
                        }
                        return $null
                    } -ErrorAction SilentlyContinue

                    if ($localPolicy) {
                        $assignees = $localPolicy -split ','
                        foreach ($assignee in $assignees) {
                            $assignee = $assignee.Trim()
                            if ($assignee) {
                                $findings += [PSCustomObject]@{
                                    DCName              = $dc.Name
                                    Source              = 'Local Policy'
                                    Privilege           = $privilegeName
                                    PrivilegeDisplay    = $privilegeDisplayName
                                    AssignedTo          = $assignee
                                    Severity            = 'High'
                                    Risk                = 'DC local policy grants Credential Manager access'
                                    Impact              = 'Credentials stored on DC can be extracted'
                                }
                            }
                        }
                    }
                } catch { }
            }

        } catch {
            Write-Verbose "P-TrustedCredManAccessPrivilege: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all assignments of the "Access Credential Manager as a trusted caller" user right. This privilege should not be assigned to any user or group.'
        Impact      = 'Low - This privilege is not needed for normal operation. May affect credential backup utilities.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Access Credential Manager as Trusted Caller Remediation
# STIG: V-63843 / V-73783
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - GPO: $($_.GPOName), Assigned to: $($_.AssignedTo)" } | Out-String)

# This privilege allows users to:
# - Backup credentials from Credential Manager
# - Restore credentials to Credential Manager
# - Potentially access saved passwords and secrets

# The default (and recommended) configuration is NO ACCOUNTS assigned

# STEP 1: Identify GPOs with this assignment
Get-GPO -All | ForEach-Object {
    `$gpo = `$_
    `$gpoPath = "\\`$env:USERDNSDOMAIN\SYSVOL\`$env:USERDNSDOMAIN\Policies\{`$(`$gpo.Id)}"
    `$secPath = "`$gpoPath\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

    if (Test-Path `$secPath) {
        `$content = Get-Content `$secPath -Raw
        if (`$content -match 'SeTrustedCredManAccessPrivilege') {
            Write-Host "Found in GPO: `$(`$gpo.DisplayName)" -ForegroundColor Yellow
        }
    }
}

# STEP 2: Remove via Group Policy Management Console (GPMC)
# 1. Open GPMC (gpmc.msc)
# 2. Find the GPO with the assignment
# 3. Edit the GPO
# 4. Navigate to: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment
# 5. Find "Access Credential Manager as a trusted caller"
# 6. Remove all users/groups
# 7. Or set to "Define this policy setting" with empty membership

# STEP 3: Remove via secedit (command line)
# Create a security template to reset the privilege

`$templateContent = @"

[Unicode]
Unicode=yes

[Privilege Rights]
SeTrustedCredManAccessPrivilege =

[Version]
signature="`$CHICAGO`$"
Revision=1

"@

`$templatePath = "`$env:TEMP\credman_reset.inf"
`$templateContent | Set-Content -Path `$templatePath -Encoding Unicode

# Apply to local policy
secedit /configure /db secedit.sdb /cfg `$templatePath /areas USER_RIGHTS

Remove-Item `$templatePath -Force

Write-Host "Cleared SeTrustedCredManAccessPrivilege from local policy"

# STEP 4: Force Group Policy update
gpupdate /force

# STEP 5: Verify the change
`$tempFile = [System.IO.Path]::GetTempFileName()
secedit /export /cfg `$tempFile /areas USER_RIGHTS 2>`$null
`$content = Get-Content `$tempFile -Raw
Remove-Item `$tempFile -Force

if (`$content -match 'SeTrustedCredManAccessPrivilege\s*=\s*(\S+)') {
    Write-Host "WARNING: Privilege still assigned to: `$(`$Matches[1])" -ForegroundColor Red
} else {
    Write-Host "SUCCESS: SeTrustedCredManAccessPrivilege is not assigned" -ForegroundColor Green
}

# STEP 6: Apply across all DCs
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    Write-Host "`nChecking `$(`$dc.Name)..."
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$tempFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg `$tempFile /areas USER_RIGHTS 2>`$null
        `$content = Get-Content `$tempFile -Raw
        Remove-Item `$tempFile -Force

        if (`$content -match 'SeTrustedCredManAccessPrivilege\s*=\s*(.+)') {
            Write-Host "  ASSIGNED: `$(`$Matches[1])" -ForegroundColor Yellow
        } else {
            Write-Host "  OK: Not assigned" -ForegroundColor Green
        }
    }
}

# STEP 7: Monitor for future assignments
# Create GPO with defined (empty) setting to override any local changes
# Link at Domain Controllers OU level with high priority

"@
            return $commands
        }
    }
}
