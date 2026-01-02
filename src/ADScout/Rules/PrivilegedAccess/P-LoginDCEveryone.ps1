@{
    Id          = 'P-LoginDCEveryone'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'Everyone Can Log On to Domain Controllers'
    Description = 'Detects when the "Allow log on locally" or "Allow log on through Remote Desktop Services" user rights on Domain Controllers include Everyone, Authenticated Users, Domain Users, or other broad groups. This violates the principle of least privilege and enables credential theft.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Securing Domain Controllers'; Url = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack' }
        @{ Title = 'DC Logon Rights'; Url = 'https://attack.mitre.org/techniques/T1078/002/' }
        @{ Title = 'PingCastle Rule P-LoginDCEveryone'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0008')  # Privilege Escalation, Lateral Movement
        Techniques = @('T1078.002', 'T1021.001')  # Valid Accounts: Domain, Remote Desktop Protocol
    }

    CIS   = @()  # DC logon rights covered in OS-specific CIS benchmarks
    STIG  = @()  # User rights STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('AC-3', 'AC-6(1)')  # Access Enforcement, Least Privilege

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Dangerous principals for DC logon rights
        $dangerousPrincipals = @(
            'Everyone',
            'Authenticated Users',
            'Domain Users',
            'Users',
            'Domain Computers',
            'S-1-1-0',      # Everyone
            'S-1-5-11',     # Authenticated Users
            '*S-1-5-21-*-513',  # Domain Users (RID 513)
            '*S-1-5-21-*-515'   # Domain Computers (RID 515)
        )

        # User rights to check
        $sensitiveRights = @{
            'SeInteractiveLogonRight' = 'Allow log on locally'
            'SeRemoteInteractiveLogonRight' = 'Allow log on through Remote Desktop Services'
            'SeBatchLogonRight' = 'Log on as a batch job'
            'SeServiceLogonRight' = 'Log on as a service'
        }

        try {
            # Check GPOs linked to Domain Controllers OU
            foreach ($gpo in $Data.GPOs) {
                # Look for GPOs linked to Domain Controllers OU
                $linkedToDC = $false
                if ($gpo.LinksTo) {
                    foreach ($link in $gpo.LinksTo) {
                        if ($link -match 'Domain Controllers' -or $link -match 'OU=Domain Controllers') {
                            $linkedToDC = $true
                            break
                        }
                    }
                }

                # Also check Default Domain Controllers Policy
                if ($gpo.DisplayName -match 'Default Domain Controllers Policy' -or
                    $gpo.Name -match 'Default Domain Controllers Policy') {
                    $linkedToDC = $true
                }

                if (-not $linkedToDC) { continue }

                # Check user rights assignments in the GPO
                if ($gpo.UserRightsAssignment) {
                    foreach ($right in $gpo.UserRightsAssignment.GetEnumerator()) {
                        $rightName = $right.Key
                        $principals = $right.Value

                        # Only check sensitive logon rights
                        if ($rightName -notin $sensitiveRights.Keys) { continue }

                        foreach ($principal in $principals) {
                            $isDangerous = $false
                            foreach ($dp in $dangerousPrincipals) {
                                if ($dp.StartsWith('*')) {
                                    if ($principal -like $dp) {
                                        $isDangerous = $true
                                        break
                                    }
                                } elseif ($principal -match [regex]::Escape($dp) -or $principal -eq $dp) {
                                    $isDangerous = $true
                                    break
                                }
                            }

                            if ($isDangerous) {
                                $findings += [PSCustomObject]@{
                                    GPOName             = $gpo.DisplayName
                                    UserRight           = $sensitiveRights[$rightName]
                                    UserRightKey        = $rightName
                                    DangerousPrincipal  = $principal
                                    LinkedTo            = 'Domain Controllers OU'
                                    Severity            = 'Critical'
                                    Risk                = 'Non-privileged users can log on to Domain Controllers'
                                    Impact              = 'Credential theft, DC compromise, domain takeover'
                                }
                            }
                        }
                    }
                }
            }

            # If no GPO data, check via registry/secedit on DCs
            if ($findings.Count -eq 0 -and $Data.DomainControllers) {
                # Add a note that manual verification is needed
                # In production, this would use remote registry or Invoke-Command
            }

        } catch {
            Write-Verbose "P-LoginDCEveryone: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove broad groups from DC logon rights. Only Domain Admins, Enterprise Admins, and specific administrative accounts should have logon rights to Domain Controllers.'
        Impact      = 'High - Ensure all legitimate DC administrators are in the appropriate groups before removing broad access.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Remove Broad Logon Rights from Domain Controllers
#
# Findings:
$($Finding.Findings | ForEach-Object { "# - GPO: $($_.GPOName) | Right: $($_.UserRight) | Principal: $($_.DangerousPrincipal)" } | Out-String)

# STEP 1: Edit the Default Domain Controllers Policy
# Open Group Policy Management Console (gpmc.msc)
# Navigate to: Forest > Domains > <domain> > Domain Controllers
# Right-click "Default Domain Controllers Policy" > Edit

# STEP 2: Navigate to User Rights Assignment
# Computer Configuration > Policies > Windows Settings > Security Settings >
# Local Policies > User Rights Assignment

# STEP 3: Configure proper logon rights

# "Allow log on locally" should only include:
# - Administrators
# - Backup Operators (if needed)
# - ENTERPRISE DOMAIN CONTROLLERS

# "Allow log on through Remote Desktop Services" should only include:
# - Administrators
# - Or a dedicated "DC Remote Desktop Users" group

# STEP 4: Remove dangerous principals via PowerShell
# Note: Modifying GPO security settings requires RSAT-GPMC

`$gpoName = "Default Domain Controllers Policy"
`$gpo = Get-GPO -Name `$gpoName

# Export current settings
`$reportPath = "`$env:TEMP\DC_Policy_Report.html"
Get-GPOReport -Guid `$gpo.Id -ReportType Html -Path `$reportPath
Start-Process `$reportPath

# STEP 5: Use secedit to apply corrected settings
# Create a security template with correct settings:

@"
[Unicode]
Unicode=yes
[Privilege Rights]
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-9
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544
SeServiceLogonRight = *S-1-5-32-544
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-21-*-513
"@ | Out-File -FilePath "`$env:TEMP\DC_Security.inf" -Encoding Unicode

# Apply the template (run on each DC or via GPO):
# secedit /configure /db secedit.sdb /cfg "`$env:TEMP\DC_Security.inf" /areas USER_RIGHTS

# STEP 6: Also configure Deny logon rights
# "Deny log on locally" should include:
# - Domain Users
# - Domain Computers

# "Deny log on through Remote Desktop Services" should include:
# - Domain Users (except those in approved RDP group)

# STEP 7: Force GPO refresh on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    Invoke-Command -ComputerName `$_.HostName -ScriptBlock { gpupdate /force }
}

"@
            return $commands
        }
    }
}
