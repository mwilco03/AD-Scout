<#
.SYNOPSIS
    Detects DPAPI backup key exposure and credential roaming risks.

.DESCRIPTION
    The DPAPI domain backup key can decrypt any domain user's DPAPI-protected secrets.
    This rule checks for backup key security and credential roaming configurations
    that could expose sensitive data.

.NOTES
    Rule ID    : DP-DPAPIMasterKey
    Category   : DataProtection
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'DP-DPAPIMasterKey'
    Version     = '1.0.0'
    Category    = 'DataProtection'
    Title       = 'DPAPI Backup Key Exposure'
    Description = 'Identifies risks related to the DPAPI domain backup key which can decrypt any domain users DPAPI-protected secrets including browser passwords, certificates, and credentials.'
    Severity    = 'High'
    Weight      = 55
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'DPAPI Secrets'; Url = 'https://docs.microsoft.com/en-us/windows/win32/seccng/cng-dpapi' }
        @{ Title = 'DPAPI Domain Backup Key'; Url = 'https://attack.mitre.org/techniques/T1555/004/' }
        @{ Title = 'Mimikatz DPAPI'; Url = 'https://adsecurity.org/?page_id=1821#DVAPI' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1555.004', 'T1552.004')  # Windows Credential Manager, Private Keys
    }

    CIS   = @('5.4')
    STIG  = @('V-254451')
    ANSSI = @('R40')

    Scoring = @{
        Type    = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Check for DPAPI-related risks
        try {
            # Check if credential roaming is enabled (stores DPAPI keys in AD)
            $gpos = Get-GPO -All -ErrorAction SilentlyContinue
            $credRoamingEnabled = $false

            foreach ($gpo in $gpos) {
                $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
                if ($report -match 'Credential Roaming|CredentialRoaming|ms-PKI-Credential-Roaming-Tokens') {
                    $credRoamingEnabled = $true
                    $findings += [PSCustomObject]@{
                        Finding           = 'Credential Roaming Enabled'
                        Source            = "GPO: $($gpo.DisplayName)"
                        Risk              = 'DPAPI keys stored in AD - accessible via LDAP'
                        DataExposed       = 'Certificates, Private Keys, Credentials'
                        RiskLevel         = 'High'
                        AttackPath        = 'LDAP query -> Extract ms-PKI-RoamingTimeStamp -> Decrypt with domain backup key'
                        Note              = 'Attackers with AD access can retrieve encrypted credentials'
                    }
                }
            }

            # Check for users with roamed credentials
            $usersWithRoaming = Get-ADUser -Filter { 'ms-PKI-RoamingTimeStamp' -like '*' } `
                -Properties 'ms-PKI-RoamingTimeStamp', 'ms-PKI-AccountCredentials', 'ms-PKI-DPAPIMasterKeys' `
                -ErrorAction SilentlyContinue

            if ($usersWithRoaming.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    Finding           = 'Users with Roamed Credentials'
                    Source            = "$($usersWithRoaming.Count) users"
                    Risk              = 'Roamed credentials stored in AD'
                    DataExposed       = 'DPAPI master keys, certificates, credentials'
                    RiskLevel         = 'High'
                    AttackPath        = 'Extract from AD -> Decrypt with backup key'
                    Note              = 'Run: Get-ADUser -Filter * -Properties ms-PKI-DPAPIMasterKeys'
                }
            }

            # Check who has access to the DPAPI backup key
            # The backup key is stored on DCs and protected by system
            # However, Domain Admins can export it

            $domainDN = (Get-ADDomain).DistinguishedName
            $domainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction SilentlyContinue

            $findings += [PSCustomObject]@{
                Finding           = 'DPAPI Domain Backup Key Access'
                Source            = "Domain Admins ($($domainAdmins.Count) members)"
                Risk              = 'Anyone who can DCSync or access DC SYSTEM can extract backup key'
                DataExposed       = 'All domain user DPAPI secrets'
                RiskLevel         = 'High'
                AttackPath        = 'DCSync/NT backup -> Extract DPAPI backup key -> Decrypt any user secrets'
                Note              = 'Backup key can decrypt: browser passwords, WiFi keys, certificates, credentials'
            }

            # Check for Local DPAPI backup on DCs (if accessible)
            if ($Data.DomainControllers) {
                foreach ($dc in $Data.DomainControllers) {
                    $dcName = $dc.Name
                    if (-not $dcName) { $dcName = $dc.DnsHostName }
                    if (-not $dcName) { continue }

                    try {
                        $dpapiInfo = Invoke-Command -ComputerName $dcName -ScriptBlock {
                            # Check for backup of LSA secrets
                            $systemBackup = Test-Path 'C:\Windows\System32\config\RegBack\SYSTEM'
                            $securityBackup = Test-Path 'C:\Windows\System32\config\RegBack\SECURITY'

                            # Check for exported backup keys (would indicate potential exfiltration)
                            $backupKeyFiles = Get-ChildItem -Path 'C:\' -Filter 'backup*.pvk' -Recurse -ErrorAction SilentlyContinue

                            @{
                                SystemBackup = $systemBackup
                                SecurityBackup = $securityBackup
                                BackupKeyFiles = $backupKeyFiles.Count
                            }
                        } -ErrorAction SilentlyContinue

                        if ($dpapiInfo.BackupKeyFiles -gt 0) {
                            $findings += [PSCustomObject]@{
                                Finding           = 'Potential Backup Key Export Found'
                                Source            = "DC: $dcName"
                                Risk              = 'DPAPI backup key may have been exported'
                                DataExposed       = 'All domain DPAPI secrets at risk'
                                RiskLevel         = 'Critical'
                                AttackPath        = 'Key already exported - investigate immediately'
                                Note              = "$($dpapiInfo.BackupKeyFiles) backup*.pvk files found"
                            }
                        }

                    } catch {}
                }
            }

        } catch {
            $findings += [PSCustomObject]@{
                Finding           = 'Check Failed'
                Source            = 'Error'
                Risk              = "Unable to verify DPAPI configuration: $_"
                DataExposed       = 'Unknown'
                RiskLevel         = 'Unknown'
                AttackPath        = 'Manual verification required'
                Note              = ''
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Protect the DPAPI backup key and monitor for credential roaming abuse.'
        Impact      = 'Medium - Key rotation affects recovery of old secrets.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# DPAPI Backup Key Protection
#############################################################################
#
# The DPAPI domain backup key is critical - it can decrypt ANY domain user's
# DPAPI-protected secrets:
# - Browser saved passwords (Chrome, Edge, Firefox)
# - Windows Credential Manager
# - WiFi passwords
# - Certificates and private keys
# - Application secrets
#
# Current risks:
$($Finding.Findings | ForEach-Object { "# - $($_.Finding): $($_.Risk)" } | Out-String)

#############################################################################
# Step 1: Understand What's at Risk
#############################################################################

# DPAPI protects secrets using user-derived keys
# These keys are backed up with the domain backup key
# Anyone with the domain backup key can decrypt ALL user secrets

# The backup key is stored in:
# - LSA Secrets on Domain Controllers
# - Can be extracted via DCSync (ms-ds-backupkey attribute)
# - Can be extracted from NTDS.dit backup + SYSTEM hive

#############################################################################
# Step 2: Disable Credential Roaming (If Not Needed)
#############################################################################

# Credential roaming stores DPAPI keys in AD user attributes
# This makes them accessible via LDAP (not just DC access)

# Check current GPO settings:
Get-GPO -All | ForEach-Object {
    `$report = Get-GPOReport -Guid `$_.Id -ReportType Xml
    if (`$report -match 'CredentialRoaming') {
        Write-Host "Credential Roaming configured in: `$(`$_.DisplayName)" -ForegroundColor Yellow
    }
}

# Disable via GPO:
# User Configuration -> Administrative Templates -> System -> Credential Roaming
# Set "Enable Credential Roaming" to Disabled

# Or remove roaming data from existing users:
# Get-ADUser -Filter * -Properties 'ms-PKI-DPAPIMasterKeys' |
#     Where-Object { `$_.'ms-PKI-DPAPIMasterKeys' } |
#     Set-ADUser -Clear 'ms-PKI-DPAPIMasterKeys','ms-PKI-AccountCredentials','ms-PKI-RoamingTimeStamp'

#############################################################################
# Step 3: Rotate DPAPI Backup Key (Nuclear Option)
#############################################################################

# WARNING: Rotating the backup key means OLD secrets CANNOT be recovered
# if the user forgets their password or account is recovered

# Only do this if you believe the key is compromised:
# This creates a NEW backup key - old key still exists but won't be used

# On a Domain Controller:
# cipher /r:NewDPAPIKey
# Copy keys to secure offline storage
# The new key will be used for new secrets

#############################################################################
# Step 4: Protect DCSync Rights
#############################################################################

# Anyone with DCSync rights can extract the backup key
# Ensure only Domain Admins have DCSync:

`$domainDN = (Get-ADDomain).DistinguishedName
`$acl = Get-Acl "AD:\`$domainDN"

`$dcSyncRights = $acl.Access | Where-Object {
    `$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or  # DS-Replication-Get-Changes
    `$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'     # DS-Replication-Get-Changes-All
}

Write-Host "Accounts with DCSync rights:" -ForegroundColor Cyan
`$dcSyncRights | Select-Object IdentityReference, ActiveDirectoryRights | Format-Table

#############################################################################
# Step 5: Secure DC Backups
#############################################################################

# System State backups contain the DPAPI backup key
# Ensure backups are:
# - Encrypted
# - Stored securely (offline/vault)
# - Access logged and restricted

# Never store backups on network shares accessible to non-admins

#############################################################################
# Step 6: Monitor for Backup Key Access
#############################################################################

# Monitor for:
# - DCSync attacks (Event 4662 with specific GUIDs)
# - Access to LSA secrets
# - NTDS.dit extraction

# DCSync detection query:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
} -MaxEvents 1000 | Where-Object {
    `$_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
} | Select-Object TimeCreated, @{N='User';E={`$_.Properties[1].Value}}

#############################################################################
# Step 7: Use Credential Guard
#############################################################################

# Credential Guard protects DPAPI on the local system
# But the domain backup key can still decrypt roamed credentials

# Enable Credential Guard via GPO:
# Computer Configuration -> Admin Templates -> System -> Device Guard
# -> Turn On Virtualization Based Security
# -> Credential Guard Configuration: Enabled with UEFI lock

#############################################################################
# Verification
#############################################################################

# Check for users with roamed credentials:
Get-ADUser -Filter * -Properties 'ms-PKI-RoamingTimeStamp' |
    Where-Object { `$_.'ms-PKI-RoamingTimeStamp' } |
    Select-Object Name, SamAccountName |
    Format-Table -AutoSize

# Count total:
`$count = (Get-ADUser -Filter { 'ms-PKI-DPAPIMasterKeys' -like '*' }).Count
Write-Host "Users with roamed DPAPI keys: `$count"

"@
            return $commands
        }
    }
}
