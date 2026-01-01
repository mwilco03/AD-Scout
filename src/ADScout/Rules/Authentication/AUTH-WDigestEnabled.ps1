<#
.SYNOPSIS
    Detects if WDigest authentication stores credentials in clear text.

.DESCRIPTION
    WDigest authentication stores credentials in memory in clear text, making
    them easily extractable with tools like Mimikatz. This should be disabled
    on all modern systems.

.NOTES
    Rule ID    : AUTH-WDigestEnabled
    Category   : Authentication
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AUTH-WDigestEnabled'
    Version     = '1.0.0'
    Category    = 'Authentication'
    Title       = 'WDigest Clear Text Credential Storage'
    Description = 'Detects systems where WDigest is storing credentials in clear text memory, enabling credential theft via tools like Mimikatz.'
    Severity    = 'Critical'
    Weight      = 65
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'WDigest Clear Text Credentials'; Url = 'https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/' }
        @{ Title = 'KB2871997 - Credential Protection'; Url = 'https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649' }
        @{ Title = 'Mimikatz sekurlsa::wdigest'; Url = 'https://attack.mitre.org/techniques/T1003/001/' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1003.001')  # LSASS Memory
    }

    CIS   = @('18.3.5')
    STIG  = @('V-63797')
    ANSSI = @('R38')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                $wdigestStatus = 'Unknown'
                $useLogonCredential = $null

                try {
                    $regResult = Invoke-Command -ComputerName $dcName -ScriptBlock {
                        # Check UseLogonCredential registry value
                        $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
                        $value = Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue

                        # Also check if the key exists
                        $keyExists = Test-Path $wdigestPath

                        @{
                            UseLogonCredential = $value.UseLogonCredential
                            KeyExists = $keyExists
                            OSVersion = [System.Environment]::OSVersion.Version.ToString()
                        }
                    } -ErrorAction Stop

                    if ($regResult) {
                        $useLogonCredential = $regResult.UseLogonCredential

                        # Determine vulnerability status
                        if ($useLogonCredential -eq 1) {
                            $wdigestStatus = 'Enabled (VULNERABLE)'
                        } elseif ($useLogonCredential -eq 0) {
                            $wdigestStatus = 'Disabled (Secure)'
                        } elseif ($null -eq $useLogonCredential) {
                            # Default behavior depends on OS version
                            # Windows 8.1/2012 R2 and later: disabled by default (if KB2871997 installed)
                            # Earlier: enabled by default
                            $osVersion = $regResult.OSVersion
                            if ($osVersion -match '^6\.[0-2]' -or $osVersion -match '^5\.') {
                                $wdigestStatus = 'Not configured (defaults to ENABLED on this OS)'
                            } else {
                                $wdigestStatus = 'Not configured (likely defaults to disabled)'
                            }
                        }
                    }
                } catch {
                    $wdigestStatus = 'Unable to check'
                }

                # Report if vulnerable or unknown
                if ($wdigestStatus -match 'VULNERABLE|ENABLED|Unable') {
                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        WDigestStatus       = $wdigestStatus
                        UseLogonCredential  = if ($null -eq $useLogonCredential) { 'Not Set' } else { $useLogonCredential }
                        RiskLevel           = if ($wdigestStatus -match 'VULNERABLE|ENABLED') { 'Critical' } else { 'High' }
                        OperatingSystem     = $dc.OperatingSystem
                        Impact              = 'Clear text passwords stored in LSASS memory'
                        AttackTool          = 'Mimikatz sekurlsa::wdigest'
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable WDigest credential caching by setting UseLogonCredential to 0. Deploy via GPO for all systems.'
        Impact      = 'Low - WDigest is rarely needed. May affect very old IIS digest authentication.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable WDigest Clear Text Credential Storage
#############################################################################
#
# WDigest stores credentials in LSASS memory in CLEAR TEXT.
# Attackers with admin access can extract these using:
#   - Mimikatz: sekurlsa::wdigest
#   - WCE: wce.exe -w
#   - Procdump + offline analysis
#
# This gives attackers actual passwords, not just hashes.
#
# Affected Systems:
$($Finding.Findings | ForEach-Object { "# - $($_.Computer): $($_.WDigestStatus)" } | Out-String)

#############################################################################
# Step 1: Deploy Fix via Registry
#############################################################################

# Apply to all Domain Controllers immediately:
`$dcs = Get-ADDomainController -Filter *

foreach (`$dc in `$dcs) {
    Invoke-Command -ComputerName `$dc.HostName -ScriptBlock {
        `$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

        # Create key if it doesn't exist
        if (-not (Test-Path `$path)) {
            New-Item -Path `$path -Force | Out-Null
        }

        # Set UseLogonCredential to 0 (disabled)
        Set-ItemProperty -Path `$path -Name 'UseLogonCredential' -Value 0 -Type DWord

        Write-Host "WDigest disabled on `$env:COMPUTERNAME" -ForegroundColor Green
    }
}

#############################################################################
# Step 2: Deploy via Group Policy (Recommended)
#############################################################################

# Create GPO linked to all computers

# GPO Path: Computer Configuration > Preferences > Windows Settings > Registry

# Registry Item:
# Action: Update
# Hive: HKEY_LOCAL_MACHINE
# Key Path: SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
# Value name: UseLogonCredential
# Value type: REG_DWORD
# Value data: 0

# Alternative: Use Security Baseline GPOs from Microsoft
# https://www.microsoft.com/en-us/download/details.aspx?id=55319

#############################################################################
# Step 3: Clear Existing Cached Credentials
#############################################################################

# After disabling WDigest, existing cached credentials remain until:
# 1. User logs off
# 2. System reboots
# 3. Credentials expire

# Force logoff of all users (CAUTION - disruptive):
# query user /server:DC01
# logoff <session_id> /server:DC01

# Or schedule a reboot during maintenance window:
# shutdown /r /t 3600 /c "Security update - WDigest disabled"

#############################################################################
# Step 4: Verification
#############################################################################

# Check all DCs:
Get-ADDomainController -Filter * | ForEach-Object {
    `$result = Invoke-Command -ComputerName `$_.HostName -ScriptBlock {
        (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
            -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
    }

    `$status = switch (`$result) {
        0 { 'Disabled (Secure)' }
        1 { 'Enabled (VULNERABLE)' }
        default { 'Not configured' }
    }

    Write-Host "`$(`$_.HostName): `$status" -ForegroundColor `$(
        if (`$result -eq 0) { 'Green' } else { 'Red' }
    )
}

#############################################################################
# Additional Hardening
#############################################################################

# Also ensure these are configured:

# 1. Enable Credential Guard (blocks all credential theft from LSASS)
# 2. Enable LSA Protection (RunAsPPL)
# 3. Disable LM hash storage (NoLMHash = 1)

# LSA Protection:
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
#     -Name 'RunAsPPL' -Value 1 -Type DWord

# No LM Hash:
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
#     -Name 'NoLMHash' -Value 1 -Type DWord

"@
            return $commands
        }
    }
}
