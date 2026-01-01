@{
    Id          = 'A-LLMNREnabled'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LLMNR/NetBIOS Name Resolution Enabled'
    Description = 'Detects when Link-Local Multicast Name Resolution (LLMNR) and NetBIOS over TCP/IP are not disabled. These legacy protocols are commonly exploited by attackers using tools like Responder to capture NTLMv2 hashes for offline cracking or relay attacks.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'NetworkSecurity'

    References  = @(
        @{ Title = 'LLMNR/NBT-NS Poisoning and SMB Relay'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'Responder - LLMNR/NBT-NS/mDNS Poisoner'; Url = 'https://github.com/lgandx/Responder' }
        @{ Title = 'Microsoft - Disable LLMNR'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800671(v=ws.11)' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1557.001', 'T1040')  # LLMNR/NBT-NS Poisoning, Network Sniffing
    }

    CIS   = @('9.2.1', '9.2.2')
    STIG  = @('V-220932', 'V-220933')
    ANSSI = @('R15')

    Scoring = @{
        Type      = 'TriggerOnPresence'
        PerItem   = 50
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $llmnrSettings = $Data.NetworkSecurity.LLMNRSettings

        if ($llmnrSettings -and -not $llmnrSettings.LLMNRDisabled) {
            $findings += [PSCustomObject]@{
                Finding             = 'LLMNR Not Disabled'
                CurrentState        = 'LLMNR is enabled (Windows default)'
                ConfiguredViaGPO    = $llmnrSettings.ConfiguredViaGPO
                GPOName             = $llmnrSettings.GPOName
                RiskLevel           = 'Critical'
                AttackVector        = 'Responder, Inveigh - Capture NTLMv2 hashes'
                Impact              = @(
                    'NTLMv2 hash capture and offline cracking',
                    'NTLM relay attacks to SMB/LDAP/HTTP',
                    'Credential theft without user interaction',
                    'Lateral movement via relayed authentication'
                ) -join '; '
                RequiredGPOSetting  = @{
                    Path  = 'Computer Configuration > Administrative Templates > Network > DNS Client'
                    Name  = 'Turn off multicast name resolution'
                    Value = 'Enabled'
                }
                RegistryFix         = @{
                    Path  = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                    Name  = 'EnableMulticast'
                    Value = 0
                    Type  = 'DWORD'
                }
            }
        }

        # Also check NetBIOS
        if ($llmnrSettings -and -not $llmnrSettings.NetBIOSDisabled) {
            $findings += [PSCustomObject]@{
                Finding             = 'NetBIOS over TCP/IP Not Disabled'
                CurrentState        = 'NetBIOS is enabled on network adapters'
                RiskLevel           = 'High'
                AttackVector        = 'NBT-NS poisoning via Responder'
                Impact              = 'Similar to LLMNR - credential capture and relay'
                RequiredSetting     = 'Disable via DHCP option 001 or per-adapter settings'
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable LLMNR via Group Policy and NetBIOS via DHCP or network adapter settings. This is a critical security hardening step.'
        Impact      = 'Low - May affect legacy name resolution in rare cases'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# ================================================================
# CRITICAL: DISABLE LLMNR AND NetBIOS
# ================================================================
# These protocols are actively exploited by:
# - Responder (https://github.com/lgandx/Responder)
# - Inveigh (https://github.com/Kevin-Robertson/Inveigh)
#
# Attackers can capture NTLMv2 hashes WITHOUT user interaction
# by simply waiting for name resolution broadcasts.

# ================================================================
# METHOD 1: Group Policy (Recommended)
# ================================================================

# 1. Open Group Policy Management Console
# 2. Edit Default Domain Policy or create new GPO
# 3. Navigate to:
#    Computer Configuration >
#    Administrative Templates >
#    Network >
#    DNS Client
# 4. Enable "Turn off multicast name resolution"

# To verify GPO is applied:
gpresult /r /scope:computer | findstr -i "multicast"

# ================================================================
# METHOD 2: Registry (for immediate fix)
# ================================================================

# Disable LLMNR via registry:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

# Verify:
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast

# ================================================================
# DISABLE NetBIOS OVER TCP/IP
# ================================================================

# Option 1: DHCP Option 001 (Microsoft Disable NetBIOS Option)
# Configure on DHCP server - applies to all DHCP clients

# Option 2: PowerShell for all adapters:
`$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { `$_.IPEnabled -eq `$true }
foreach (`$adapter in `$adapters) {
    # 0 = Default, 1 = Enable, 2 = Disable
    `$adapter.SetTcpipNetbios(2)
}

# Option 3: Disable via registry for each adapter:
# HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
# NetbiosOptions = 2

# ================================================================
# VERIFY REMEDIATION
# ================================================================

# Check LLMNR status:
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue

# Check NetBIOS status per adapter:
Get-WmiObject Win32_NetworkAdapterConfiguration | ``
    Where-Object { `$_.IPEnabled } | ``
    Select-Object Description, TcpipNetbiosOptions

# Test with nbtstat:
nbtstat -n

"@
            return $commands
        }
    }
}
