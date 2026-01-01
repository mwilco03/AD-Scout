@{
    Id          = 'A-NoGPOLLMNR'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'LLMNR and NetBIOS-NS Not Disabled'
    Description = 'Detects when LLMNR (Link-Local Multicast Name Resolution) and NetBIOS Name Service are not disabled via Group Policy. These legacy name resolution protocols are commonly exploited for credential theft via poisoning attacks.'
    Severity    = 'High'
    Weight      = 30
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'LLMNR/NBT-NS Poisoning'; Url = 'https://attack.mitre.org/techniques/T1557/001/' }
        @{ Title = 'Responder Tool'; Url = 'https://github.com/lgandx/Responder' }
        @{ Title = 'PingCastle Rule A-NoGPOLLMNR'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0009')  # Credential Access, Collection
        Techniques = @('T1557.001', 'T1040')  # LLMNR/NBT-NS Poisoning, Network Sniffing
    }

    CIS   = @('18.5.4.1', '18.5.4.2')
    STIG  = @('V-63723')
    ANSSI = @('vuln1_llmnr', 'vuln1_netbios')
    NIST  = @('SC-7', 'SC-8')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        $llmnrDisabled = $false
        $netbiosDisabled = $false
        $mdnsDisabled = $false

        # Registry paths
        # LLMNR: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0
        # NetBIOS: Configured per network adapter or via DHCP

        try {
            # Check GPOs for LLMNR setting
            foreach ($gpo in $Data.GPOs) {
                if ($gpo.RegistrySettings) {
                    foreach ($regSetting in $gpo.RegistrySettings) {
                        # Check for LLMNR disable
                        if ($regSetting.KeyPath -match 'Windows NT\\DNSClient' -and
                            $regSetting.ValueName -eq 'EnableMulticast' -and
                            $regSetting.Value -eq 0) {
                            $llmnrDisabled = $true
                        }

                        # Check for mDNS disable
                        if ($regSetting.KeyPath -match 'Windows NT\\DNSClient' -and
                            $regSetting.ValueName -eq 'EnableMDNS' -and
                            $regSetting.Value -eq 0) {
                            $mdnsDisabled = $true
                        }
                    }
                }

                # Check Administrative Templates
                if ($gpo.ComputerConfiguration -and $gpo.ComputerConfiguration.AdministrativeTemplates) {
                    $llmnrPolicy = $gpo.ComputerConfiguration.AdministrativeTemplates | Where-Object {
                        $_.Name -match 'Turn off multicast name resolution' -or
                        $_.PolicyPath -match 'DNS Client'
                    }

                    if ($llmnrPolicy -and $llmnrPolicy.State -eq 'Enabled') {
                        $llmnrDisabled = $true
                    }
                }
            }

            # Check for NetBIOS configuration in GPO
            foreach ($gpo in $Data.GPOs) {
                if ($gpo.RegistrySettings) {
                    foreach ($regSetting in $gpo.RegistrySettings) {
                        # NetBIOS over TCP/IP setting
                        if ($regSetting.KeyPath -match 'NetBT\\Parameters' -and
                            $regSetting.ValueName -match 'NetBiosOptions|NodeType') {
                            if ($regSetting.Value -eq 2) {  # 2 = Disable NetBIOS over TCP/IP
                                $netbiosDisabled = $true
                            }
                        }
                    }
                }
            }

            # Report findings
            if (-not $llmnrDisabled) {
                $findings += [PSCustomObject]@{
                    Protocol            = 'LLMNR'
                    Status              = 'Not Disabled'
                    GPOSetting          = 'Turn off multicast name resolution'
                    RegistryPath        = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast'
                    RequiredValue       = '0'
                    Severity            = 'High'
                    Risk                = 'LLMNR poisoning enables credential capture'
                    AttackTool          = 'Responder, Inveigh'
                    Impact              = 'Attacker on local network can capture NTLMv2 hashes'
                }
            }

            if (-not $netbiosDisabled) {
                $findings += [PSCustomObject]@{
                    Protocol            = 'NetBIOS-NS'
                    Status              = 'Not Disabled'
                    GPOSetting          = 'Configure NetBIOS over TCP/IP via DHCP or adapter settings'
                    Severity            = 'High'
                    Risk                = 'NetBIOS name poisoning enables credential capture'
                    AttackTool          = 'Responder, Inveigh'
                    Impact              = 'Attacker on local network can capture NTLMv2 hashes'
                }
            }

            if (-not $mdnsDisabled) {
                $findings += [PSCustomObject]@{
                    Protocol            = 'mDNS'
                    Status              = 'Not Disabled'
                    GPOSetting          = 'EnableMDNS registry value'
                    RegistryPath        = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMDNS'
                    RequiredValue       = '0'
                    Severity            = 'Medium'
                    Risk                = 'mDNS can be poisoned for credential capture'
                    Impact              = 'Similar attack vector to LLMNR'
                }
            }

        } catch {
            Write-Verbose "A-NoGPOLLMNR: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable LLMNR and NetBIOS-NS via Group Policy to prevent name resolution poisoning attacks.'
        Impact      = 'Low - These protocols are rarely needed in modern networks with proper DNS. Test in lab first.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# LLMNR and NetBIOS-NS Remediation
#
# Protocols to disable:
$($Finding.Findings | ForEach-Object { "# - $($_.Protocol): $($_.Status)" } | Out-String)

# These protocols enable credential capture attacks using tools like Responder

# STEP 1: Create or edit GPO to disable LLMNR
# Path: Computer Configuration > Administrative Templates > Network > DNS Client
# Setting: "Turn off multicast name resolution" = Enabled

# Via PowerShell - create registry preference in GPO:
`$gpoName = "Security - Disable LLMNR and NetBIOS"
`$gpo = New-GPO -Name `$gpoName -ErrorAction SilentlyContinue
if (-not `$gpo) { `$gpo = Get-GPO -Name `$gpoName }

# Link to domain
New-GPLink -Guid `$gpo.Id -Target (Get-ADDomain).DistinguishedName -ErrorAction SilentlyContinue

# Set LLMNR disable via registry
Set-GPRegistryValue -Guid `$gpo.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0

# Set mDNS disable
Set-GPRegistryValue -Guid `$gpo.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMDNS" -Type DWord -Value 0

Write-Host "Created GPO: `$gpoName with LLMNR disabled"

# STEP 2: Disable NetBIOS over TCP/IP via DHCP
# Configure DHCP option 001 (Microsoft Disable NetBIOS Option) = 2
# Or configure per-adapter:

`$adapters = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' }
foreach (`$adapter in `$adapters) {
    # Get the adapter's registry path
    `$adapterGuid = `$adapter.InterfaceGuid
    `$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_`$adapterGuid"

    if (Test-Path `$regPath) {
        # NetbiosOptions: 0 = Default, 1 = Enable, 2 = Disable
        Set-ItemProperty -Path `$regPath -Name "NetbiosOptions" -Value 2 -Type DWord
        Write-Host "Disabled NetBIOS on adapter: `$(`$adapter.Name)"
    }
}

# STEP 3: Deploy via GPO Script (for all computers)
# Create a startup script that runs:
@'
`$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { `$_.IPEnabled -eq `$true }
foreach (`$adapter in `$adapters) {
    `$adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
'@ | Out-File "\\`$((Get-ADDomain).DNSRoot)\SYSVOL\`$((Get-ADDomain).DNSRoot)\Scripts\Disable-NetBIOS.ps1"

# Add script to GPO Startup Scripts

# STEP 4: Force GPO update
Invoke-GPUpdate -Force

# STEP 5: Verify LLMNR is disabled
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue

# STEP 6: Test with Responder (authorized testing only)
# Run Responder in analyze mode to verify protocols are disabled:
# python Responder.py -I eth0 -A

# STEP 7: Monitor for poisoning attempts
# Enable Windows Firewall logging
# Look for multicast traffic to 224.0.0.252 (LLMNR) port 5355

"@
            return $commands
        }
    }
}
