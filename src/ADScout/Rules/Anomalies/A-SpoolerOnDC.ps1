<#
.SYNOPSIS
    Detects Print Spooler service running on Domain Controllers.

.DESCRIPTION
    The Print Spooler service on Domain Controllers enables PrintNightmare (CVE-2021-34527)
    and printer bug (SpoolSample) attacks. These attacks allow remote code execution or
    coerced authentication that can lead to domain compromise.

.NOTES
    Rule ID    : A-SpoolerOnDC
    Category   : Anomalies
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'A-SpoolerOnDC'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'Print Spooler Service Running on Domain Controllers'
    Description = 'Detects Domain Controllers with the Print Spooler service running. This service enables PrintNightmare (CVE-2021-34527) RCE attacks and printer bug coercion attacks.'
    Severity    = 'Critical'
    Weight      = 75
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'PrintNightmare - CVE-2021-34527'; Url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527' }
        @{ Title = 'SpoolSample - Printer Bug'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'Microsoft - Disable Print Spooler on DCs'; Url = 'https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7' }
    )

    MITRE = @{
        Tactics    = @('TA0002', 'TA0008')  # Execution, Lateral Movement
        Techniques = @('T1569.002', 'T1187')  # Service Execution, Forced Authentication
    }

    CIS   = @('5.3')
    STIG  = @('V-73805', 'V-78123')
    ANSSI = @('vuln2_spooler')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 25
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                # Try to check if Spooler service is running
                $spoolerStatus = $null
                $vulnerable = $false
                $checkMethod = ''

                try {
                    # Method 1: Try CIM/WMI
                    $service = Get-CimInstance -ClassName Win32_Service -ComputerName $dcName -Filter "Name='Spooler'" -ErrorAction Stop
                    if ($service) {
                        $spoolerStatus = $service.State
                        $startMode = $service.StartMode
                        $vulnerable = $spoolerStatus -eq 'Running'
                        $checkMethod = 'CIM'
                    }
                } catch {
                    try {
                        # Method 2: Try sc.exe query
                        $result = sc.exe \\$dcName query spooler 2>&1
                        if ($result -match 'RUNNING') {
                            $spoolerStatus = 'Running'
                            $vulnerable = $true
                            $checkMethod = 'SC'
                        } elseif ($result -match 'STOPPED') {
                            $spoolerStatus = 'Stopped'
                            $checkMethod = 'SC'
                        }
                    } catch {
                        # Method 3: Check via RPC endpoint
                        try {
                            $rpcEndpoint = [System.Net.Sockets.TcpClient]::new()
                            $rpcEndpoint.Connect($dcName, 135)
                            if ($rpcEndpoint.Connected) {
                                # Port 135 is open, spooler might be running
                                $spoolerStatus = 'Unknown (RPC reachable)'
                                $checkMethod = 'RPC'
                            }
                            $rpcEndpoint.Close()
                        } catch {
                            $spoolerStatus = 'Unable to check'
                            $checkMethod = 'Failed'
                        }
                    }
                }

                # Even if we can't check, flag DCs for manual review
                if ($vulnerable -or $spoolerStatus -eq 'Unknown (RPC reachable)') {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        SpoolerStatus       = $spoolerStatus
                        StartMode           = if ($startMode) { $startMode } else { 'Unknown' }
                        CheckMethod         = $checkMethod
                        VulnerableTo        = 'PrintNightmare (CVE-2021-34527), Printer Bug (SpoolSample), PetitPotam variant'
                        RiskLevel           = 'Critical'
                        DistinguishedName   = $dc.DistinguishedName
                        IPAddress           = $dc.IPv4Address
                        OperatingSystem     = $dc.OperatingSystem
                    }
                } elseif ($spoolerStatus -eq 'Unable to check') {
                    $findings += [PSCustomObject]@{
                        DomainController    = $dcName
                        SpoolerStatus       = 'Unable to verify - manual check required'
                        StartMode           = 'Unknown'
                        CheckMethod         = $checkMethod
                        VulnerableTo        = 'Potential PrintNightmare, Printer Bug exposure'
                        RiskLevel           = 'High'
                        DistinguishedName   = $dc.DistinguishedName
                        IPAddress           = $dc.IPv4Address
                        OperatingSystem     = $dc.OperatingSystem
                    }
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable the Print Spooler service on all Domain Controllers. DCs should never need to print.'
        Impact      = 'Low - Domain Controllers should not require print functionality.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
#############################################################################
# Disable Print Spooler on Domain Controllers
#############################################################################
#
# The Print Spooler service enables multiple critical attacks:
#
# 1. PrintNightmare (CVE-2021-34527)
#    - Remote Code Execution with SYSTEM privileges
#    - Any authenticated user can exploit
#
# 2. Printer Bug / SpoolSample
#    - Forces DC to authenticate to attacker-controlled server
#    - Enables NTLM relay attacks
#    - Can be combined with unconstrained delegation
#
# 3. Coercion Attacks
#    - Used in PetitPotam and other coercion chains
#
#############################################################################

# Domain Controllers with Print Spooler:
$($Finding.Findings | ForEach-Object { "# - $($_.DomainController): $($_.SpoolerStatus)" } | Out-String)

"@

            foreach ($item in $Finding.Findings) {
                $commands += @"

#############################################################################
# Remediate: $($item.DomainController)
#############################################################################

# Stop and disable the Print Spooler service
Invoke-Command -ComputerName '$($item.DomainController)' -ScriptBlock {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service -Name Spooler -StartupType Disabled
    Write-Host "Print Spooler disabled on `$env:COMPUTERNAME"
}

# Or using sc.exe:
# sc.exe \\$($item.DomainController) stop spooler
# sc.exe \\$($item.DomainController) config spooler start= disabled

"@
            }

            $commands += @"

#############################################################################
# GPO Deployment (Recommended for All DCs)
#############################################################################

# Create a GPO linked to the Domain Controllers OU:
#
# Computer Configuration > Policies > Windows Settings > Security Settings >
#   System Services > Print Spooler
#
# Set to: Disabled
#
# PowerShell GPO creation:
`$gpoName = "Security - Disable Print Spooler on DCs"
`$ou = "OU=Domain Controllers,`$((Get-ADDomain).DistinguishedName)"

# Create GPO
New-GPO -Name `$gpoName | New-GPLink -Target `$ou

# Note: Service configuration via GPO requires additional ADMX templates
# or use Group Policy Preferences > Services

#############################################################################
# Verification
#############################################################################

# Verify Spooler is stopped on all DCs
`$dcs = Get-ADDomainController -Filter *
foreach (`$dc in `$dcs) {
    `$svc = Get-Service -Name Spooler -ComputerName `$dc.HostName -ErrorAction SilentlyContinue
    Write-Host "`$(`$dc.HostName): `$(`$svc.Status)" -ForegroundColor `$(if (`$svc.Status -eq 'Stopped') { 'Green' } else { 'Red' })
}

"@
            return $commands
        }
    }
}
