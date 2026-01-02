@{
    Id          = 'A-DCWebClient'
    Version     = '1.0.0'
    Category    = 'Anomalies'
    Title       = 'WebClient Service Running on Domain Controller'
    Description = 'Detects when the WebClient service is running or enabled on Domain Controllers. WebClient enables WebDAV which can be abused for NTLM relay attacks via coercion techniques like PetitPotam, leading to domain compromise.'
    Severity    = 'Critical'
    Weight      = 40
    DataSource  = 'DomainControllers'

    References  = @(
        @{ Title = 'WebClient NTLM Relay'; Url = 'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications' }
        @{ Title = 'PetitPotam Attack'; Url = 'https://github.com/topotam/PetitPotam' }
        @{ Title = 'DC WebDAV Attack'; Url = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
        @{ Title = 'PingCastle Rule A-DC-WebClient'; Url = 'https://www.pingcastle.com/documentation/' }
    )

    MITRE = @{
        Tactics    = @('TA0006', 'TA0008')  # Credential Access, Lateral Movement
        Techniques = @('T1557.001', 'T1187')  # LLMNR/NBT-NS Poisoning, Forced Authentication
    }

    CIS   = @()  # Service-specific settings vary by CIS benchmark version
    STIG  = @()  # WebClient service STIGs are OS-version specific
    ANSSI = @()
    NIST  = @('CM-7', 'SC-7')  # Least Functionality, Boundary Protection

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        try {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                $dcHostName = $dc.DNSHostName

                # Check if WebClient service info is available
                $webClientStatus = $null

                if ($dc.Services) {
                    $webClient = $dc.Services | Where-Object { $_.Name -eq 'WebClient' }
                    if ($webClient) {
                        $webClientStatus = $webClient.Status
                        $webClientStartType = $webClient.StartType
                    }
                }

                # If service status is running or enabled, flag it
                if ($webClientStatus -eq 'Running' -or
                    $webClientStartType -eq 'Automatic' -or
                    $webClientStartType -eq 'Manual') {

                    $findings += [PSCustomObject]@{
                        DCName              = $dcName
                        HostName            = $dcHostName
                        ServiceStatus       = $webClientStatus
                        StartType           = $webClientStartType
                        Severity            = 'Critical'
                        Risk                = 'WebDAV enabled allows NTLM relay via coercion'
                        AttackScenario      = 'Attacker coerces DC auth via PetitPotam, relays to ADCS for certificate'
                        Impact              = 'Complete domain compromise'
                    }
                }
            }

            # If no DC data available, flag for manual check
            if ($Data.DomainControllers.Count -eq 0) {
                try {
                    $domainDN = $Domain.DistinguishedName
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [ADSI]"LDAP://OU=Domain Controllers,$domainDN"
                    $searcher.Filter = "(objectClass=computer)"
                    $searcher.PropertiesToLoad.AddRange(@('cn', 'dNSHostName'))

                    $dcs = $searcher.FindAll()

                    foreach ($dc in $dcs) {
                        $dcName = $dc.Properties['cn'][0]
                        $dcHostName = $dc.Properties['dnshostname'][0]

                        # Try to check service remotely
                        try {
                            $svc = Get-Service -ComputerName $dcHostName -Name 'WebClient' -ErrorAction Stop
                            if ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
                                $findings += [PSCustomObject]@{
                                    DCName              = $dcName
                                    HostName            = $dcHostName
                                    ServiceStatus       = $svc.Status.ToString()
                                    StartType           = $svc.StartType.ToString()
                                    Severity            = 'Critical'
                                    Risk                = 'WebDAV enabled allows NTLM relay via coercion'
                                    AttackScenario      = 'PetitPotam + NTLM Relay = Domain Admin'
                                    Impact              = 'Complete domain compromise'
                                }
                            }
                        } catch {
                            # Cannot access remotely, add for manual verification
                            $findings += [PSCustomObject]@{
                                DCName              = $dcName
                                HostName            = $dcHostName
                                ServiceStatus       = 'Unknown'
                                StartType           = 'Manual verification required'
                                Severity            = 'Medium'
                                Risk                = 'Unable to verify WebClient status remotely'
                                AttackScenario      = 'Verify manually on DC'
                                Impact              = 'Potential coercion attack vector'
                            }
                        }
                    }
                } catch {
                    Write-Verbose "A-DCWebClient: Error querying DCs - $_"
                }
            }

        } catch {
            Write-Verbose "A-DCWebClient: Error - $_"
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable and stop the WebClient service on all Domain Controllers. There is no legitimate reason for WebDAV functionality on a DC.'
        Impact      = 'Low - WebClient is not required for DC functionality. No impact to normal operations.'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# WebClient Service on Domain Controller Remediation
#
# Affected Domain Controllers:
$($Finding.Findings | ForEach-Object { "# - $($_.DCName): Status=$($_.ServiceStatus), StartType=$($_.StartType)" } | Out-String)

# The WebClient service enables WebDAV functionality which:
# 1. Is not required on Domain Controllers
# 2. Enables NTLM relay attacks via coercion (PetitPotam, PrinterBug)
# 3. Can lead to complete domain compromise

# STEP 1: Stop and disable WebClient on all DCs
$($Finding.Findings | ForEach-Object { @"
# Disable WebClient on $($_.DCName)
Invoke-Command -ComputerName "$($_.HostName)" -ScriptBlock {
    Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue
    Set-Service -Name WebClient -StartupType Disabled
    Write-Host "WebClient disabled on `$env:COMPUTERNAME"
}

"@ })

# STEP 2: Alternative - Use sc.exe for remote service management
$($Finding.Findings | ForEach-Object { @"
# Via sc.exe for $($_.DCName):
sc.exe \\$($_.HostName) stop WebClient
sc.exe \\$($_.HostName) config WebClient start= disabled

"@ })

# STEP 3: Disable via Group Policy (recommended for persistence)
# Create a GPO linked to Domain Controllers OU:
# Computer Configuration > Policies > Windows Settings > Security Settings > System Services
# Set "WebClient" to Disabled

# PowerShell to create the GPO:
`$gpoName = "Security - Disable WebClient on DCs"
`$gpo = New-GPO -Name `$gpoName

# Link to Domain Controllers OU
`$dcOU = "OU=Domain Controllers," + (Get-ADDomain).DistinguishedName
New-GPLink -Guid `$gpo.Id -Target `$dcOU

Write-Host "Created GPO: `$gpoName"
Write-Host "Configure manually: Computer Config > Policies > Windows Settings > Security Settings > System Services > WebClient = Disabled"

# STEP 4: Also consider disabling via registry
$($Finding.Findings | ForEach-Object { @"
# Disable via registry on $($_.DCName):
Invoke-Command -ComputerName "$($_.HostName)" -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient" -Name "Start" -Value 4
}

"@ })

# STEP 5: Verify remediation
$($Finding.Findings | ForEach-Object { @"
# Verify on $($_.DCName):
Invoke-Command -ComputerName "$($_.HostName)" -ScriptBlock {
    `$svc = Get-Service -Name WebClient
    Write-Host "`$env:COMPUTERNAME - WebClient Status: `$(`$svc.Status), StartType: `$(`$svc.StartType)"
}

"@ })

# STEP 6: Additional protection - Block WebDAV at firewall
# Block outbound connections on ports 80/443 from DCs to WebDAV servers
# This prevents coerced authentication from being relayed

"@
            return $commands
        }
    }
}
