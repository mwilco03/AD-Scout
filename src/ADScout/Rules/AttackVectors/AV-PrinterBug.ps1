<#
.SYNOPSIS
    Detects conditions enabling the Printer Bug (SpoolSample) attack.

.DESCRIPTION
    The Printer Bug allows any authenticated user to force a computer to authenticate
    to an attacker-controlled server. When combined with unconstrained delegation,
    this enables domain compromise.

.NOTES
    Rule ID    : AV-PrinterBug
    Category   : AttackVectors
    Author     : AD-Scout Contributors
    Version    : 1.0.0
#>

@{
    Id          = 'AV-PrinterBug'
    Version     = '1.0.0'
    Category    = 'AttackVectors'
    Title       = 'Printer Bug (SpoolSample) Attack Conditions'
    Description = 'Detects conditions enabling the Printer Bug attack where the spooler service can be abused to coerce DC authentication to attacker-controlled servers.'
    Severity    = 'High'
    Weight      = 60
    DataSource  = 'DomainControllers,Computers'

    References  = @(
        @{ Title = 'SpoolSample - Printer Bug Tool'; Url = 'https://github.com/leechristensen/SpoolSample' }
        @{ Title = 'Printer Bug Attack'; Url = 'https://www.youraf.com/2018/08/printerbug.html' }
        @{ Title = 'Forced Authentication'; Url = 'https://attack.mitre.org/techniques/T1187/' }
    )

    MITRE = @{
        Tactics    = @('TA0008', 'TA0006')  # Lateral Movement, Credential Access
        Techniques = @('T1187', 'T1557')   # Forced Authentication, MITM
    }

    CIS   = @('5.3')
    STIG  = @('V-78123')
    ANSSI = @('vuln2_printer_bug')

    Scoring = @{
        Type    = 'PerDiscovery'
        PerItem = 20
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Find computers with unconstrained delegation
        $unconstrainedComputers = @()
        if ($Data.Computers) {
            $unconstrainedComputers = $Data.Computers | Where-Object {
                $_.TrustedForDelegation -eq $true -and
                $_.PrimaryGroupID -ne 516  # Not a DC
            }
        }

        # Check DCs for Print Spooler
        if ($Data.DomainControllers) {
            foreach ($dc in $Data.DomainControllers) {
                $dcName = $dc.Name
                if (-not $dcName) { $dcName = $dc.DnsHostName }
                if (-not $dcName) { continue }

                $spoolerVulnerable = $false
                $checkMethod = 'Unknown'

                try {
                    # Try to check if Print Spooler is running
                    $service = Get-Service -Name Spooler -ComputerName $dcName -ErrorAction Stop
                    if ($service.Status -eq 'Running') {
                        $spoolerVulnerable = $true
                        $checkMethod = 'Service Query'
                    }
                } catch {
                    try {
                        # Alternative: Try RPC named pipe check
                        $pipe = "\\$dcName\pipe\spoolss"
                        $testPath = Test-Path $pipe -ErrorAction SilentlyContinue
                        if ($testPath) {
                            $spoolerVulnerable = $true
                            $checkMethod = 'Named Pipe'
                        }
                    } catch {
                        # Assume potentially vulnerable if we can't check
                        $spoolerVulnerable = $true
                        $checkMethod = 'Unable to verify (assume vulnerable)'
                    }
                }

                if ($spoolerVulnerable) {
                    # Calculate attack severity based on unconstrained delegation presence
                    $attackSeverity = 'High'
                    $attackPath = 'DC can be coerced to authenticate via Print Spooler'

                    if ($unconstrainedComputers.Count -gt 0) {
                        $attackSeverity = 'Critical'
                        $attackPath = "DC coercion + $($unconstrainedComputers.Count) unconstrained delegation targets = Domain Compromise"
                    }

                    $findings += [PSCustomObject]@{
                        Computer            = $dcName
                        ComputerType        = 'Domain Controller'
                        SpoolerStatus       = 'Running/Accessible'
                        CheckMethod         = $checkMethod
                        AttackPath          = $attackPath
                        UnconstrainedTargets = $unconstrainedComputers.Count
                        RiskLevel           = $attackSeverity
                        ImpactDescription   = if ($unconstrainedComputers.Count -gt 0) {
                            'Attacker can force DC auth to unconstrained delegation server, capture TGT, and compromise domain'
                        } else {
                            'Attacker can force DC auth for NTLM relay attacks'
                        }
                        DistinguishedName   = $dc.DistinguishedName
                    }
                }
            }
        }

        # Also report unconstrained delegation computers as they are part of the attack chain
        foreach ($computer in $unconstrainedComputers) {
            $findings += [PSCustomObject]@{
                Computer            = $computer.Name
                ComputerType        = 'Unconstrained Delegation'
                SpoolerStatus       = 'N/A (delegation target)'
                CheckMethod         = 'AD Attribute'
                AttackPath          = 'Receives coerced DC authentication, captures TGT for impersonation'
                UnconstrainedTargets = $unconstrainedComputers.Count
                RiskLevel           = 'Critical'
                ImpactDescription   = 'Any user can use this server to capture DC tickets via Printer Bug'
                DistinguishedName   = $computer.DistinguishedName
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Disable Print Spooler on all Domain Controllers and remove unconstrained delegation from non-DC computers.'
        Impact      = 'Low for spooler (DCs should not print). High for delegation changes (may affect applications).'
        Script      = {
            param($Finding, $Domain)

            $dcFindings = $Finding.Findings | Where-Object { $_.ComputerType -eq 'Domain Controller' }
            $delegationFindings = $Finding.Findings | Where-Object { $_.ComputerType -eq 'Unconstrained Delegation' }

            $commands = @"
#############################################################################
# Printer Bug (SpoolSample) Attack Remediation
#############################################################################
#
# Attack Chain:
# 1. Attacker identifies DC with Print Spooler running
# 2. Attacker compromises or has access to server with unconstrained delegation
# 3. Using SpoolSample, attacker coerces DC to authenticate to their server
# 4. Unconstrained delegation server captures DC's TGT
# 5. Attacker uses TGT to DCSync or access any resource as DC
#
# Result: Complete domain compromise
#
#############################################################################
# Vulnerable Domain Controllers (Print Spooler):
$($dcFindings | ForEach-Object { "# - $($_.Computer): Spooler $($_.SpoolerStatus)" } | Out-String)
# Unconstrained Delegation Servers (Attack Targets):
$($delegationFindings | ForEach-Object { "# - $($_.Computer)" } | Out-String)

#############################################################################
# Step 1: Disable Print Spooler on Domain Controllers
#############################################################################

"@

            foreach ($dc in $dcFindings) {
                $commands += @"
# Disable Print Spooler on $($dc.Computer)
Invoke-Command -ComputerName '$($dc.Computer)' -ScriptBlock {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service -Name Spooler -StartupType Disabled
    Write-Host "Spooler disabled on `$env:COMPUTERNAME" -ForegroundColor Green
}

"@
            }

            $commands += @"

#############################################################################
# Step 2: Remove Unconstrained Delegation
#############################################################################

# Review each server before removing delegation - applications may depend on it

"@

            foreach ($computer in $delegationFindings) {
                $commands += @"
# Remove unconstrained delegation from $($computer.Computer)
# CAUTION: Verify no applications require this setting first
# Set-ADComputer -Identity '$($computer.Computer)' -TrustedForDelegation `$false

# Alternative: Convert to constrained delegation
# `$spns = @('http/target.domain.com', 'cifs/target.domain.com')
# Set-ADComputer -Identity '$($computer.Computer)' `
#     -TrustedForDelegation `$false `
#     -Add @{'msDS-AllowedToDelegateTo' = `$spns}

"@
            }

            $commands += @"

#############################################################################
# Step 3: Deploy via Group Policy (Recommended)
#############################################################################

# Create GPO linked to Domain Controllers OU:
# Computer Configuration > Preferences > Control Panel Settings > Services

# Service: Print Spooler
# Startup: Disabled
# Service action: Stop service

# Or use Security Settings > System Services:
# Print Spooler: Disabled

#############################################################################
# Detection and Monitoring
#############################################################################

# Monitor for SpoolSample attacks via Windows Event Log
# Event ID 5145 - Detailed File Share (look for \pipe\spoolss access)
# Event ID 4624 - Logon (DC authenticating to unusual targets)

# Honey pot detection:
# Create a monitored server with unconstrained delegation
# Alert on any authentication capture attempts

#############################################################################
# Verification
#############################################################################

# Verify Print Spooler is disabled on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    `$svc = Get-Service -Name Spooler -ComputerName `$_.HostName -ErrorAction SilentlyContinue
    Write-Host "`$(`$_.HostName): `$(`$svc.Status)" -ForegroundColor `$(
        if (`$svc.Status -eq 'Stopped' -or -not `$svc) { 'Green' } else { 'Red' }
    )
}

# Verify no unconstrained delegation (except DCs)
Get-ADComputer -Filter { TrustedForDelegation -eq `$true } -Properties TrustedForDelegation |
    Where-Object { `$_.DistinguishedName -notlike '*Domain Controllers*' } |
    Select-Object Name, DistinguishedName

"@
            return $commands
        }
    }
}
