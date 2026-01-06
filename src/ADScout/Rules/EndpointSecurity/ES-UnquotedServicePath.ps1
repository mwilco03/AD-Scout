<#
.SYNOPSIS
    Detects services with unquoted paths containing spaces.

.DESCRIPTION
    Unquoted service paths with spaces allow privilege escalation by
    placing malicious executables in the path before the intended target.

.NOTES
    Rule ID    : ES-UnquotedServicePath
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-UnquotedServicePath'
    Name        = 'Unquoted Service Paths'
    Category    = 'EndpointSecurity'
    Model       = 'ServiceSecurity'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 8
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1574.009')  # Hijack Execution Flow: Path Interception
    CIS         = @()
    STIG        = @('V-63395')
    ANSSI       = @()

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.ServiceSecurity) {
            foreach ($endpoint in $ADData.EndpointData.ServiceSecurity) {
                foreach ($svc in $endpoint.UnquotedPaths) {
                    # Higher risk if service runs as SYSTEM or Auto start
                    $risk = 'Medium'
                    if ($svc.StartName -eq 'LocalSystem') { $risk = 'High' }
                    if ($svc.StartMode -eq 'Auto' -and $svc.StartName -eq 'LocalSystem') { $risk = 'Critical' }

                    $findings += [PSCustomObject]@{
                        Hostname    = $endpoint.Hostname
                        ServiceName = $svc.ServiceName
                        DisplayName = $svc.DisplayName
                        PathName    = $svc.PathName
                        StartMode   = $svc.StartMode
                        StartName   = $svc.StartName
                        Risk        = $risk
                        Issue       = 'Unquoted service path with spaces'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'ServiceName', 'PathName', 'Risk')
    DetailFormat     = '{Hostname}: {ServiceName} - {PathName}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Fix unquoted service path: $($Finding.ServiceName)

# Current path: $($Finding.PathName)

# Option 1: Update service path with quotes
sc.exe config "$($Finding.ServiceName)" binPath= `"$($Finding.PathName)`"

# Option 2: Via registry
`$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\$($Finding.ServiceName)'
`$currentPath = (Get-ItemProperty -Path `$regPath).ImagePath
Set-ItemProperty -Path `$regPath -Name 'ImagePath' -Value `"`$currentPath`"

# Verify:
Get-CimInstance Win32_Service -Filter "Name='$($Finding.ServiceName)'" | Select-Object Name, PathName

# Note: Restart service for changes to take effect

"@
    }

    Description = 'Services with unquoted paths containing spaces are vulnerable to privilege escalation.'

    TechnicalExplanation = @"
When a service path contains spaces and is not quoted, Windows tries paths in order:

Example: C:\Program Files\My App\service.exe

Windows tries:
1. C:\Program.exe
2. C:\Program Files\My.exe
3. C:\Program Files\My App\service.exe

An attacker who can write to C:\ or C:\Program Files\ can place a malicious
executable that runs instead of the intended service.

Risk escalation:
- Auto-start services: Payload runs on boot
- LocalSystem services: Full system access
- Network Service: Access to network resources

Common vulnerable paths:
- C:\Program Files\* (spaces after "Program Files")
- C:\Program Files (x86)\*
- Custom application paths

This vulnerability has been present since Windows NT and remains common
in third-party software installers.
"@

    References = @(
        'https://attack.mitre.org/techniques/T1574/009/',
        'https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.ServiceSecurity
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}
