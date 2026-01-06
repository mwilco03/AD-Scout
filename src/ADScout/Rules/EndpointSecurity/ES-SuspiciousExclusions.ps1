<#
.SYNOPSIS
    Detects Windows Defender exclusions on sensitive paths.

.DESCRIPTION
    Attackers add Defender exclusions to hide malware. Exclusions on
    temp directories, user profiles, or common malware paths are suspicious.

.NOTES
    Rule ID    : ES-SuspiciousExclusions
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-SuspiciousExclusions'
    Name        = 'Suspicious Defender Exclusions'
    Category    = 'EndpointSecurity'
    Model       = 'AntiMalware'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 8
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1562.001')
    CIS         = @('8.1')
    STIG        = @()
    ANSSI       = @()

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        # Suspicious path patterns
        $suspiciousPatterns = @(
            '\\Temp\\?$',
            '\\AppData\\Local\\Temp',
            '\\Windows\\Temp',
            '\\Users\\Public',
            '\\ProgramData$',
            '\\Downloads\\?$',
            ':\\$',  # Entire drive exclusions
            '\\.ps1$',
            '\\.exe$',
            '\\.dll$',
            '\\.bat$',
            '\\.vbs$',
            '\\.js$',
            '\\Recycle',
            '\\perflogs',
            '\\intel\\',
            '\\AMD\\',
            '\\NVIDIA\\'
        )

        if ($ADData.EndpointData -and $ADData.EndpointData.DefenderStatus) {
            foreach ($endpoint in $ADData.EndpointData.DefenderStatus) {
                $exclusions = $endpoint.Exclusions
                $suspiciousFound = @()

                foreach ($path in $exclusions.ExclusionPath) {
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($path -match $pattern) {
                            $suspiciousFound += "Path: $path"
                            break
                        }
                    }
                }

                foreach ($ext in $exclusions.ExclusionExtension) {
                    if ($ext -match '^(exe|dll|ps1|bat|vbs|js|com|scr)$') {
                        $suspiciousFound += "Extension: .$ext"
                    }
                }

                foreach ($proc in $exclusions.ExclusionProcess) {
                    if ($proc -match '(powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32)') {
                        $suspiciousFound += "Process: $proc"
                    }
                }

                if ($suspiciousFound.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        Hostname            = $endpoint.Hostname
                        TotalExclusions     = $exclusions.TotalExclusions
                        SuspiciousExclusions = $suspiciousFound -join '; '
                        Risk                = 'High'
                        Issue               = 'Defender exclusions on suspicious paths'
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'SuspiciousExclusions', 'Risk')
    DetailFormat     = '{Hostname}: {SuspiciousExclusions}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Review and remove suspicious exclusions

# View current exclusions:
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess

# Remove specific exclusion:
Remove-MpPreference -ExclusionPath "C:\Path\To\Remove"
Remove-MpPreference -ExclusionExtension ".exe"
Remove-MpPreference -ExclusionProcess "powershell.exe"

# IMPORTANT: Investigate why these exclusions were added
# - Could indicate compromised system
# - May be legacy IT decision needing review
# - Check for malware that added them

# Monitor exclusion changes:
# Enable audit logging for Defender configuration changes

"@
    }

    Description = 'Suspicious Defender exclusions that could hide malware or attacker tools.'

    TechnicalExplanation = @"
Attackers commonly add AV exclusions to evade detection:

1. Path exclusions: C:\Windows\Temp, user Downloads, ProgramData
2. Extension exclusions: .exe, .dll, .ps1, .bat
3. Process exclusions: powershell.exe, cmd.exe

Common attack patterns:
- Malware adds exclusion for its own path after initial execution
- Attackers exclude C:\ or entire user profile folders
- Ransomware excludes encryption executable

Suspicious indicators:
- Exclusions on temp directories (common malware staging)
- Executable extensions excluded (allows any malware)
- System utilities excluded (powershell, cmd)
- Very broad exclusions (drive letters, root folders)
"@

    References = @(
        'https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-exclusions-microsoft-defender-antivirus',
        'https://attack.mitre.org/techniques/T1562/001/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.DefenderStatus
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}
