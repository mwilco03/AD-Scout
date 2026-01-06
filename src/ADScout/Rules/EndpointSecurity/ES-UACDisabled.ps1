<#
.SYNOPSIS
    Detects endpoints with UAC disabled or weakened.

.DESCRIPTION
    User Account Control provides privilege separation. Disabled or
    weakened UAC allows easy privilege escalation.

.NOTES
    Rule ID    : ES-UACDisabled
    Category   : EndpointSecurity
    Author     : AD-Scout
    Version    : 1.0.0
#>

@{
    Id          = 'E-UACDisabled'
    Name        = 'User Account Control Disabled or Weakened'
    Category    = 'EndpointSecurity'
    Model       = 'PrivilegeEscalation'
    Version     = '1.0.0'

    Computation = 'PerDiscover'
    Points      = 10
    MaxPoints   = 100
    Threshold   = $null

    MITRE       = @('T1548.002')  # Abuse Elevation Control: UAC Bypass
    CIS         = @('2.3.17.1', '2.3.17.2')
    STIG        = @('V-63321', 'V-63323')
    ANSSI       = @('R40')

    ScriptBlock = {
        param([Parameter(Mandatory)][hashtable]$ADData)

        $findings = @()

        if ($ADData.EndpointData -and $ADData.EndpointData.UACConfiguration) {
            foreach ($endpoint in $ADData.EndpointData.UACConfiguration) {
                $uac = $endpoint.UACSettings
                $vulns = $endpoint.Vulnerabilities

                if ($vulns.Count -gt 0) {
                    $criticalVulns = $vulns | Where-Object { $_.Risk -eq 'Critical' }
                    $highVulns = $vulns | Where-Object { $_.Risk -eq 'High' }

                    $risk = if ($criticalVulns) { 'Critical' } elseif ($highVulns) { 'High' } else { 'Medium' }

                    $findings += [PSCustomObject]@{
                        Hostname                      = $endpoint.Hostname
                        EnableLUA                     = $uac.EnableLUA
                        ConsentPromptBehaviorAdmin    = $uac.ConsentPromptBehaviorAdmin
                        LocalAccountTokenFilterPolicy = $uac.LocalAccountTokenFilterPolicy
                        PromptOnSecureDesktop         = $uac.PromptOnSecureDesktop
                        VulnerabilityCount            = $vulns.Count
                        Issues                        = ($vulns | ForEach-Object { $_.Description }) -join '; '
                        Risk                          = $risk
                    }
                }
            }
        }

        return $findings
    }

    DetailProperties = @('Hostname', 'Issues', 'Risk')
    DetailFormat     = '{Hostname}: {Issues}'

    Remediation = {
        param([Parameter(Mandatory)]$Finding)
        @"

# Remediation for: $($Finding.Hostname)
# Strengthen UAC configuration

# Enable UAC (EnableLUA):
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1

# Set Admin Approval Mode to prompt on secure desktop:
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1

# Enable filtering for built-in Administrator:
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1

# Disable remote UAC bypass (LocalAccountTokenFilterPolicy):
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0

# Via GPO:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# > User Account Control: * settings

# Reboot required for changes to take effect

"@
    }

    Description = 'UAC is disabled or weakened, allowing easy privilege escalation.'

    TechnicalExplanation = @"
User Account Control (UAC) settings and their risks:

1. EnableLUA = 0 (CRITICAL)
   - UAC completely disabled
   - All processes run with full admin token
   - No privilege separation

2. ConsentPromptBehaviorAdmin = 0 (HIGH)
   - Admins elevate without any prompt
   - Malware can silently escalate

3. LocalAccountTokenFilterPolicy = 1 (HIGH)
   - Disables remote UAC filtering
   - Enables pass-the-hash for local admin accounts
   - Remote admin connections get full token

4. PromptOnSecureDesktop = 0 (MEDIUM)
   - UAC prompt on regular desktop
   - Vulnerable to UI spoofing attacks

5. FilterAdministratorToken = 0 (MEDIUM)
   - Built-in Administrator bypasses UAC
   - Full privileges without prompts
"@

    References = @(
        'https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings',
        'https://attack.mitre.org/techniques/T1548/002/'
    )

    Prerequisites = {
        param([hashtable]$ADData)
        $ADData.EndpointData -and $ADData.EndpointData.UACConfiguration
    }

    AppliesTo = @('OnPremises', 'Hybrid')
}
