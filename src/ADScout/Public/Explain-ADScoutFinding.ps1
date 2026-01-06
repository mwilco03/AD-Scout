function Explain-ADScoutFinding {
    <#
    .SYNOPSIS
        Provides customer-friendly explanation of a finding.

    .DESCRIPTION
        Generates a clear, non-technical explanation of a finding suitable for
        presenting to customers, management, or non-security stakeholders.

        Includes:
        - Plain-language description of the risk
        - Real-world attack scenario
        - Business impact
        - Recommended remediation steps
        - Effort estimate

    .PARAMETER Finding
        A finding object from Invoke-ADScoutScan results.

    .PARAMETER RuleId
        Rule ID to explain (fetches rule definition).

    .PARAMETER Format
        Output format: Text, Markdown, HTML.

    .PARAMETER Audience
        Target audience: Executive, Technical, Compliance.

    .EXAMPLE
        $results[0] | Explain-ADScoutFinding

    .EXAMPLE
        Explain-ADScoutFinding -RuleId "P-UnconstrainedDelegation" -Audience Executive

    .EXAMPLE
        $results | Where-Object { $_.Score -ge 50 } | Explain-ADScoutFinding -Format Markdown
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$Finding,

        [Parameter()]
        [string]$RuleId,

        [Parameter()]
        [ValidateSet('Text', 'Markdown', 'HTML')]
        [string]$Format = 'Text',

        [Parameter()]
        [ValidateSet('Executive', 'Technical', 'Compliance')]
        [string]$Audience = 'Executive'
    )

    begin {
        # Risk explanations database
        $riskExplanations = @{
            # Privileged Access
            'P-UnconstrainedDelegation' = @{
                Executive = @{
                    Summary    = "Computers can impersonate any user to any service"
                    Risk       = "An attacker who compromises one of these systems gains the ability to impersonate any user in your organization, including administrators."
                    Scenario   = "An attacker sends a phishing email to an admin. When the admin connects to the compromised server, the attacker captures their identity and uses it to access any system."
                    Impact     = "Complete domain compromise possible from a single server breach."
                    Effort     = "Medium - Requires testing application compatibility before changing"
                }
                Technical = @{
                    Summary    = "TrustedForDelegation flag enabled on non-DC computers"
                    Risk       = "Kerberos TGT forwarding allows credential theft via PrinterBug/PetitPotam attacks"
                    Scenario   = "Attacker uses SpoolSample or PetitPotam to coerce DC authentication to unconstrained delegation host, captures TGT, performs pass-the-ticket for domain admin access"
                    Impact     = "CVSS-equivalent: 9.8 Critical"
                    Effort     = "Convert to Constrained Delegation or RBCD"
                }
            }

            'S-PwdNeverExpires' = @{
                Executive = @{
                    Summary    = "Accounts have passwords that never need to be changed"
                    Risk       = "If these passwords are stolen, they remain valid forever, giving attackers permanent access."
                    Scenario   = "An old password from a 2019 breach is still valid today because it was never changed."
                    Impact     = "Persistent unauthorized access to your systems and data."
                    Effort     = "Low - Enable password expiration policy"
                }
                Technical = @{
                    Summary    = "UserAccountControl DONT_EXPIRE_PASSWORD flag set"
                    Risk       = "Credential exposure has infinite exploitation window"
                    Scenario   = "Breached credentials from historic incidents remain valid, no rotation enforcement"
                    Impact     = "Increases dwell time for attackers, complicates incident response"
                    Effort     = "Set password expiration, coordinate with service account owners"
                }
            }

            'A-SMBSigningNotRequired' = @{
                Executive = @{
                    Summary    = "Network file sharing traffic can be intercepted and modified"
                    Risk       = "Attackers on your network can intercept file transfers and inject malicious content."
                    Scenario   = "An attacker intercepts a login request and redirects it to gain access to a server."
                    Impact     = "Data theft, malware injection, unauthorized access."
                    Effort     = "Low - Group Policy change"
                }
                Technical = @{
                    Summary    = "SMB signing not required on domain controllers"
                    Risk       = "Vulnerable to NTLM relay attacks (ntlmrelayx, Responder)"
                    Scenario   = "Attacker runs Responder, captures NTLM auth, relays to DC for admin access"
                    Impact     = "Privilege escalation to domain admin via network position"
                    Effort     = "Enable via GPO: RequireSecuritySignature = 1"
                }
            }

            'K-Kerberoasting' = @{
                Executive = @{
                    Summary    = "Service account passwords can be cracked offline"
                    Risk       = "Attackers can steal encrypted passwords and crack them on their own computers without being detected."
                    Scenario   = "An attacker with basic network access extracts service account passwords and cracks them overnight."
                    Impact     = "Compromised service accounts often have elevated privileges."
                    Effort     = "Medium - Requires service account password changes"
                }
                Technical = @{
                    Summary    = "Service accounts with weak SPNs vulnerable to Kerberoasting"
                    Risk       = "TGS tickets can be requested by any user and cracked offline"
                    Scenario   = "GetUserSPNs.py or Rubeus kerberoast, hashcat/john to crack RC4-encrypted tickets"
                    Impact     = "Service account compromise, often with admin rights"
                    Effort     = "25+ character passwords, AES-only encryption, gMSA migration"
                }
            }
        }

        # Generic explanations for rules not in database
        $genericExplanations = @{
            Executive = @{
                Summary    = "Security misconfiguration detected"
                Risk       = "This issue could allow attackers to gain unauthorized access or escalate their privileges."
                Scenario   = "An attacker exploits this weakness to move deeper into your network."
                Impact     = "Potential data breach or system compromise."
                Effort     = "Varies - See technical remediation steps"
            }
            Technical = @{
                Summary    = "Security control gap identified"
                Risk       = "Deviates from security best practices"
                Scenario   = "Exploitation depends on specific attack vector"
                Impact     = "See rule description for details"
                Effort     = "Review remediation guidance"
            }
        }
    }

    process {
        # Get rule info
        $ruleInfo = $null
        $targetRuleId = $RuleId

        if ($Finding) {
            $targetRuleId = $Finding.RuleId ?? $Finding.Id
            $ruleInfo = $Finding
        }

        if ($targetRuleId -and -not $ruleInfo) {
            $ruleInfo = Get-ADScoutRule -Id $targetRuleId -ErrorAction SilentlyContinue
        }

        if (-not $ruleInfo -and -not $targetRuleId) {
            Write-Warning "No finding or rule ID provided"
            return
        }

        # Get explanation
        $explanation = if ($riskExplanations.ContainsKey($targetRuleId)) {
            $riskExplanations[$targetRuleId][$Audience]
        } else {
            $genericExplanations[$Audience]
        }

        # Build output
        $ruleName = $ruleInfo.RuleName ?? $ruleInfo.Name ?? $ruleInfo.Title ?? $targetRuleId
        $ruleDescription = $ruleInfo.Description ?? "See documentation for details."
        $findingCount = $ruleInfo.FindingCount ?? $ruleInfo.Findings.Count ?? 0
        $score = $ruleInfo.Score ?? $ruleInfo.Weight ?? 0

        $severity = switch ($score) {
            { $_ -ge 50 } { 'Critical' }
            { $_ -ge 30 } { 'High' }
            { $_ -ge 15 } { 'Medium' }
            { $_ -ge 5 }  { 'Low' }
            default       { 'Info' }
        }

        switch ($Format) {
            'Text' {
                Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
                Write-Host "FINDING: $ruleName" -ForegroundColor White
                Write-Host ("=" * 70) -ForegroundColor Cyan

                Write-Host "`nSeverity: " -NoNewline
                $sevColor = switch ($severity) { 'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
                Write-Host $severity -ForegroundColor $sevColor
                Write-Host "Affected: $findingCount objects"

                Write-Host "`nWHAT THIS MEANS:" -ForegroundColor Yellow
                Write-Host $explanation.Summary

                Write-Host "`nWHY IT'S A RISK:" -ForegroundColor Yellow
                Write-Host $explanation.Risk

                Write-Host "`nATTACK SCENARIO:" -ForegroundColor Yellow
                Write-Host $explanation.Scenario

                Write-Host "`nBUSINESS IMPACT:" -ForegroundColor Yellow
                Write-Host $explanation.Impact

                Write-Host "`nREMEDIATION EFFORT:" -ForegroundColor Yellow
                Write-Host $explanation.Effort

                if ($ruleInfo.Remediation.Description) {
                    Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Green
                    Write-Host $ruleInfo.Remediation.Description
                }
            }

            'Markdown' {
                $md = @"
## $ruleName

**Severity:** $severity | **Affected Objects:** $findingCount

### Summary
$($explanation.Summary)

### Risk
$($explanation.Risk)

### Attack Scenario
> $($explanation.Scenario)

### Business Impact
$($explanation.Impact)

### Remediation
**Effort:** $($explanation.Effort)

$($ruleInfo.Remediation.Description ?? 'See detailed remediation guidance.')

---
"@
                Write-Output $md
            }

            'HTML' {
                $sevColor = switch ($severity) { 'Critical' { '#dc3545' } 'High' { '#fd7e14' } 'Medium' { '#ffc107' } default { '#6c757d' } }
                $html = @"
<div class="finding-card" style="border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 15px 0; border-left: 4px solid $sevColor;">
    <h3 style="margin-top: 0;">$ruleName</h3>
    <p><span style="background: $sevColor; color: white; padding: 2px 8px; border-radius: 4px;">$severity</span> <span style="color: #666;">$findingCount affected</span></p>

    <h4>What This Means</h4>
    <p>$($explanation.Summary)</p>

    <h4>Why It's a Risk</h4>
    <p>$($explanation.Risk)</p>

    <h4>Attack Scenario</h4>
    <blockquote style="background: #f8f9fa; padding: 10px; border-left: 3px solid #dee2e6;">$($explanation.Scenario)</blockquote>

    <h4>Business Impact</h4>
    <p>$($explanation.Impact)</p>

    <h4>Remediation</h4>
    <p><strong>Effort:</strong> $($explanation.Effort)</p>
</div>
"@
                Write-Output $html
            }
        }
    }
}

function Get-ADScoutFindingSummary {
    <#
    .SYNOPSIS
        Generates an executive summary of all critical findings.

    .PARAMETER Results
        Scan results from Invoke-ADScoutScan.

    .PARAMETER TopN
        Number of top findings to summarize.

    .EXAMPLE
        $results | Get-ADScoutFindingSummary -TopN 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [int]$TopN = 10
    )

    begin {
        $allResults = @()
    }

    process {
        $allResults += $Results
    }

    end {
        $topFindings = $allResults | Sort-Object Score -Descending | Select-Object -First $TopN

        Write-Host "`nEXECUTIVE SUMMARY: Top $TopN Security Findings" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan

        $totalScore = ($allResults | Measure-Object -Property Score -Sum).Sum
        $criticalCount = ($allResults | Where-Object { $_.Score -ge 50 }).Count

        Write-Host "`nOverall Risk Score: $totalScore" -ForegroundColor $(if ($totalScore -ge 100) { 'Red' } elseif ($totalScore -ge 50) { 'Yellow' } else { 'Green' })
        Write-Host "Critical Issues: $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { 'Red' } else { 'Green' })

        Write-Host "`nPriority Actions Required:" -ForegroundColor Yellow
        $i = 1
        foreach ($finding in $topFindings) {
            $severity = switch ($finding.Score) {
                { $_ -ge 50 } { 'CRITICAL' }
                { $_ -ge 30 } { 'HIGH' }
                { $_ -ge 15 } { 'MEDIUM' }
                default       { 'LOW' }
            }
            $color = switch ($severity) { 'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }

            Write-Host "`n$i. [$severity] $($finding.RuleName)" -ForegroundColor $color
            Write-Host "   Affected: $($finding.FindingCount) objects | Score: $($finding.Score) points" -ForegroundColor Gray
            $i++
        }
    }
}
