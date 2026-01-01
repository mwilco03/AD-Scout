@{
    Id          = 'G-UnlinkedGPOs'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Unlinked Group Policy Objects'
    Description = 'Identifies GPOs that are not linked to any OU, site, or domain. Unlinked GPOs may contain stale configurations or represent cleanup opportunities.'
    Severity    = 'Low'
    Weight      = 5
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'Group Policy Best Practices'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy-best-practices' }
    )

    MITRE = @{
        Tactics    = @()
        Techniques = @()
    }

    CIS   = @('5.17')
    STIG  = @()
    ANSSI = @()
    NIST  = @('CM-2')

    Scoring = @{
        Type      = 'PerDiscovery'
        PerItem   = 1
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        foreach ($gpo in $Data) {
            if (-not $gpo.Links -or $gpo.Links.Count -eq 0) {
                $findings += [PSCustomObject]@{
                    GPOName       = $gpo.DisplayName
                    GPOId         = $gpo.Id
                    WhenCreated   = $gpo.WhenCreated
                    WhenChanged   = $gpo.WhenChanged
                    Owner         = $gpo.Owner
                    GpoStatus     = $gpo.GpoStatus
                    Description   = $gpo.Description
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Review unlinked GPOs and either link them to appropriate OUs, archive them, or delete if no longer needed.'
        Impact      = 'None - Unlinked GPOs do not apply'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# Unlinked GPOs detected
# Review each GPO and decide: link, archive, or delete

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName)
# ID: $($item.GPOId)
# Created: $($item.WhenCreated)
# Last Modified: $($item.WhenChanged)

# To backup before deletion:
# Backup-GPO -Guid '$($item.GPOId)' -Path 'C:\GPOBackups'

# To delete:
# Remove-GPO -Guid '$($item.GPOId)'

"@
            }
            return $commands
        }
    }
}
