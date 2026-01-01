function Convert-SidToName {
    <#
    .SYNOPSIS
        Converts a SID to a readable name.

    .DESCRIPTION
        Translates a Security Identifier (SID) to its corresponding
        account name. Handles well-known SIDs and domain accounts.

    .PARAMETER Sid
        The SID to convert.

    .PARAMETER Domain
        The domain context for resolution.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Sid,

        [Parameter()]
        [string]$Domain
    )

    process {
        try {
            $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $account = $sidObject.Translate([System.Security.Principal.NTAccount])
            return $account.Value
        }
        catch {
            Write-Verbose "Failed to translate SID $Sid : $_"

            # Check well-known SIDs
            $wellKnownSids = @{
                'S-1-0-0'     = 'Nobody'
                'S-1-1-0'     = 'Everyone'
                'S-1-2-0'     = 'Local'
                'S-1-3-0'     = 'Creator Owner'
                'S-1-3-1'     = 'Creator Group'
                'S-1-5-1'     = 'Dialup'
                'S-1-5-2'     = 'Network'
                'S-1-5-3'     = 'Batch'
                'S-1-5-4'     = 'Interactive'
                'S-1-5-6'     = 'Service'
                'S-1-5-7'     = 'Anonymous'
                'S-1-5-9'     = 'Enterprise Domain Controllers'
                'S-1-5-10'    = 'Self'
                'S-1-5-11'    = 'Authenticated Users'
                'S-1-5-12'    = 'Restricted Code'
                'S-1-5-13'    = 'Terminal Server Users'
                'S-1-5-14'    = 'Remote Interactive Logon'
                'S-1-5-18'    = 'SYSTEM'
                'S-1-5-19'    = 'LOCAL SERVICE'
                'S-1-5-20'    = 'NETWORK SERVICE'
            }

            # Check for well-known domain SIDs (relative to domain)
            if ($Sid -match '^S-1-5-21-[\d-]+-(\d+)$') {
                $rid = $Matches[1]
                $domainRids = @{
                    '500' = 'Administrator'
                    '501' = 'Guest'
                    '502' = 'krbtgt'
                    '512' = 'Domain Admins'
                    '513' = 'Domain Users'
                    '514' = 'Domain Guests'
                    '515' = 'Domain Computers'
                    '516' = 'Domain Controllers'
                    '517' = 'Cert Publishers'
                    '518' = 'Schema Admins'
                    '519' = 'Enterprise Admins'
                    '520' = 'Group Policy Creator Owners'
                    '526' = 'Key Admins'
                    '527' = 'Enterprise Key Admins'
                }
                if ($domainRids.ContainsKey($rid)) {
                    return $domainRids[$rid]
                }
            }

            if ($wellKnownSids.ContainsKey($Sid)) {
                return $wellKnownSids[$Sid]
            }

            # Return the SID if we can't translate
            return $Sid
        }
    }
}
