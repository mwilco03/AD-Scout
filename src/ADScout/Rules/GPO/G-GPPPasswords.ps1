@{
    Id          = 'G-GPPPasswords'
    Version     = '1.0.0'
    Category    = 'GPO'
    Title       = 'Group Policy Preferences Passwords'
    Description = 'Detects Group Policy Preferences containing encrypted passwords. The encryption key is publicly known (MS14-025), making these passwords trivially recoverable.'
    Severity    = 'Critical'
    Weight      = 50
    DataSource  = 'GPOs'

    References  = @(
        @{ Title = 'MS14-025: Vulnerability in Group Policy Preferences'; Url = 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025' }
        @{ Title = 'Finding Passwords in SYSVOL'; Url = 'https://adsecurity.org/?p=2288' }
    )

    MITRE = @{
        Tactics    = @('TA0006')  # Credential Access
        Techniques = @('T1552.006')  # Unsecured Credentials: Group Policy Preferences
    }

    CIS   = @('5.16')
    STIG  = @('V-36448')
    ANSSI = @('vuln1_gpp_passwords')
    NIST  = @('IA-5(1)')

    Scoring = @{
        Type = 'TriggerOnPresence'
    }

    Detect = {
        param($Data, $Domain)

        $findings = @()

        # Files that may contain GPP passwords
        $gppFiles = @(
            'Groups.xml'
            'Services.xml'
            'Scheduledtasks.xml'
            'DataSources.xml'
            'Printers.xml'
            'Drives.xml'
        )

        foreach ($gpo in $Data) {
            $gppFindings = @()

            foreach ($file in $gpo.GPPFiles) {
                if ($file.Name -in $gppFiles -and $file.Content -match 'cpassword="[^"]+"') {
                    # Extract cpassword value
                    if ($file.Content -match 'cpassword="([^"]+)"') {
                        $cpassword = $matches[1]
                        if ($cpassword -and $cpassword.Length -gt 0) {
                            $gppFindings += [PSCustomObject]@{
                                FileName   = $file.Name
                                FilePath   = $file.Path
                                HasPassword = $true
                            }
                        }
                    }
                }
            }

            if ($gppFindings.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    GPOName        = $gpo.DisplayName
                    GPOId          = $gpo.Id
                    GPPFiles       = $gppFindings
                    FileCount      = $gppFindings.Count
                    LinksTo        = ($gpo.Links -join ', ')
                    WhenChanged    = $gpo.WhenChanged
                }
            }
        }

        return $findings
    }

    Remediation = @{
        Description = 'Remove all Group Policy Preferences containing passwords immediately. Use LAPS, gMSA, or other secure credential management solutions instead.'
        Impact      = 'High - Services/accounts using these credentials will need reconfiguration'
        Script      = {
            param($Finding, $Domain)

            $commands = @"
# CRITICAL: GPP passwords detected
# These passwords can be decrypted by ANYONE with access to SYSVOL
# Remove immediately!

# To find and remove GPP passwords:

"@
            foreach ($item in $Finding.Findings) {
                $commands += @"

# GPO: $($item.GPOName)
# Files with passwords: $($item.FileCount)
$(foreach ($file in $item.GPPFiles) { "# - $($file.FilePath)`n" })

# Delete the GPP settings via GPMC or remove the files directly:
# Remove the cpassword attribute or delete the preferences

# After removal, change ALL passwords that were in GPP!

"@
            }

            $commands += @"

# Scan SYSVOL for any remaining cpassword values:
# findstr /S /I cpassword \\\\$env:USERDNSDOMAIN\\SYSVOL\\$env:USERDNSDOMAIN\\Policies\\*.xml

# Alternative: Use Microsoft's KB2962486 detection script
"@
            return $commands
        }
    }
}
