function Get-ADScoutFingerprint {
    <#
    .SYNOPSIS
        Generates a deterministic fingerprint hash for an object.

    .DESCRIPTION
        Creates a SHA256-based fingerprint for objects, used for baseline
        comparison and delta detection. The fingerprint is deterministic -
        the same input always produces the same output.

    .PARAMETER InputObject
        The object to generate a fingerprint for.

    .PARAMETER Length
        The length of the returned hash string. Default is 16 characters.

    .EXAMPLE
        $finding | Get-ADScoutFingerprint

    .EXAMPLE
        Get-ADScoutFingerprint -InputObject $result -Length 32
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject]$InputObject,

        [Parameter()]
        [ValidateRange(8, 64)]
        [int]$Length = 16
    )

    process {
        try {
            # Convert to deterministic JSON representation
            $jsonInput = $InputObject | ConvertTo-Json -Compress -Depth 3
            $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonInput)

            # Compute SHA256 hash
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hashResult = $sha256.ComputeHash($hashBytes)

            # Return Base64-encoded hash truncated to specified length
            $base64Hash = [Convert]::ToBase64String($hashResult)
            return $base64Hash.Substring(0, [Math]::Min($Length, $base64Hash.Length))
        }
        catch {
            Write-Warning "Failed to generate fingerprint: $_"
            return $null
        }
        finally {
            if ($sha256) { $sha256.Dispose() }
        }
    }
}
