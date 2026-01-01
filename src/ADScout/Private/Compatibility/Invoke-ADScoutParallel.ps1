function Invoke-ADScoutParallel {
    <#
    .SYNOPSIS
        Executes scriptblocks in parallel using the best available method.

    .DESCRIPTION
        Provides cross-version parallel execution with tiered fallback:
        1. PowerShell 7+ ForEach-Object -Parallel
        2. ThreadJob module
        3. Runspace pools
        4. Sequential execution (fallback)

    .PARAMETER ScriptBlock
        The scriptblock to execute for each item.

    .PARAMETER InputObject
        The collection of items to process.

    .PARAMETER ThrottleLimit
        Maximum concurrent operations.

    .PARAMETER ArgumentList
        Additional arguments to pass to the scriptblock.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,

        [Parameter()]
        [int]$ThrottleLimit = [Environment]::ProcessorCount,

        [Parameter()]
        [object[]]$ArgumentList
    )

    begin {
        $items = @()
    }

    process {
        $items += $InputObject
    }

    end {
        if (-not $items) {
            return
        }

        # Try PowerShell 7+ parallel
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Verbose "Using ForEach-Object -Parallel (PS7+)"

            $items | ForEach-Object -Parallel $ScriptBlock -ThrottleLimit $ThrottleLimit
            return
        }

        # Try ThreadJob module
        if (Get-Module -ListAvailable ThreadJob -ErrorAction SilentlyContinue) {
            Write-Verbose "Using ThreadJob module"

            $jobs = $items | ForEach-Object {
                $item = $_
                Start-ThreadJob -ScriptBlock {
                    param($sb, $inputItem, $args)
                    & ([scriptblock]::Create($sb)) -InputObject $inputItem @args
                } -ArgumentList $ScriptBlock.ToString(), $item, $ArgumentList -ThrottleLimit $ThrottleLimit
            }

            $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            return
        }

        # Use runspace pools
        Write-Verbose "Using runspace pool"

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $runspacePool.Open()

        $runspaces = @()

        foreach ($item in $items) {
            $powershell = [powershell]::Create()
            $powershell.RunspacePool = $runspacePool

            [void]$powershell.AddScript($ScriptBlock)
            [void]$powershell.AddParameter('_', $item)

            if ($ArgumentList) {
                foreach ($arg in $ArgumentList) {
                    [void]$powershell.AddArgument($arg)
                }
            }

            $runspaces += [PSCustomObject]@{
                PowerShell = $powershell
                Handle     = $powershell.BeginInvoke()
            }
        }

        # Wait for completion and collect results
        foreach ($runspace in $runspaces) {
            try {
                $runspace.PowerShell.EndInvoke($runspace.Handle)
            }
            catch {
                Write-Warning "Runspace error: $_"
            }
            finally {
                $runspace.PowerShell.Dispose()
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }
}
