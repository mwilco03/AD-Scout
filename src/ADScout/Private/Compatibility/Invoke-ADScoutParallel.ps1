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
        The scriptblock to execute for each item. Should accept $_ as the current item
        and optionally $args[0], $args[1], etc. for additional arguments.

    .PARAMETER InputObject
        The collection of items to process.

    .PARAMETER ThrottleLimit
        Maximum concurrent operations.

    .PARAMETER ArgumentList
        Additional arguments to pass to the scriptblock. For PS7+ parallel execution,
        these are passed as $using: variables in a hashtable.

    .PARAMETER ProgressActivity
        Optional activity name for progress reporting.

    .EXAMPLE
        $rules | Invoke-ADScoutParallel -ScriptBlock {
            param($rule, $data)
            & $rule.ScriptBlock -ADData $data
        } -ArgumentList $adData -ThrottleLimit 4
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
        [object[]]$ArgumentList,

        [Parameter()]
        [string]$ProgressActivity
    )

    begin {
        $items = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($item in $InputObject) {
            $items.Add($item)
        }
    }

    end {
        if ($items.Count -eq 0) {
            return
        }

        # For small item counts, sequential is often faster (avoid overhead)
        if ($items.Count -le 2) {
            Write-Verbose "Using sequential execution (only $($items.Count) items)"
            foreach ($item in $items) {
                try {
                    & $ScriptBlock $item @ArgumentList
                }
                catch {
                    Write-Warning "Sequential execution error: $_"
                }
            }
            return
        }

        # Try PowerShell 7+ parallel
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Verbose "Using ForEach-Object -Parallel (PS7+) with ThrottleLimit=$ThrottleLimit"

            # For PS7, we need to pass ArgumentList via $using: scope
            # Create a wrapper scriptblock that captures the arguments
            $argList = $ArgumentList
            $sb = $ScriptBlock

            $items | ForEach-Object -Parallel {
                $item = $_
                $arguments = $using:argList
                $scriptToRun = $using:sb

                try {
                    & $scriptToRun $item @arguments
                }
                catch {
                    Write-Warning "Parallel execution error for item: $_"
                }
            } -ThrottleLimit $ThrottleLimit
            return
        }

        # Try ThreadJob module
        if (Get-Module -ListAvailable ThreadJob -ErrorAction SilentlyContinue) {
            Write-Verbose "Using ThreadJob module with ThrottleLimit=$ThrottleLimit"
            Import-Module ThreadJob -ErrorAction SilentlyContinue

            $jobs = [System.Collections.Generic.List[object]]::new()

            foreach ($item in $items) {
                $job = Start-ThreadJob -ScriptBlock {
                    param($scriptText, $inputItem, $arguments)
                    $sb = [scriptblock]::Create($scriptText)
                    try {
                        & $sb $inputItem @arguments
                    }
                    catch {
                        Write-Warning "ThreadJob error: $_"
                    }
                } -ArgumentList $ScriptBlock.ToString(), $item, $ArgumentList -ThrottleLimit $ThrottleLimit
                $jobs.Add($job)
            }

            # Wait and collect results
            $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job -Force
            return
        }

        # Use runspace pools (PS 5.1 without ThreadJob)
        Write-Verbose "Using runspace pool with ThrottleLimit=$ThrottleLimit"

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $runspacePool.Open()

        $runspaces = [System.Collections.Generic.List[PSCustomObject]]::new()
        $scriptText = $ScriptBlock.ToString()

        foreach ($item in $items) {
            $powershell = [powershell]::Create()
            $powershell.RunspacePool = $runspacePool

            # Create a wrapper script that reconstructs the scriptblock
            $wrapperScript = {
                param($scriptText, $inputItem, $arguments)
                $sb = [scriptblock]::Create($scriptText)
                try {
                    & $sb $inputItem @arguments
                }
                catch {
                    Write-Warning "Runspace error: $_"
                }
            }

            [void]$powershell.AddScript($wrapperScript)
            [void]$powershell.AddParameter('scriptText', $scriptText)
            [void]$powershell.AddParameter('inputItem', $item)
            [void]$powershell.AddParameter('arguments', $ArgumentList)

            $runspaces.Add([PSCustomObject]@{
                PowerShell = $powershell
                Handle     = $powershell.BeginInvoke()
            })
        }

        # Wait for completion and collect results
        foreach ($runspace in $runspaces) {
            try {
                $runspace.PowerShell.EndInvoke($runspace.Handle)
            }
            catch {
                Write-Warning "Runspace collection error: $_"
            }
            finally {
                $runspace.PowerShell.Dispose()
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }
}
