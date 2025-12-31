#Requires -Modules Pester
<#
.SYNOPSIS
    Main test file for AD-Scout module.

.DESCRIPTION
    Entry point for Pester tests. Imports the module and runs all tests.
#>

BeforeAll {
    # Import the module from source
    $modulePath = Join-Path $PSScriptRoot '../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force
}

Describe 'ADScout Module' {
    Context 'Module Import' {
        It 'Should import without errors' {
            { Import-Module (Join-Path $PSScriptRoot '../src/ADScout/ADScout.psd1') -Force } | Should -Not -Throw
        }

        It 'Should be loaded' {
            $module = Get-Module ADScout
            $module | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct version format' {
            $module = Get-Module ADScout
            $module.Version | Should -Match '^\d+\.\d+\.\d+$'
        }
    }

    Context 'Exported Functions' {
        BeforeAll {
            $expectedFunctions = @(
                'Invoke-ADScoutScan'
                'Get-ADScoutRule'
                'New-ADScoutRule'
                'Register-ADScoutRule'
                'Export-ADScoutReport'
                'Get-ADScoutRemediation'
                'Set-ADScoutConfig'
                'Get-ADScoutConfig'
                'Show-ADScoutDashboard'
            )
        }

        It 'Should export all expected functions' {
            $commands = Get-Command -Module ADScout
            foreach ($funcName in $expectedFunctions) {
                $commands.Name | Should -Contain $funcName
            }
        }

        It 'Should not export private functions' {
            $commands = Get-Command -Module ADScout
            $commands.Name | Should -Not -Contain 'Get-ADScoutUserData'
            $commands.Name | Should -Not -Contain 'Write-ADScoutLog'
        }

        It 'Should export exactly the expected number of functions' {
            $commands = Get-Command -Module ADScout -CommandType Function
            $commands.Count | Should -Be $expectedFunctions.Count
        }
    }

    Context 'Help Documentation' {
        BeforeAll {
            $commands = Get-Command -Module ADScout -CommandType Function
        }

        It 'All exported functions should have help' {
            foreach ($cmd in $commands) {
                $help = Get-Help $cmd.Name -ErrorAction SilentlyContinue
                $help | Should -Not -BeNullOrEmpty -Because "$($cmd.Name) should have help"
            }
        }

        It 'All exported functions should have synopsis' {
            foreach ($cmd in $commands) {
                $help = Get-Help $cmd.Name
                $help.Synopsis | Should -Not -BeNullOrEmpty -Because "$($cmd.Name) should have synopsis"
            }
        }

        It 'All exported functions should have examples' {
            foreach ($cmd in $commands) {
                $help = Get-Help $cmd.Name -Examples
                $help.Examples | Should -Not -BeNullOrEmpty -Because "$($cmd.Name) should have examples"
            }
        }
    }
}

Describe 'Get-ADScoutRule' {
    It 'Should return rules without errors' {
        { Get-ADScoutRule } | Should -Not -Throw
    }

    It 'Should return at least one rule' {
        $rules = Get-ADScoutRule
        $rules.Count | Should -BeGreaterThan 0
    }

    It 'Should return the S-PwdNeverExpires rule' {
        $rule = Get-ADScoutRule -Id 'S-PwdNeverExpires'
        $rule | Should -Not -BeNullOrEmpty
        $rule.Id | Should -Be 'S-PwdNeverExpires'
    }

    It 'Should filter by category' {
        $rules = Get-ADScoutRule -Category StaleObjects
        $rules | Should -Not -BeNullOrEmpty
        $rules | ForEach-Object {
            $_.Category | Should -Be 'StaleObjects'
        }
    }

    It 'Rules should have required properties' {
        $rules = Get-ADScoutRule
        foreach ($rule in $rules) {
            $rule.Id | Should -Not -BeNullOrEmpty
            $rule.Name | Should -Not -BeNullOrEmpty
            $rule.Category | Should -Not -BeNullOrEmpty
            $rule.ScriptBlock | Should -Not -BeNullOrEmpty
            $rule.Description | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-ADScoutConfig' {
    It 'Should return configuration without errors' {
        { Get-ADScoutConfig } | Should -Not -Throw
    }

    It 'Should return expected properties' {
        $config = Get-ADScoutConfig
        $config.ParallelThrottleLimit | Should -BeOfType [int]
        $config.DefaultReporter | Should -Not -BeNullOrEmpty
        $config.CacheTTL | Should -BeOfType [int]
    }

    It 'Should return specific setting by name' {
        $value = Get-ADScoutConfig -Name ParallelThrottleLimit
        $value | Should -BeOfType [int]
        $value | Should -BeGreaterThan 0
    }
}

Describe 'Set-ADScoutConfig' {
    It 'Should set configuration without errors' {
        { Set-ADScoutConfig -CacheTTL 600 } | Should -Not -Throw
    }

    It 'Should update configuration values' {
        Set-ADScoutConfig -CacheTTL 123
        $config = Get-ADScoutConfig
        $config.CacheTTL | Should -Be 123

        # Reset
        Set-ADScoutConfig -CacheTTL 300
    }
}
