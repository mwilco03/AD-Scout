#Requires -Modules Pester

<#
.SYNOPSIS
    Main Pester test entry point for AD-Scout module.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'ADScout' 'ADScout.psd1'
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force -ErrorAction Stop
    }
}

Describe 'ADScout Module' -Tag 'Unit', 'Module' {
    Context 'Module Loading' {
        It 'Should import without errors' {
            { Import-Module (Join-Path $PSScriptRoot '..' 'src' 'ADScout' 'ADScout.psd1') -Force } | Should -Not -Throw
        }

        It 'Should export expected functions' {
            $module = Get-Module ADScout
            $module | Should -Not -BeNullOrEmpty

            $expectedFunctions = @(
                'Invoke-ADScoutScan'
                'Get-ADScoutRule'
                'Export-ADScoutReport'
                'Show-ADScoutDashboard'
                'Export-ADScoutElasticsearch'
                'Export-ADScoutSplunk'
                'Export-ADScoutSentinel'
                'New-ADScoutEngagement'
                'New-ADScoutException'
            )

            foreach ($func in $expectedFunctions) {
                $module.ExportedFunctions.Keys | Should -Contain $func
            }
        }

        It 'Should have valid module manifest' {
            $manifestPath = Join-Path $PSScriptRoot '..' 'src' 'ADScout' 'ADScout.psd1'
            { Test-ModuleManifest -Path $manifestPath } | Should -Not -Throw
        }
    }
}

Describe 'Get-ADScoutRule' -Tag 'Unit', 'Rules' {
    It 'Should return rules' {
        $rules = Get-ADScoutRule
        $rules | Should -Not -BeNullOrEmpty
    }

    It 'Should filter by category' {
        $rules = Get-ADScoutRule -Category 'StaleObjects'
        $rules | ForEach-Object { $_.Category | Should -Be 'StaleObjects' }
    }
}

Describe 'Show-ADScoutDashboard' -Tag 'Unit', 'Dashboard' {
    It 'Should have Port parameter' {
        $cmd = Get-Command Show-ADScoutDashboard
        $cmd.Parameters.Keys | Should -Contain 'Port'
    }

    It 'Should have NoBrowser parameter' {
        $cmd = Get-Command Show-ADScoutDashboard
        $cmd.Parameters.Keys | Should -Contain 'NoBrowser'
    }
}

Describe 'SIEM Reporters' -Tag 'Unit', 'SIEM' {
    Context 'Elasticsearch Reporter' {
        It 'Should have Export-ADScoutElasticsearch function' {
            Get-Command Export-ADScoutElasticsearch | Should -Not -BeNullOrEmpty
        }

        It 'Should have required parameters' {
            $cmd = Get-Command Export-ADScoutElasticsearch
            $cmd.Parameters.Keys | Should -Contain 'ElasticsearchUrl'
            $cmd.Parameters.Keys | Should -Contain 'UseECS'
        }
    }

    Context 'Splunk Reporter' {
        It 'Should have Export-ADScoutSplunk function' {
            Get-Command Export-ADScoutSplunk | Should -Not -BeNullOrEmpty
        }

        It 'Should have required parameters' {
            $cmd = Get-Command Export-ADScoutSplunk
            $cmd.Parameters.Keys | Should -Contain 'HECUrl'
            $cmd.Parameters.Keys | Should -Contain 'Token'
        }
    }

    Context 'Sentinel Reporter' {
        It 'Should have Export-ADScoutSentinel function' {
            Get-Command Export-ADScoutSentinel | Should -Not -BeNullOrEmpty
        }

        It 'Should have required parameters' {
            $cmd = Get-Command Export-ADScoutSentinel
            $cmd.Parameters.Keys | Should -Contain 'WorkspaceId'
            $cmd.Parameters.Keys | Should -Contain 'SharedKey'
        }

        It 'Should generate KQL for analytics rule' {
            $kql = New-ADScoutSentinelAnalyticsRule -OutputKQL
            $kql | Should -Not -BeNullOrEmpty
            $kql | Should -Match 'ADScoutFindings_CL'
        }
    }
}

Describe 'Engagement Management' -Tag 'Unit', 'Engagement' {
    BeforeAll {
        $testPath = Join-Path $TestDrive 'engagements'
    }

    It 'Should create new engagement' {
        $engagement = New-ADScoutEngagement -Name 'Test Engagement' -StoragePath $testPath
        $engagement | Should -Not -BeNullOrEmpty
        $engagement.Name | Should -Be 'Test Engagement'
    }
}

Describe 'Exception Management' -Tag 'Unit', 'Exception' {
    BeforeAll {
        $testPath = Join-Path $TestDrive 'exceptions'
    }

    It 'Should create rule exception' {
        $exception = New-ADScoutException -RuleId 'S-PwdNeverExpires' -Justification 'Test exception' -StoragePath $testPath
        $exception | Should -Not -BeNullOrEmpty
        $exception.RuleId | Should -Be 'S-PwdNeverExpires'
    }

    It 'Should create category exception' {
        $exception = New-ADScoutException -Category 'DLLRequired' -Justification 'No DLLs' -StoragePath $testPath
        $exception.Category | Should -Be 'DLLRequired'
    }
}

AfterAll {
    Remove-Module ADScout -Force -ErrorAction SilentlyContinue
}
