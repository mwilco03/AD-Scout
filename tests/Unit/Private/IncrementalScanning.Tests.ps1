#Requires -Modules Pester

Describe 'Incremental Scanning Functions' -Tag 'Unit', 'Incremental' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' '..' 'src' 'ADScout' 'ADScout.psd1'
        Import-Module $modulePath -Force
        $testSessionPath = Join-Path $TestDrive 'test-session'
        New-Item -Path $testSessionPath -ItemType Directory -Force | Out-Null
    }

    AfterAll {
        Remove-Module ADScout -Force -ErrorAction SilentlyContinue
    }

    Describe 'Save-ADScoutScanWatermark' {
        It 'Saves watermark to session path' {
            Save-ADScoutScanWatermark `
                -SessionPath $testSessionPath `
                -Domain 'test.local' `
                -ScanTime (Get-Date) `
                -HighestUSN 12345678 `
                -ObjectCount 1000 `
                -ScanType 'Full'

            $watermarkFile = Join-Path $testSessionPath 'watermark.json'
            Test-Path $watermarkFile | Should -Be $true
        }

        It 'Stores correct values in watermark' {
            $scanTime = Get-Date
            Save-ADScoutScanWatermark `
                -SessionPath $testSessionPath `
                -Domain 'contoso.com' `
                -ScanTime $scanTime `
                -HighestUSN 98765432 `
                -ObjectCount 5000 `
                -ScanType 'Incremental'

            $watermarkFile = Join-Path $testSessionPath 'watermark.json'
            $watermark = Get-Content $watermarkFile -Raw | ConvertFrom-Json

            $watermark.Domain | Should -Be 'contoso.com'
            $watermark.HighestUSN | Should -Be 98765432
            $watermark.ObjectCount | Should -Be 5000
            $watermark.ScanType | Should -Be 'Incremental'
        }
    }

    Describe 'Get-ADScoutScanWatermark' {
        BeforeAll {
            # Create a test watermark
            $watermark = @{
                Domain = 'test.local'
                ScanTime = (Get-Date).ToString('o')
                HighestUSN = 11111111
                ObjectCount = 500
                ScanType = 'Full'
                Version = '1.0'
            }
            $watermark | ConvertTo-Json | Out-File -FilePath (Join-Path $testSessionPath 'watermark.json') -Encoding UTF8
        }

        It 'Retrieves watermark from session path' {
            $result = Get-ADScoutScanWatermark -SessionPath $testSessionPath
            $result | Should -Not -BeNullOrEmpty
            $result.Domain | Should -Be 'test.local'
            $result.HighestUSN | Should -Be 11111111
        }

        It 'Returns null when no watermark exists' {
            $emptyPath = Join-Path $TestDrive 'empty-session'
            New-Item -Path $emptyPath -ItemType Directory -Force | Out-Null

            $result = Get-ADScoutScanWatermark -SessionPath $emptyPath
            $result | Should -BeNullOrEmpty
        }
    }

    Describe 'Test-ADScoutIncrementalAvailable' {
        BeforeAll {
            # Create a recent watermark
            $recentPath = Join-Path $TestDrive 'recent-session'
            New-Item -Path $recentPath -ItemType Directory -Force | Out-Null

            $recentWatermark = @{
                Domain = 'test.local'
                ScanTime = (Get-Date).AddHours(-2).ToString('o')
                HighestUSN = 22222222
                ObjectCount = 1000
                ScanType = 'Full'
                Version = '1.0'
            }
            $recentWatermark | ConvertTo-Json | Out-File -FilePath (Join-Path $recentPath 'watermark.json') -Encoding UTF8

            # Create an old watermark
            $oldPath = Join-Path $TestDrive 'old-session'
            New-Item -Path $oldPath -ItemType Directory -Force | Out-Null

            $oldWatermark = @{
                Domain = 'test.local'
                ScanTime = (Get-Date).AddDays(-10).ToString('o')
                HighestUSN = 11111111
                ObjectCount = 800
                ScanType = 'Full'
                Version = '1.0'
            }
            $oldWatermark | ConvertTo-Json | Out-File -FilePath (Join-Path $oldPath 'watermark.json') -Encoding UTF8
        }

        It 'Returns available for recent watermark' {
            $result = Test-ADScoutIncrementalAvailable -SessionPath $recentPath
            $result.Available | Should -Be $true
        }

        It 'Returns not available for old watermark' {
            $result = Test-ADScoutIncrementalAvailable -SessionPath $oldPath
            $result.Available | Should -Be $false
            $result.Reason | Should -Match 'days old'
        }

        It 'Returns not available when no watermark exists' {
            $emptyPath = Join-Path $TestDrive 'no-watermark'
            New-Item -Path $emptyPath -ItemType Directory -Force | Out-Null

            $result = Test-ADScoutIncrementalAvailable -SessionPath $emptyPath
            $result.Available | Should -Be $false
            $result.Reason | Should -Match 'No previous scan'
        }
    }

    Describe 'Merge-ADScoutIncrementalResults' {
        BeforeAll {
            $script:baselineResults = @(
                [PSCustomObject]@{
                    RuleId = 'TEST-001'
                    RuleName = 'Test Rule 1'
                    Category = 'Test'
                    Description = 'Test description'
                    FindingCount = 5
                    Score = 10
                    MaxScore = 20
                    Findings = @(
                        @{ DistinguishedName = 'CN=User1,DC=test,DC=local' }
                        @{ DistinguishedName = 'CN=User2,DC=test,DC=local' }
                        @{ DistinguishedName = 'CN=User3,DC=test,DC=local' }
                        @{ DistinguishedName = 'CN=User4,DC=test,DC=local' }
                        @{ DistinguishedName = 'CN=User5,DC=test,DC=local' }
                    )
                    MITRE = 'T1078'
                    ExecutedAt = (Get-Date).AddDays(-1)
                }
                [PSCustomObject]@{
                    RuleId = 'TEST-002'
                    RuleName = 'Test Rule 2'
                    Category = 'Test'
                    Description = 'Another test'
                    FindingCount = 2
                    Score = 4
                    MaxScore = 10
                    Findings = @(
                        @{ DistinguishedName = 'CN=Comp1,DC=test,DC=local' }
                        @{ DistinguishedName = 'CN=Comp2,DC=test,DC=local' }
                    )
                    MITRE = 'T1098'
                    ExecutedAt = (Get-Date).AddDays(-1)
                }
            )

            $script:incrementalResults = @(
                [PSCustomObject]@{
                    RuleId = 'TEST-001'
                    RuleName = 'Test Rule 1'
                    Category = 'Test'
                    Description = 'Test description'
                    FindingCount = 1
                    Score = 2
                    MaxScore = 20
                    Findings = @(
                        @{ DistinguishedName = 'CN=User1,DC=test,DC=local' }  # Still has issue
                    )
                    MITRE = 'T1078'
                    ExecutedAt = Get-Date
                }
            )

            $script:changedDNs = @('CN=User1,DC=test,DC=local', 'CN=User2,DC=test,DC=local')
        }

        It 'Merges results preserving unchanged findings' {
            $merged = Merge-ADScoutIncrementalResults `
                -BaselineResults $script:baselineResults `
                -IncrementalResults $script:incrementalResults `
                -ChangedObjectDNs $script:changedDNs

            $merged | Should -Not -BeNullOrEmpty
            $merged.Count | Should -BeGreaterOrEqual 1
        }

        It 'Updates findings for changed objects' {
            $merged = Merge-ADScoutIncrementalResults `
                -BaselineResults $script:baselineResults `
                -IncrementalResults $script:incrementalResults `
                -ChangedObjectDNs $script:changedDNs

            $rule1 = $merged | Where-Object { $_.RuleId -eq 'TEST-001' }
            $rule1 | Should -Not -BeNullOrEmpty
            # Score should reflect incremental results
            $rule1.Score | Should -Be 2
        }
    }

    Describe 'Get-ADScoutIncrementalSummary' {
        BeforeAll {
            $script:baseline = @(
                [PSCustomObject]@{ RuleId = 'R1'; Score = 10; FindingCount = 5 }
                [PSCustomObject]@{ RuleId = 'R2'; Score = 5; FindingCount = 2 }
            )

            $script:current = @(
                [PSCustomObject]@{ RuleId = 'R1'; Score = 8; FindingCount = 4 }  # Improved
                [PSCustomObject]@{ RuleId = 'R3'; Score = 6; FindingCount = 3 }  # New
            )

            $script:watermark = [PSCustomObject]@{
                ScanTime = (Get-Date).AddDays(-1).ToString('o')
                HighestUSN = 12345678
            }
        }

        It 'Calculates score change correctly' {
            $summary = Get-ADScoutIncrementalSummary `
                -BaselineResults $script:baseline `
                -CurrentResults $script:current `
                -Watermark $script:watermark

            $summary.BaselineTotalScore | Should -Be 15
            $summary.CurrentTotalScore | Should -Be 14
            $summary.ScoreChange | Should -Be -1
        }

        It 'Identifies new findings' {
            $summary = Get-ADScoutIncrementalSummary `
                -BaselineResults $script:baseline `
                -CurrentResults $script:current `
                -Watermark $script:watermark

            $summary.NewFindingCount | Should -Be 1
            $summary.NewFindings[0].RuleId | Should -Be 'R3'
        }

        It 'Identifies resolved findings' {
            $summary = Get-ADScoutIncrementalSummary `
                -BaselineResults $script:baseline `
                -CurrentResults $script:current `
                -Watermark $script:watermark

            $summary.ResolvedFindingCount | Should -Be 1
            $summary.ResolvedFindings[0].RuleId | Should -Be 'R2'
        }
    }

    Describe 'Invoke-ADScoutScan Incremental Parameters' {
        It 'Has Incremental parameter' {
            $cmd = Get-Command Invoke-ADScoutScan
            $cmd.Parameters.Keys | Should -Contain 'Incremental'
        }

        It 'Has Differential alias for Incremental' {
            $cmd = Get-Command Invoke-ADScoutScan
            $param = $cmd.Parameters['Incremental']
            $param.Aliases | Should -Contain 'Differential'
        }

        It 'Has BaselinePath parameter' {
            $cmd = Get-Command Invoke-ADScoutScan
            $cmd.Parameters.Keys | Should -Contain 'BaselinePath'
        }

        It 'Has EngagementId parameter' {
            $cmd = Get-Command Invoke-ADScoutScan
            $cmd.Parameters.Keys | Should -Contain 'EngagementId'
        }
    }
}
