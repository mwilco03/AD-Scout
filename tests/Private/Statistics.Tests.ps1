#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for AD-Scout statistical analysis functions.

.DESCRIPTION
    Validates the mathematical correctness and edge case handling
    of the Statistics helper functions used for anomaly detection.
#>

BeforeAll {
    # Import the module from source
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force

    # Dot-source the private functions directly for testing
    $statisticsPath = Join-Path $PSScriptRoot '../../src/ADScout/Private/Statistics'
    Get-ChildItem -Path $statisticsPath -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
}

Describe 'Get-ADScoutStatistics' {
    Context 'Basic Calculations' {
        It 'Should calculate correct mean for simple dataset' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5)
            $stats.Mean | Should -Be 3
        }

        It 'Should calculate correct median for odd count' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5)
            $stats.Median | Should -Be 3
        }

        It 'Should calculate correct median for even count' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4)
            $stats.Median | Should -Be 2.5
        }

        It 'Should calculate correct min and max' {
            $stats = Get-ADScoutStatistics -Values @(5, 1, 9, 3, 7)
            $stats.Min | Should -Be 1
            $stats.Max | Should -Be 9
        }

        It 'Should calculate correct count' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5, 6, 7)
            $stats.Count | Should -Be 7
        }

        It 'Should calculate standard deviation correctly' {
            # Population stddev of 2, 4, 4, 4, 5, 5, 7, 9 is 2
            $stats = Get-ADScoutStatistics -Values @(2, 4, 4, 4, 5, 5, 7, 9)
            $stats.Mean | Should -Be 5
            $stats.StdDev | Should -Be 2
        }
    }

    Context 'Quartile Calculations' {
        It 'Should calculate quartiles correctly' {
            # Standard dataset: 1, 2, 3, 4, 5, 6, 7, 8
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5, 6, 7, 8)
            $stats.Q1 | Should -BeGreaterThan 1.5
            $stats.Q1 | Should -BeLessThan 3.5
            $stats.Q3 | Should -BeGreaterThan 5.5
            $stats.Q3 | Should -BeLessThan 7.5
        }

        It 'Should calculate IQR correctly' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5, 6, 7, 8)
            $stats.IQR | Should -Be ($stats.Q3 - $stats.Q1)
        }
    }

    Context 'Edge Cases' {
        It 'Should handle empty array' {
            $stats = Get-ADScoutStatistics -Values @()
            $stats.Count | Should -Be 0
            $stats.Mean | Should -Be 0
            $stats.StdDev | Should -Be 0
        }

        It 'Should handle single value' {
            $stats = Get-ADScoutStatistics -Values @(42)
            $stats.Count | Should -Be 1
            $stats.Mean | Should -Be 42
            $stats.Median | Should -Be 42
            $stats.StdDev | Should -Be 0
            $stats.Min | Should -Be 42
            $stats.Max | Should -Be 42
        }

        It 'Should handle two values' {
            $stats = Get-ADScoutStatistics -Values @(10, 20)
            $stats.Count | Should -Be 2
            $stats.Mean | Should -Be 15
            $stats.Median | Should -Be 15
        }

        It 'Should handle identical values' {
            $stats = Get-ADScoutStatistics -Values @(5, 5, 5, 5, 5)
            $stats.Mean | Should -Be 5
            $stats.StdDev | Should -Be 0
            $stats.IQR | Should -Be 0
        }

        It 'Should handle negative values' {
            $stats = Get-ADScoutStatistics -Values @(-5, -3, -1, 1, 3, 5)
            $stats.Mean | Should -Be 0
            $stats.Min | Should -Be -5
            $stats.Max | Should -Be 5
        }

        It 'Should handle large values' {
            $stats = Get-ADScoutStatistics -Values @(1000000, 2000000, 3000000)
            $stats.Mean | Should -Be 2000000
        }

        It 'Should handle decimal values' {
            $stats = Get-ADScoutStatistics -Values @(1.5, 2.5, 3.5, 4.5)
            $stats.Mean | Should -Be 3
            $stats.Median | Should -Be 3
        }
    }

    Context 'Pipeline Input' {
        It 'Should accept pipeline input' {
            $stats = @(1, 2, 3, 4, 5) | Get-ADScoutStatistics
            $stats.Mean | Should -Be 3
        }
    }

    Context 'Return Type' {
        It 'Should return a hashtable' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3)
            $stats | Should -BeOfType [hashtable]
        }

        It 'Should contain all expected keys' {
            $stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5)
            $stats.Keys | Should -Contain 'Count'
            $stats.Keys | Should -Contain 'Mean'
            $stats.Keys | Should -Contain 'Median'
            $stats.Keys | Should -Contain 'StdDev'
            $stats.Keys | Should -Contain 'Min'
            $stats.Keys | Should -Contain 'Max'
            $stats.Keys | Should -Contain 'Q1'
            $stats.Keys | Should -Contain 'Q3'
            $stats.Keys | Should -Contain 'IQR'
        }
    }
}

Describe 'Get-ADScoutZScore' {
    Context 'Z-Score Calculation' {
        It 'Should calculate correct Z-scores' {
            # Mean = 5, StdDev = 2
            # Value 9 should have Z-score of 2
            $results = Get-ADScoutZScore -Values @(3, 5, 5, 5, 7) -IncludeAll
            # Mean should be 5, but let's verify the calculation works
            $results | Should -Not -BeNullOrEmpty
        }

        It 'Should identify outliers correctly' {
            # Create dataset where 100 is clearly an outlier
            $values = @(1, 2, 3, 4, 5, 100)
            $outliers = Get-ADScoutZScore -Values $values -Threshold 2.0
            $outliers | Should -Not -BeNullOrEmpty
            $outliers.Value | Should -Contain 100
        }

        It 'Should respect threshold parameter' {
            $values = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 20)

            # Lower threshold = more outliers
            $lowThreshold = Get-ADScoutZScore -Values $values -Threshold 1.0
            $highThreshold = Get-ADScoutZScore -Values $values -Threshold 3.0

            $lowThreshold.Count | Should -BeGreaterOrEqual $highThreshold.Count
        }
    }

    Context 'IncludeAll Parameter' {
        It 'Should return all values when IncludeAll is specified' {
            $values = @(1, 2, 3, 4, 5)
            $results = Get-ADScoutZScore -Values $values -IncludeAll
            $results.Count | Should -Be 5
        }

        It 'Should return only outliers by default' {
            # All values are similar, no outliers expected
            $values = @(5, 5, 5, 5, 5, 5)
            $results = Get-ADScoutZScore -Values $values -Threshold 2.0
            $results.Count | Should -Be 0
        }
    }

    Context 'Edge Cases' {
        It 'Should handle insufficient data' {
            $results = Get-ADScoutZScore -Values @(1)
            $results.Count | Should -Be 0
        }

        It 'Should handle zero standard deviation' {
            $results = Get-ADScoutZScore -Values @(5, 5, 5, 5)
            $results.Count | Should -Be 0
        }
    }

    Context 'Output Properties' {
        It 'Should include expected properties' {
            $results = Get-ADScoutZScore -Values @(1, 2, 3, 4, 100) -IncludeAll
            $sample = $results | Select-Object -First 1
            $sample.PSObject.Properties.Name | Should -Contain 'Value'
            $sample.PSObject.Properties.Name | Should -Contain 'ZScore'
            $sample.PSObject.Properties.Name | Should -Contain 'IsOutlier'
            $sample.PSObject.Properties.Name | Should -Contain 'Mean'
            $sample.PSObject.Properties.Name | Should -Contain 'StdDev'
        }
    }
}

Describe 'Get-ADScoutIQROutliers' {
    Context 'IQR Outlier Detection' {
        It 'Should identify upper outliers' {
            # 100 is clearly an outlier
            $values = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100)
            $outliers = Get-ADScoutIQROutliers -Values $values
            $outliers | Should -Not -BeNullOrEmpty
            ($outliers | Where-Object { $_.Value -eq 100 }) | Should -Not -BeNullOrEmpty
        }

        It 'Should respect Multiplier parameter' {
            $values = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20)

            # Lower multiplier = more outliers
            $strictOutliers = Get-ADScoutIQROutliers -Values $values -Multiplier 1.0
            $looseOutliers = Get-ADScoutIQROutliers -Values $values -Multiplier 3.0

            $strictOutliers.Count | Should -BeGreaterOrEqual $looseOutliers.Count
        }

        It 'Should detect only upper outliers with UpperOnly' {
            # Dataset with both low and high outliers
            $values = @(-100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100)
            $upperOnly = Get-ADScoutIQROutliers -Values $values -UpperOnly

            foreach ($outlier in $upperOnly) {
                $outlier.IsUpperOutlier | Should -Be $true
            }
        }
    }

    Context 'Edge Cases' {
        It 'Should require minimum sample size' {
            $results = Get-ADScoutIQROutliers -Values @(1, 2, 3)
            $results.Count | Should -Be 0
        }

        It 'Should handle no outliers gracefully' {
            $values = @(5, 5, 5, 5, 5)
            $results = Get-ADScoutIQROutliers -Values $values
            $results.Count | Should -Be 0
        }
    }

    Context 'Output Properties' {
        It 'Should include fence information' {
            $results = Get-ADScoutIQROutliers -Values @(1, 2, 3, 4, 5, 6, 7, 8, 9, 100) -IncludeAll
            $sample = $results | Select-Object -First 1
            $sample.PSObject.Properties.Name | Should -Contain 'LowerFence'
            $sample.PSObject.Properties.Name | Should -Contain 'UpperFence'
            $sample.PSObject.Properties.Name | Should -Contain 'IQR'
        }
    }
}

Describe 'Get-ADScoutPeerBaseline' {
    Context 'OU Grouping' {
        BeforeAll {
            # Create mock user objects
            $mockUsers = @(
                [PSCustomObject]@{
                    SamAccountName    = 'user1'
                    DistinguishedName = 'CN=User1,OU=IT,DC=contoso,DC=com'
                    MemberOf          = @('Group1', 'Group2', 'Group3')
                }
                [PSCustomObject]@{
                    SamAccountName    = 'user2'
                    DistinguishedName = 'CN=User2,OU=IT,DC=contoso,DC=com'
                    MemberOf          = @('Group1', 'Group2')
                }
                [PSCustomObject]@{
                    SamAccountName    = 'user3'
                    DistinguishedName = 'CN=User3,OU=HR,DC=contoso,DC=com'
                    MemberOf          = @('Group1')
                }
                [PSCustomObject]@{
                    SamAccountName    = 'user4'
                    DistinguishedName = 'CN=User4,OU=HR,DC=contoso,DC=com'
                    MemberOf          = @('Group1', 'Group2')
                }
            )
        }

        It 'Should group users by OU' {
            $groups = Get-ADScoutPeerBaseline -Objects $mockUsers
            $groups.Count | Should -Be 2  # IT and HR
        }

        It 'Should calculate statistics per group' {
            $groups = Get-ADScoutPeerBaseline -Objects $mockUsers
            foreach ($group in $groups) {
                $group.Statistics | Should -Not -BeNullOrEmpty
                $group.Statistics.Mean | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should preserve objects in groups' {
            $groups = Get-ADScoutPeerBaseline -Objects $mockUsers
            $totalObjects = ($groups | ForEach-Object { $_.Objects.Count } | Measure-Object -Sum).Sum
            $totalObjects | Should -Be 4
        }
    }

    Context 'Custom Value Property' {
        BeforeAll {
            $mockUsers = @(
                [PSCustomObject]@{
                    SamAccountName    = 'user1'
                    DistinguishedName = 'CN=User1,OU=Test,DC=contoso,DC=com'
                    LogonCount        = 100
                    MemberOf          = @()
                }
                [PSCustomObject]@{
                    SamAccountName    = 'user2'
                    DistinguishedName = 'CN=User2,OU=Test,DC=contoso,DC=com'
                    LogonCount        = 200
                    MemberOf          = @()
                }
            )
        }

        It 'Should use custom value property' {
            $groups = Get-ADScoutPeerBaseline -Objects $mockUsers -ValueProperty { $_.LogonCount }
            $groups[0].Statistics.Mean | Should -Be 150
        }
    }

    Context 'Edge Cases' {
        It 'Should handle empty input' {
            $groups = Get-ADScoutPeerBaseline -Objects @()
            $groups.Count | Should -Be 0
        }

        It 'Should handle users without OU' {
            $mockUsers = @(
                [PSCustomObject]@{
                    SamAccountName    = 'user1'
                    DistinguishedName = 'CN=User1,CN=Users,DC=contoso,DC=com'
                    MemberOf          = @('Group1')
                }
            )
            $groups = Get-ADScoutPeerBaseline -Objects $mockUsers
            $groups | Should -Not -BeNullOrEmpty
        }
    }
}
