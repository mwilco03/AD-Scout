#Requires -Modules Pester

Describe 'Engagement Management Functions' -Tag 'Unit', 'Engagement' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' '..' 'src' 'ADScout' 'ADScout.psd1'
        Import-Module $modulePath -Force
        $testStoragePath = Join-Path $TestDrive 'engagements'
    }

    AfterAll {
        Remove-Module ADScout -Force -ErrorAction SilentlyContinue
    }

    Describe 'New-ADScoutEngagement' {
        It 'Creates engagement with required parameters' {
            $engagement = New-ADScoutEngagement -Name 'Test Engagement' -StoragePath $testStoragePath
            $engagement | Should -Not -BeNullOrEmpty
            $engagement.Name | Should -Be 'Test Engagement'
            $engagement.Status | Should -Be 'Active'
        }

        It 'Creates engagement with all parameters' {
            $engagement = New-ADScoutEngagement `
                -Name 'Full Test' `
                -Description 'Test description' `
                -Client 'Test Client' `
                -Domain 'contoso.com' `
                -Tags @('annual', 'security') `
                -StoragePath $testStoragePath

            $engagement.Description | Should -Be 'Test description'
            $engagement.Client | Should -Be 'Test Client'
            $engagement.Domain | Should -Contain 'contoso.com'
            $engagement.Tags | Should -Contain 'annual'
        }

        It 'Generates unique ID' {
            $eng1 = New-ADScoutEngagement -Name 'Unique1' -StoragePath $testStoragePath
            $eng2 = New-ADScoutEngagement -Name 'Unique2' -StoragePath $testStoragePath
            $eng1.Id | Should -Not -Be $eng2.Id
        }

        It 'Creates storage directory structure' {
            $engagement = New-ADScoutEngagement -Name 'Structure Test' -StoragePath $testStoragePath

            Test-Path $engagement.StoragePath | Should -Be $true
            Test-Path (Join-Path $engagement.StoragePath 'scans') | Should -Be $true
            Test-Path (Join-Path $engagement.StoragePath 'baselines') | Should -Be $true
            Test-Path (Join-Path $engagement.StoragePath 'exceptions') | Should -Be $true
        }

        It 'Saves metadata to JSON file' {
            $engagement = New-ADScoutEngagement -Name 'Metadata Test' -StoragePath $testStoragePath
            $metadataPath = Join-Path $engagement.StoragePath 'engagement.json'

            Test-Path $metadataPath | Should -Be $true
            $saved = Get-Content $metadataPath | ConvertFrom-Json
            $saved.Name | Should -Be 'Metadata Test'
        }
    }

    Describe 'Get-ADScoutEngagement' {
        BeforeAll {
            $eng1 = New-ADScoutEngagement -Name 'Get Test 1' -StoragePath $testStoragePath -Tags 'test'
            $eng2 = New-ADScoutEngagement -Name 'Get Test 2' -StoragePath $testStoragePath -Tags 'production'
            $script:testEngagementId = $eng1.Id
        }

        It 'Returns all engagements when no filter specified' {
            $engagements = Get-ADScoutEngagement -StoragePath $testStoragePath
            $engagements.Count | Should -BeGreaterOrEqual 2
        }

        It 'Filters by ID' {
            $engagement = Get-ADScoutEngagement -Id $script:testEngagementId -StoragePath $testStoragePath
            $engagement | Should -Not -BeNullOrEmpty
            $engagement.Id | Should -Be $script:testEngagementId
        }

        It 'Filters by name with wildcards' {
            $engagements = Get-ADScoutEngagement -Name 'Get Test*' -StoragePath $testStoragePath
            $engagements.Count | Should -Be 2
        }

        It 'Returns empty array when engagement not found' {
            $engagement = Get-ADScoutEngagement -Id 'nonexistent' -StoragePath $testStoragePath
            $engagement | Should -BeNullOrEmpty
        }

        It 'Excludes archived by default' {
            $archived = New-ADScoutEngagement -Name 'Archived Test' -StoragePath $testStoragePath
            Set-ADScoutEngagement -Id $archived.Id -Status 'Archived'

            $engagements = Get-ADScoutEngagement -StoragePath $testStoragePath
            $engagements.Id | Should -Not -Contain $archived.Id
        }

        It 'Includes archived when specified' {
            $archived = New-ADScoutEngagement -Name 'Include Archived' -StoragePath $testStoragePath
            Set-ADScoutEngagement -Id $archived.Id -Status 'Archived'

            $engagements = Get-ADScoutEngagement -StoragePath $testStoragePath -IncludeArchived
            $engagements.Id | Should -Contain $archived.Id
        }
    }

    Describe 'Set-ADScoutEngagement' {
        BeforeEach {
            $script:engagement = New-ADScoutEngagement -Name 'Set Test' -StoragePath $testStoragePath
        }

        It 'Updates name' {
            $updated = Set-ADScoutEngagement -Id $script:engagement.Id -Name 'Updated Name'
            $updated.Name | Should -Be 'Updated Name'
        }

        It 'Updates status' {
            $updated = Set-ADScoutEngagement -Id $script:engagement.Id -Status 'Completed'
            $updated.Status | Should -Be 'Completed'
        }

        It 'Updates description' {
            $updated = Set-ADScoutEngagement -Id $script:engagement.Id -Description 'New description'
            $updated.Description | Should -Be 'New description'
        }

        It 'Updates tags' {
            $updated = Set-ADScoutEngagement -Id $script:engagement.Id -Tags @('new', 'tags')
            $updated.Tags | Should -Contain 'new'
            $updated.Tags | Should -Contain 'tags'
        }

        It 'Adds modification metadata' {
            $updated = Set-ADScoutEngagement -Id $script:engagement.Id -Status 'Completed'
            $updated.ModifiedAt | Should -Not -BeNullOrEmpty
            $updated.ModifiedBy | Should -Not -BeNullOrEmpty
        }

        It 'Returns error for nonexistent engagement' {
            { Set-ADScoutEngagement -Id 'nonexistent' -Status 'Active' -ErrorAction Stop } | Should -Throw
        }
    }

    Describe 'Remove-ADScoutEngagement' {
        It 'Removes engagement with Force' {
            $engagement = New-ADScoutEngagement -Name 'Remove Test' -StoragePath $testStoragePath
            Remove-ADScoutEngagement -Id $engagement.Id -Force

            Get-ADScoutEngagement -Id $engagement.Id -StoragePath $testStoragePath | Should -BeNullOrEmpty
        }

        It 'Archives instead of deleting when -Archive specified' {
            $engagement = New-ADScoutEngagement -Name 'Archive Test' -StoragePath $testStoragePath
            Remove-ADScoutEngagement -Id $engagement.Id -Archive

            $archived = Get-ADScoutEngagement -Id $engagement.Id -IncludeArchived -StoragePath $testStoragePath
            $archived.Status | Should -Be 'Archived'
        }
    }

    Describe 'Get-ADScoutEngagementScans' {
        BeforeAll {
            $script:scanEngagement = New-ADScoutEngagement -Name 'Scan History Test' -StoragePath $testStoragePath

            # Create some mock scan files
            $scansPath = Join-Path $script:scanEngagement.StoragePath 'scans'
            @{
                ScanId = '20240101-120000'
                ExecutedAt = (Get-Date).AddDays(-2)
                ResultCount = 10
                TotalScore = 50
            } | ConvertTo-Json | Out-File (Join-Path $scansPath '20240101-120000.json')

            @{
                ScanId = '20240102-120000'
                ExecutedAt = (Get-Date).AddDays(-1)
                ResultCount = 8
                TotalScore = 40
            } | ConvertTo-Json | Out-File (Join-Path $scansPath '20240102-120000.json')
        }

        It 'Returns all scans for engagement' {
            $scans = Get-ADScoutEngagementScans -EngagementId $script:scanEngagement.Id
            $scans.Count | Should -BeGreaterOrEqual 2
        }

        It 'Limits results with -Last parameter' {
            $scans = Get-ADScoutEngagementScans -EngagementId $script:scanEngagement.Id -Last 1
            $scans.Count | Should -Be 1
        }

        It 'Returns most recent scan first' {
            $scans = Get-ADScoutEngagementScans -EngagementId $script:scanEngagement.Id
            $scans[0].ScanId | Should -Be '20240102-120000'
        }
    }
}
