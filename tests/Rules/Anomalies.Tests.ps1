#Requires -Modules Pester
<#
.SYNOPSIS
    Tests for the Anomaly category rules.

.DESCRIPTION
    Validates anomaly detection rules including statistical analysis,
    edge case handling, and correct identification of outliers.
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../../src/ADScout/ADScout.psd1'
    Import-Module $modulePath -Force

    # Dot-source the private Statistics functions for testing
    $statisticsPath = Join-Path $PSScriptRoot '../../src/ADScout/Private/Statistics'
    Get-ChildItem -Path $statisticsPath -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
}

Describe 'A-ExcessiveGroupMembership Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'A-ExcessiveGroupMembership'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should have correct Id' {
            $rule.Id | Should -Be 'A-ExcessiveGroupMembership'
        }

        It 'Should be in Anomalies category' {
            $rule.Category | Should -Be 'Anomalies'
        }

        It 'Should have version 1.1.0 with peer comparison' {
            $rule.Version | Should -Be '1.1.0'
        }

        It 'Should have MITRE ATT&CK mappings' {
            $rule.MITRE | Should -Contain 'T1078.002'
            $rule.MITRE | Should -Contain 'T1098'
        }
    }

    Context 'Rule Execution with Clear Outlier' {
        BeforeAll {
            # Create dataset with one clear outlier (user1 with 50 groups, others with 2-5)
            $mockADData = @{
                Users = @(
                    # Outlier in IT OU
                    [PSCustomObject]@{
                        SamAccountName    = 'outlier_user'
                        DistinguishedName = 'CN=OutlierUser,OU=IT,DC=test,DC=local'
                        DisplayName       = 'Outlier User'
                        Enabled           = $true
                        MemberOf          = 1..50 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                    }
                    # Normal IT users (10 of them for peer comparison)
                    1..10 | ForEach-Object {
                        [PSCustomObject]@{
                            SamAccountName    = "it_user$_"
                            DistinguishedName = "CN=ITUser$_,OU=IT,DC=test,DC=local"
                            DisplayName       = "IT User $_"
                            Enabled           = $true
                            MemberOf          = 1..(3 + ($_ % 3)) | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                        }
                    }
                    # HR users (different OU)
                    1..5 | ForEach-Object {
                        [PSCustomObject]@{
                            SamAccountName    = "hr_user$_"
                            DistinguishedName = "CN=HRUser$_,OU=HR,DC=test,DC=local"
                            DisplayName       = "HR User $_"
                            Enabled           = $true
                            MemberOf          = 1..2 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                        }
                    }
                )
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find the outlier user' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'outlier_user'
        }

        It 'Should include peer comparison mode' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $outlierFinding = $findings | Where-Object { $_.SamAccountName -eq 'outlier_user' }
            $outlierFinding.ComparisonMode | Should -BeIn @('Peer', 'Global')
        }

        It 'Should include Z-score in findings' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $outlierFinding = $findings | Where-Object { $_.SamAccountName -eq 'outlier_user' }
            $outlierFinding.ZScore | Should -BeGreaterThan 2.0
        }
    }

    Context 'Edge Cases' {
        It 'Should handle insufficient users gracefully' {
            $mockADData = @{
                Users = @(
                    [PSCustomObject]@{
                        SamAccountName    = 'user1'
                        DistinguishedName = 'CN=User1,OU=Test,DC=test,DC=local'
                        Enabled           = $true
                        MemberOf          = @('Group1')
                    }
                )
            }
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.Count | Should -Be 0
        }

        It 'Should not flag when no variation exists' {
            # All users have same number of groups
            $mockADData = @{
                Users = 1..15 | ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName    = "user$_"
                        DistinguishedName = "CN=User$_,OU=Test,DC=test,DC=local"
                        Enabled           = $true
                        MemberOf          = @('Group1', 'Group2', 'Group3')
                    }
                }
            }
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.Count | Should -Be 0
        }

        It 'Should skip disabled users' {
            $mockADData = @{
                Users = @(
                    # Disabled user with many groups - should not be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'disabled_user'
                        DistinguishedName = 'CN=DisabledUser,OU=Test,DC=test,DC=local'
                        Enabled           = $false
                        MemberOf          = 1..100 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                    }
                ) + (1..15 | ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName    = "user$_"
                        DistinguishedName = "CN=User$_,OU=Test,DC=test,DC=local"
                        Enabled           = $true
                        MemberOf          = @('Group1', 'Group2')
                    }
                })
            }
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'disabled_user'
        }
    }
}

Describe 'A-DormantPrivilegedAccount Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'A-DormantPrivilegedAccount'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should be in Anomalies category' {
            $rule.Category | Should -Be 'Anomalies'
        }

        It 'Should have CIS control mapping' {
            $rule.CIS | Should -Contain '5.4.1'
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            $mockADData = @{
                Users = @(
                    # Dormant privileged account - should be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'old_admin'
                        DistinguishedName = 'CN=OldAdmin,OU=Admins,DC=test,DC=local'
                        DisplayName       = 'Old Admin'
                        Enabled           = $true
                        AdminCount        = 1
                        LastLogonDate     = (Get-Date).AddDays(-180)
                        WhenCreated       = (Get-Date).AddDays(-365)
                        PasswordLastSet   = (Get-Date).AddDays(-200)
                    }
                    # Active privileged account - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'active_admin'
                        DistinguishedName = 'CN=ActiveAdmin,OU=Admins,DC=test,DC=local'
                        DisplayName       = 'Active Admin'
                        Enabled           = $true
                        AdminCount        = 1
                        LastLogonDate     = (Get-Date).AddDays(-5)
                        WhenCreated       = (Get-Date).AddDays(-100)
                        PasswordLastSet   = (Get-Date).AddDays(-30)
                    }
                    # Dormant non-privileged account - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'old_user'
                        DistinguishedName = 'CN=OldUser,OU=Users,DC=test,DC=local'
                        DisplayName       = 'Old User'
                        Enabled           = $true
                        AdminCount        = $null
                        LastLogonDate     = (Get-Date).AddDays(-200)
                        WhenCreated       = (Get-Date).AddDays(-400)
                        PasswordLastSet   = (Get-Date).AddDays(-250)
                    }
                    # Disabled privileged account - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'disabled_admin'
                        DistinguishedName = 'CN=DisabledAdmin,OU=Admins,DC=test,DC=local'
                        DisplayName       = 'Disabled Admin'
                        Enabled           = $false
                        AdminCount        = 1
                        LastLogonDate     = (Get-Date).AddDays(-300)
                        WhenCreated       = (Get-Date).AddDays(-500)
                        PasswordLastSet   = (Get-Date).AddDays(-400)
                    }
                )
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find dormant privileged account' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'old_admin'
        }

        It 'Should NOT find active privileged account' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'active_admin'
        }

        It 'Should NOT find non-privileged account' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'old_user'
        }

        It 'Should NOT find disabled account' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'disabled_admin'
        }

        It 'Should include severity level' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings[0].Severity | Should -BeIn @('Medium', 'High', 'Critical')
        }
    }
}

Describe 'A-OrphanedAdminCount Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'A-OrphanedAdminCount'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should be in Anomalies category' {
            $rule.Category | Should -Be 'Anomalies'
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            $mockADData = @{
                Users = @(
                    # Orphaned AdminCount - should be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'orphan_admin'
                        DistinguishedName = 'CN=OrphanAdmin,OU=Users,DC=test,DC=local'
                        DisplayName       = 'Orphan Admin'
                        Enabled           = $true
                        AdminCount        = 1
                        MemberOf          = @('CN=Regular Group,OU=Groups,DC=test,DC=local')
                        WhenChanged       = (Get-Date).AddDays(-30)
                        Description       = 'Former admin'
                    }
                    # Legit admin (in Domain Admins) - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'current_admin'
                        DistinguishedName = 'CN=CurrentAdmin,OU=Admins,DC=test,DC=local'
                        DisplayName       = 'Current Admin'
                        Enabled           = $true
                        AdminCount        = 1
                        MemberOf          = @('CN=Domain Admins,CN=Users,DC=test,DC=local')
                        WhenChanged       = (Get-Date).AddDays(-5)
                        Description       = 'Active admin'
                    }
                    # No AdminCount - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'regular_user'
                        DistinguishedName = 'CN=RegularUser,OU=Users,DC=test,DC=local'
                        DisplayName       = 'Regular User'
                        Enabled           = $true
                        AdminCount        = $null
                        MemberOf          = @('CN=Regular Group,OU=Groups,DC=test,DC=local')
                        WhenChanged       = (Get-Date).AddDays(-10)
                        Description       = 'Normal user'
                    }
                )
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find orphaned AdminCount account' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'orphan_admin'
        }

        It 'Should NOT find current admin in Domain Admins' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'current_admin'
        }

        It 'Should NOT find regular user without AdminCount' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'regular_user'
        }
    }
}

Describe 'A-RapidPrivilegeAccumulation Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'A-RapidPrivilegeAccumulation'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should be in Anomalies category' {
            $rule.Category | Should -Be 'Anomalies'
        }

        It 'Should have MITRE ATT&CK mapping for account creation' {
            $rule.MITRE | Should -Contain 'T1136.002'
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            $mockADData = @{
                Users = @(
                    # New account with many groups - should be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'new_privileged'
                        DistinguishedName = 'CN=NewPrivileged,OU=Users,DC=test,DC=local'
                        DisplayName       = 'New Privileged User'
                        Enabled           = $true
                        WhenCreated       = (Get-Date).AddDays(-7)
                        MemberOf          = 1..20 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                    }
                    # New account with few groups - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'new_normal'
                        DistinguishedName = 'CN=NewNormal,OU=Users,DC=test,DC=local'
                        DisplayName       = 'New Normal User'
                        Enabled           = $true
                        WhenCreated       = (Get-Date).AddDays(-5)
                        MemberOf          = @('CN=Group1,DC=test,DC=local')
                    }
                    # Old account with many groups - should NOT be flagged
                    [PSCustomObject]@{
                        SamAccountName    = 'old_privileged'
                        DistinguishedName = 'CN=OldPrivileged,OU=Users,DC=test,DC=local'
                        DisplayName       = 'Old Privileged User'
                        Enabled           = $true
                        WhenCreated       = (Get-Date).AddDays(-365)
                        MemberOf          = 1..20 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                    }
                ) + (1..15 | ForEach-Object {
                    # Baseline users for statistics
                    [PSCustomObject]@{
                        SamAccountName    = "baseline_user$_"
                        DistinguishedName = "CN=BaselineUser$_,OU=Users,DC=test,DC=local"
                        DisplayName       = "Baseline User $_"
                        Enabled           = $true
                        WhenCreated       = (Get-Date).AddDays(-100 - $_)
                        MemberOf          = 1..3 | ForEach-Object { "CN=Group$_,DC=test,DC=local" }
                    }
                })
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find new account with excessive groups' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'new_privileged'
        }

        It 'Should NOT find new account with normal groups' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'new_normal'
        }

        It 'Should NOT find old account even with many groups' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Not -Contain 'old_privileged'
        }

        It 'Should include account age in findings' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $newUser = $findings | Where-Object { $_.SamAccountName -eq 'new_privileged' }
            $newUser.AccountAgeDays | Should -BeLessThan 30
        }
    }
}

Describe 'A-LogonCountAnomaly Rule' {
    BeforeAll {
        $rule = Get-ADScoutRule -Id 'A-LogonCountAnomaly'
    }

    Context 'Rule Definition' {
        It 'Should exist' {
            $rule | Should -Not -BeNullOrEmpty
        }

        It 'Should be in Anomalies category' {
            $rule.Category | Should -Be 'Anomalies'
        }
    }

    Context 'Rule Execution' {
        BeforeAll {
            # Create dataset with logon count outlier
            $mockADData = @{
                Users = @(
                    # High logon count outlier
                    [PSCustomObject]@{
                        SamAccountName    = 'high_logon_user'
                        DistinguishedName = 'CN=HighLogonUser,OU=Users,DC=test,DC=local'
                        DisplayName       = 'High Logon User'
                        Enabled           = $true
                        LogonCount        = 50000
                        LastLogonDate     = (Get-Date).AddDays(-1)
                    }
                ) + (1..25 | ForEach-Object {
                    # Normal users
                    [PSCustomObject]@{
                        SamAccountName    = "user$_"
                        DistinguishedName = "CN=User$_,OU=Users,DC=test,DC=local"
                        DisplayName       = "User $_"
                        Enabled           = $true
                        LogonCount        = 100 + ($_ * 10)
                        LastLogonDate     = (Get-Date).AddDays(-$_)
                    }
                })
            }
        }

        It 'Should execute without errors' {
            { & $rule.ScriptBlock -ADData $mockADData } | Should -Not -Throw
        }

        It 'Should find high logon count user' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.SamAccountName | Should -Contain 'high_logon_user'
        }

        It 'Should indicate anomaly type' {
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $highUser = $findings | Where-Object { $_.SamAccountName -eq 'high_logon_user' }
            $highUser.AnomalyType | Should -Be 'HighLogonCount'
        }
    }

    Context 'Insufficient Data' {
        It 'Should handle insufficient logon data gracefully' {
            $mockADData = @{
                Users = 1..5 | ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName = "user$_"
                        DistinguishedName = "CN=User$_,OU=Users,DC=test,DC=local"
                        Enabled        = $true
                        LogonCount     = 100
                    }
                }
            }
            $findings = & $rule.ScriptBlock -ADData $mockADData
            $findings.Count | Should -Be 0
        }
    }
}
