# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure and architecture
- Module manifest and loader
- Core public functions:
  - `Invoke-ADScoutScan` - Main scanning function
  - `Get-ADScoutRule` - List and filter rules
  - `New-ADScoutRule` - Create new rule from template
  - `Register-ADScoutRule` - Register custom rule paths
  - `Export-ADScoutReport` - Export findings to various formats
  - `Get-ADScoutRemediation` - Get remediation guidance
  - `Set-ADScoutConfig` / `Get-ADScoutConfig` - Configuration management
  - `Show-ADScoutDashboard` - Interactive dashboard
- Data collectors for users, computers, groups, trusts, GPOs, certificates
- Cross-version compatibility layer (PS 5.1, PS 7.x)
- Parallel execution support with tiered fallback
- First rule: `S-PwdNeverExpires` (Stale Objects category)
- Console reporter with color-coded output
- HTML, JSON, and CSV reporters
- Rule template with MITRE/CIS/STIG mappings
- Tab completion for -Category and -Format parameters
- GitHub Actions CI/CD workflows
- Pester test framework setup
- PSScriptAnalyzer configuration

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- N/A (initial release)

## [0.1.0-alpha] - TBD

Initial alpha release for community testing.
