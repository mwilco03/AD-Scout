# AD-Scout

**PowerShell-native Active Directory security assessment framework**

[![CI](https://github.com/mwilco03/AD-Scout/actions/workflows/ci.yml/badge.svg)](https://github.com/mwilco03/AD-Scout/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ADScout?label=PSGallery)](https://www.powershellgallery.com/packages/ADScout)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

## Overview

AD-Scout is a community-driven, extensible Active Directory security assessment framework built entirely in PowerShell. It provides comprehensive security analysis with customizable rules, multiple output formats, and seamless integration into existing workflows.

## Quick Start

```powershell
# Install from PowerShell Gallery
Install-Module -Name ADScout -Scope CurrentUser

# Import the module
Import-Module ADScout

# Run a basic scan
Invoke-ADScoutScan | Export-ADScoutReport -Format Console

# Scan specific categories
Invoke-ADScoutScan -Category PrivilegedAccounts, StaleObjects | Export-ADScoutReport -Format HTML -Path ./report.html

# List available rules
Get-ADScoutRule

# Get remediation guidance
Get-ADScoutRemediation -RuleId S-PwdNeverExpires
```

## Key Features

- **PowerShell-first**: Native module experience with tab-completion, pipeline support, and Show-Command integration
- **Community-extensible**: Drop-in rule files with no compilation required
- **Cross-version compatible**: Works on PowerShell 5.1 and 7.x (Desktop and Core editions)
- **Output-flexible**: Pluggable reporters (HTML, JSON, CSV, SARIF, Console, and more)
- **Security framework mappings**: Built-in MITRE ATT&CK, CIS, and STIG references
- **Remediation guidance**: Actionable scripts for each finding
- **Enterprise-ready**: Credential support, throttling, and progress reporting

## Comparison

| Feature | AD-Scout | PingCastle | BloodHound | ADRecon |
|---------|----------|------------|------------|---------|
| Language | PowerShell | C# | C#/JS | PowerShell |
| Extensibility | Drop-in rules | Requires rebuild | Custom queries | Script modification |
| Output Formats | Pluggable | HTML/XML | Neo4j | Multiple |
| Attack Paths | Planned | Limited | Extensive | None |
| MITRE Mapping | Yes | Partial | No | No |
| License | MIT | Proprietary/GPL | GPL | MIT |
| Offline Analysis | Yes | Yes | Yes | Yes |
| PowerShell Native | Yes | No | No | Yes |

## Rule Categories

- **Anomalies**: Unusual configurations that may indicate compromise
- **StaleObjects**: Dormant accounts, unused computers, orphaned objects
- **PrivilegedAccounts**: Excessive privileges, dangerous delegations, admin sprawl
- **Trusts**: Insecure trust relationships, SID filtering issues

## Output Formats

- **Console**: Real-time terminal output with color-coded severity
- **HTML**: Interactive report with charts and drill-down
- **JSON**: Machine-readable for automation and SIEM integration
- **CSV**: Spreadsheet-compatible for analysis and tracking
- **SARIF**: Static Analysis Results Interchange Format for DevSecOps

## Documentation

- [Design Document](DESIGN_DOCUMENT.md) - Vision and philosophy
- [Architecture](ARCHITECTURE.md) - Implementation guide
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Acknowledgments](ACKNOWLEDGMENTS.md) - Credits to prior art

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x
- Active Directory environment (or offline data for analysis)
- Appropriate permissions for AD queries (Domain User minimum, Domain Admin for complete analysis)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Creating Custom Rules

```powershell
# Generate a new rule template
New-ADScoutRule -Name "MyCustomRule" -Category Anomalies -Path ./MyRules

# Register a custom rule directory
Register-ADScoutRule -Path ./MyRules

# Run scan including custom rules
Invoke-ADScoutScan
```

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

AD-Scout is licensed under the [MIT License](LICENSE).

This project is an independent work and is not affiliated with, endorsed by, or derived from any other Active Directory security tool. See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for credits to projects that inspired this work.
