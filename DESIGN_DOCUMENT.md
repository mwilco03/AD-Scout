# ADScout: PowerShell-Native Active Directory Security Assessment Framework

## Design Document v0.1

> **Status**: STATIC - This document defines the vision and philosophy of AD-Scout. Changes require maintainer approval.

---

## Executive Summary

**ADScout** is a PowerShell-native Active Directory security assessment framework designed from the ground up for the modern administrator, security professional, and DevOps engineer. While standing on the shoulders of giants like PingCastle, BloodHound, and ADRecon, ADScout is a wholly distinct project with different goals, architecture, and philosophy.

**Core Philosophy:** *"If it can be done in PowerShell, it should be done in PowerShell."*

---

## 1. Vision & Objectives

### What We Are Aiming to Accomplish

1. **Democratize AD Security Assessment** - Make professional-grade AD security auditing accessible to every organization, regardless of budget or expertise level.

2. **PowerShell-Native Experience** - First-class PowerShell citizen with tab-completion, pipeline support, `Show-Command` integration, and idiomatic PowerShell patterns.

3. **Community-Driven Extensibility** - Lower the barrier for security professionals to contribute rules, scanners, and reports without requiring C# compilation or complex toolchains.

4. **Cross-Version Compatibility** - Deterministic behavior across PowerShell 5.1 (Windows) and 7.x (cross-platform).

5. **Transparency & Education** - Not just "you have a problem" but "here's why it's a problem, here's the attack path, and here's exactly how to fix it."

---

## 2. Differentiation: Why ADScout?

### How ADScout Differs from PingCastle

| Aspect | PingCastle | ADScout |
|--------|------------|---------|
| **Language** | C# compiled executable | PowerShell-native module |
| **Rule Creation** | Requires C# knowledge, recompilation | Drop-in `.ps1` files with scriptblocks |
| **Extensibility** | Modify source, rebuild | `Register-ADScoutRule` at runtime |
| **Integration** | Standalone tool | Pipeline-native, CI/CD ready |
| **Reporting** | Embedded HTML generation | Pluggable reporters (HTML, JSON, CSV, Dashboard) |
| **AV Detection** | Often flagged (15+ vendors) | Scripts rarely flagged |
| **Learning Curve** | Run executable, read report | Interactive exploration, `Get-Help` everywhere |
| **Customization** | Configuration files | PowerShell parameter sets, splatting |
| **Community Rules** | Pull requests to main repo | Local rule directories, community galleries |

### How ADScout Differs from BloodHound

| Aspect | BloodHound | ADScout |
|--------|------------|---------|
| **Focus** | Attack path analysis (graph) | Security posture assessment (score) |
| **Output** | Neo4j database, web UI | PowerShell objects, exportable reports |
| **Use Case** | Red team, penetration testing | Blue team, compliance, continuous monitoring |
| **Dependencies** | Neo4j, SharpHound binary | PowerShell only (optional .NET libs) |
| **Complementary** | Yes - different focus areas | Can feed data TO BloodHound |

### How ADScout Differs from ADRecon

| Aspect | ADRecon | ADScout |
|--------|---------|---------|
| **Focus** | Data collection & inventory | Security assessment & scoring |
| **Output** | Excel spreadsheets | Scored findings with remediation |
| **Rules** | Implicit in code | Explicit, declarative, extensible |
| **Scoring** | None | Risk-based scoring system |

---

## 3. Key Features

### 3.1 Rule Generator Architecture

The heart of ADScout is its **scriptblock-based rule system**:

```powershell
# Defining a rule is as simple as writing a scriptblock
New-ADScoutRule -Id "S-PwdNeverExpires" -Category "StaleObjects" -ScriptBlock {
    param($ADData)

    # Return objects that violate the rule
    $ADData.Users | Where-Object {
        $_.PasswordNeverExpires -eq $true -and
        $_.Enabled -eq $true
    }
}

# The returned objects automatically become the finding details
# Points are calculated based on count and rule configuration
```

#### Rule Definition Schema

```powershell
@{
    # Identity
    Id          = "S-PwdNeverExpires"
    Name        = "Password Never Expires"
    Category    = "StaleObjects"        # Anomalies, StaleObjects, PrivilegedAccounts, Trusts
    Model       = "PasswordPolicy"       # Sub-categorization

    # Scoring
    Computation = "PerDiscover"          # TriggerOnPresence, PerDiscover, TriggerOnThreshold, TriggerIfLessThan
    Points      = 1                       # Points per finding (or total for TriggerOnPresence)
    MaxPoints   = 30                      # Cap for PerDiscover rules

    # Framework Mappings
    MITRE       = @("T1078.002")         # MITRE ATT&CK technique IDs
    ANSSI       = "R36"                   # ANSSI recommendation
    CIS         = "5.1.2"                 # CIS Benchmark control
    STIG        = "V-8527"                # DISA STIG finding ID

    # The Check (returns violating objects)
    ScriptBlock = {
        param($ADData)
        $ADData.Users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
    }

    # Output Configuration
    DetailProperties = @("SamAccountName", "DistinguishedName", "PasswordLastSet")

    # Remediation
    Remediation = {
        param($Finding)
        "Set-ADUser -Identity '$($Finding.SamAccountName)' -PasswordNeverExpires `$false"
    }

    # Documentation
    Description = "Accounts with passwords that never expire present a persistent attack surface."
    TechnicalExplanation = "When PasswordNeverExpires is set, compromised credentials remain valid indefinitely."

    # References
    References = @(
        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
        "https://attack.mitre.org/techniques/T1078/002/"
    )
}
```

### 3.2 Tab-Completion & Show-Command Integration

Every command supports rich tab-completion:

```powershell
# Tab through categories
Invoke-ADScoutScan -Category <TAB>
# Shows: Anomalies, StaleObjects, PrivilegedAccounts, Trusts

# Tab through specific rules
Invoke-ADScoutScan -RuleId <TAB>
# Shows: A-AuditDC, S-PwdNeverExpires, P-Kerberoasting...

# Tab through output formats
Export-ADScoutReport -Format <TAB>
# Shows: HTML, JSON, CSV, SARIF, Markdown, Console

# Show-Command for discovery
Show-Command Invoke-ADScoutScan
# Opens GUI with all parameters, dropdowns, help text
```

### 3.3 Data Collection Priority

**PowerShell-First Philosophy:**

```
Priority 1: Native PowerShell Cmdlets
    Get-ADUser, Get-ADComputer, Get-ADGroup, Get-ADTrust
    Get-ADDomain, Get-ADForest, Get-ADReplicationSite

Priority 2: CIM/WMI (CIM preferred)
    Get-CimInstance -ClassName Win32_OperatingSystem
    Get-CimInstance vs Get-WmiObject (CIM preferred for PS 3+)

Priority 3: .NET Framework Classes
    [System.DirectoryServices.DirectorySearcher] for LDAP
    [System.DirectoryServices.ActiveDirectory.*] for forest/domain

Priority 4: External Libraries (when no alternative)
    SMBLibrary for protocol-level SMB scanning
    Only loaded when specific scanners invoked
```

### 3.4 Cross-Version Compatibility Matrix

| Feature | PS 5.1 | PS 7.x | Notes |
|---------|--------|--------|-------|
| **Core Rules** | ✅ | ✅ | DirectorySearcher works everywhere |
| **AD Cmdlets** | ✅ | ✅ | Graceful fallback to ADSI |
| **CIM Sessions** | ✅ | ✅ | Native support |
| **Tab Completion** | ✅ | ✅ | Full support |
| **Classes** | ✅ | ✅ | Full support |
| **HTML Reports** | ✅ | ✅ | ConvertTo-Html universal |
| **Parallel Scans** | ⚠️ | ✅ | Runspaces on 5.1, ForEach-Parallel on 7 |

### 3.5 Reporting System

#### Pluggable Reporter Architecture

```powershell
# Use multiple reporters
Invoke-ADScoutScan | Export-ADScoutReport -Format HTML, JSON, Console

# Export to different destinations
$results | Export-ADScoutReport -Format HTML -Path "./report.html"
$results | Export-ADScoutReport -Format JSON -Path "./results.json"
$results | Export-ADScoutReport -Format SARIF -Path "./security.sarif"
```

#### Built-in Reporters

| Reporter | Output | Features |
|----------|--------|----------|
| **Console** | Terminal | Color-coded, severity indicators |
| **HTML** | Static HTML file | Interactive tables, charts |
| **JSON** | Structured data | CI/CD integration, API consumption |
| **CSV** | Spreadsheet-ready | Excel import, legacy systems |
| **SARIF** | Security standard | GitHub/Azure DevOps security tab |
| **Markdown** | Documentation | Git-friendly, PR comments |

---

## 4. Community Requests Addressed

Based on analysis of community feedback from similar tools:

| Request | How ADScout Addresses It |
|---------|-------------------------|
| **API Access** | Native PowerShell objects - IS the API |
| **Scheduled Scanning** | PowerShell + Task Scheduler (trivial) |
| **AV False Positives** | Scripts don't trigger like compiled EXEs |
| **Integration with Tools** | Pipeline-native, outputs to any format |
| **Multi-Domain Support** | `-Domain` parameter support |
| **Remediation Scripts** | `Get-ADScoutRemediation -RuleId X` outputs runnable scripts |
| **Custom Rules** | First-class citizen, no recompilation |
| **Better Error Handling** | `-ErrorAction`, try/catch, `-Verbose` |

### New Features

```powershell
# 1. Differential Scanning - What changed since last scan?
$baseline = Import-ADScoutBaseline -Path "./baseline.json"
Invoke-ADScoutScan -Baseline $baseline | Where-Object IsNew

# 2. Remediation Automation
Get-ADScoutRemediation -RuleId "S-PwdNeverExpires" -AsScript

# 3. Compliance Mapping
Invoke-ADScoutScan | Where-Object { $_.MITRE -contains "T1078.002" }

# 4. Impact Analysis
Invoke-ADScoutScan | Select-Object RuleId, Score, FindingCount
```

---

## 5. Technical Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              INVOCATION                                  │
│  Invoke-ADScoutScan -Domain contoso.com -Category Anomalies             │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA COLLECTION                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │ PS Cmdlets   │  │ CIM/WMI      │  │ ADSI/LDAP    │  │ .NET Libs   │  │
│  │ Get-ADUser   │  │ Win32_*      │  │ DirectorySvc │  │ (optional)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
│         └──────────────────┴─────────────────┴─────────────────┘         │
│                                     │                                    │
│                                     ▼                                    │
│                          ┌──────────────────┐                            │
│                          │   $ADData Object │  (Normalized data model)   │
│                          └────────┬─────────┘                            │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            RULE ENGINE                                   │
│                                                                          │
│   foreach ($Rule in Get-ADScoutRule -Category $Category) {              │
│       $Findings = & $Rule.ScriptBlock -ADData $ADData                   │
│       $Score = Measure-RuleScore -Findings $Findings -Rule $Rule        │
│   }                                                                      │
│                                                                          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              RESULTS                                     │
│                                                                          │
│   [PSCustomObject]@{                                                     │
│       Domain        = "contoso.com"                                      │
│       ScanTime      = [datetime]                                         │
│       GlobalScore   = 65                                                 │
│       CategoryScores = @{ Anomalies=35; StaleObjects=45; ... }          │
│       Rules         = @( [RuleResult], [RuleResult], ... )              │
│   }                                                                      │
│                                                                          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                        ┌────────────┼────────────┐
                        ▼            ▼            ▼
                 ┌──────────┐ ┌──────────┐ ┌──────────┐
                 │ Pipeline │ │  Export  │ │Dashboard │
                 │ Output   │ │  Report  │ │  Live    │
                 └──────────┘ └──────────┘ └──────────┘
```

---

## 6. Considerations & Design Decisions

### Security
- **Credential Handling**: Never store credentials; use `Get-Credential` or Windows auth
- **Execution Policy**: Work within user's policy, don't bypass
- **Least Privilege**: Document minimum required permissions per scan type
- **Output Sanitization**: Don't expose sensitive data in reports by default

### Performance
- **Lazy Loading**: Don't load optional libraries unless specific scans requested
- **Caching**: Cache expensive queries (schema, forest info) per session
- **Parallelization**: Configurable thread count, respect server limits

### Compatibility
- **No Breaking Changes**: Semantic versioning, deprecation warnings
- **Fallback Chains**: Always have a way to get data, even if degraded

### Usability
- **Verbose by Default**: Progress indicators, `-Verbose` for details
- **Fail Gracefully**: Skip unavailable data sources, continue scanning
- **Helpful Errors**: Not just "Access Denied" but "Try running as Domain Admin"

---

## 7. Licensing Strategy

### MIT License

**Rationale:**

| Factor | MIT Advantage |
|--------|---------------|
| **Simplicity** | One of the most permissive, easy to understand |
| **Adoption** | Maximum adoption potential |
| **Contribution** | No license friction for contributors |
| **Compatibility** | Compatible with LGPL libraries we depend on |
| **Commercial Use** | Allowed |
| **No Copyleft** | Derivatives don't need to be open source |

---

## 8. Standing on the Shoulders of Giants

### Acknowledgments

ADScout would not be possible without the pioneering work of these projects and individuals:

#### PingCastle
**Author:** Vincent LE TOUX

PingCastle established the foundational concepts of Active Directory security scoring, risk categorization, and the rule-based assessment model. Its comprehensive rule library represents years of security research and real-world assessment experience.

#### BloodHound / SharpHound
**Authors:** SpecterOps team

BloodHound revolutionized understanding of Active Directory attack paths through graph theory.

#### SMBLibrary
**Author:** Tal Aloni

A complete, open-source SMB implementation in C#, enabling protocol-level inspection.

#### ADRecon
**Author:** Prashant Mahajan

Demonstrated the viability of comprehensive AD data collection in pure PowerShell.

#### PSWriteHTML
**Author:** Evotec

Proved that beautiful, interactive HTML reports can be generated entirely from PowerShell.

#### DSInternals
**Author:** Michael Grafnetter

Showed that deep AD internals can be exposed through PowerShell.

---

### This Is a Different Project

While we deeply appreciate and acknowledge these contributions, **ADScout is an independent project** with:

- **Different goals**: PowerShell-native experience over compiled performance
- **Different architecture**: Scriptblock-based rules over C# classes
- **Different philosophy**: Community-first, contribution-friendly design
- **Different licensing**: MIT
- **Different target audience**: PowerShell administrators, DevOps engineers, blue teamers

We are not a fork, port, or derivative work. We are a new tool that applies lessons learned from these giants to create something that fills a different niche in the AD security ecosystem.

---

## 9. Roadmap

### Phase 1: Foundation (MVP)
- [x] Core module structure
- [x] Rule engine with scriptblock support
- [x] Essential rules (starting with S-PwdNeverExpires)
- [x] Basic HTML reporting
- [x] PowerShell 5.1 support
- [x] Tab completion for all parameters

### Phase 2: Parity
- [ ] Additional rules implemented
- [ ] PSWriteHTML integration
- [ ] PowerShell 7.x parallel scanning
- [ ] JSON/SARIF export
- [ ] Remediation script generation

### Phase 3: Innovation
- [ ] Differential scanning / baselines
- [ ] Live dashboard
- [ ] Microsoft Graph integration (Entra ID)
- [ ] Community rule gallery
- [ ] Impact analysis

### Phase 4: Ecosystem
- [ ] VS Code extension
- [ ] GitHub Actions integration
- [ ] Azure DevOps tasks
- [ ] Documentation site

---

## 10. Getting Started

```powershell
# Install from PowerShell Gallery (future)
Install-Module ADScout -Scope CurrentUser

# Quick scan
Invoke-ADScoutScan | Format-Table RuleId, Score, Description

# Full scan with HTML report
Invoke-ADScoutScan | Export-ADScoutReport -Format HTML -Path "./ADSecurityReport.html"

# Interactive exploration
Show-Command Invoke-ADScoutScan  # GUI for parameter discovery

# Add custom rule
New-ADScoutRule -Name "MyCustomCheck" -Category Anomalies -Path ./MyRules

# Register custom rules
Register-ADScoutRule -Path ./MyRules

# Run scan with all rules
Invoke-ADScoutScan
```

---

*"In the world of security, sharing knowledge is not a weakness—it's our greatest strength."*
