# AD-Scout Design Document

> **Status**: STATIC - This document defines the vision and philosophy of AD-Scout. Changes require maintainer approval.

## Vision

AD-Scout is a PowerShell-native Active Directory security assessment framework that empowers security professionals and system administrators to identify, understand, and remediate security weaknesses in their Active Directory environments.

## Mission

To provide an open-source, extensible, and accessible tool for Active Directory security assessment that:

1. Works seamlessly within existing PowerShell workflows
2. Enables community contribution without barriers
3. Provides actionable remediation guidance
4. Maps findings to industry security frameworks

## Core Principles

### 1. PowerShell-First

AD-Scout is not a compiled binary with a PowerShell wrapper. It is a native PowerShell module that:

- Uses native cmdlets before CIM, CIM before WMI, WMI before .NET
- Supports the PowerShell pipeline for composability
- Provides tab-completion for discoverability
- Works with `Show-Command` for GUI interaction
- Integrates with PowerShell's help system

**Rationale**: PowerShell is the native management language for Windows environments. A PowerShell-first approach ensures natural integration with existing tools and workflows.

### 2. Community-Extensible

Anyone can contribute rules without:

- Compiling code
- Understanding complex architectures
- Signing binaries
- Waiting for releases

Rules are PowerShell hashtables in `.ps1` files that can be:
- Dropped into the module's Rules directory
- Loaded from custom paths
- Shared as single files

**Rationale**: Security knowledge should be shareable. Lowering the barrier to contribution increases the collective security of all users.

### 3. Cross-Version Compatible

AD-Scout works on:

- Windows PowerShell 5.1 (most enterprise environments)
- PowerShell 7.x (modern environments)
- Desktop and Core editions

When version-specific features are available, AD-Scout uses them for performance (e.g., `ForEach-Object -Parallel`), but always falls back gracefully.

**Rationale**: Enterprise environments cannot always run the latest software. AD-Scout meets administrators where they are.

### 4. Output-Flexible

Results are data, not presentation. AD-Scout separates:

- **Collection**: Gathering AD data
- **Analysis**: Evaluating rules against data
- **Reporting**: Presenting findings

Reporters are pluggable modules that can output to:
- Console (human-readable)
- HTML (management reporting)
- JSON (automation and SIEM)
- CSV (spreadsheet analysis)
- SARIF (DevSecOps integration)
- Custom formats (webhooks, databases, etc.)

**Rationale**: Different stakeholders need different outputs. A CISO needs an executive summary; a SOC needs SIEM-ingestible data; an admin needs actionable commands.

### 5. Framework-Mapped

Every finding maps to relevant security frameworks:

- **MITRE ATT&CK**: Adversary tactics and techniques
- **CIS Controls**: Defensive security controls
- **DISA STIG**: Government compliance requirements
- **ANSSI**: European security guidance

**Rationale**: Mapping findings to frameworks provides context, aids prioritization, and supports compliance efforts.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interface                         │
│  (Invoke-ADScoutScan, Show-ADScoutDashboard, CLI)          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Orchestration Layer                       │
│  (Parallel execution, progress reporting, error handling)   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Collectors    │ │    Analyzers    │ │   Reporters     │
│                 │ │                 │ │                 │
│ • Users         │ │ • Rule Engine   │ │ • Console       │
│ • Computers     │ │ • Scoring       │ │ • HTML          │
│ • Groups        │ │ • Categorization│ │ • JSON          │
│ • GPOs          │ │                 │ │ • CSV           │
│ • Trusts        │ │                 │ │ • Custom        │
│ • Certificates  │ │                 │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Rules                                │
│  (PowerShell hashtables with metadata and ScriptBlocks)     │
└─────────────────────────────────────────────────────────────┘
```

## Differentiation

### vs. PingCastle

- **Language**: AD-Scout is pure PowerShell; PingCastle is C#
- **Extensibility**: AD-Scout uses drop-in rules; PingCastle requires recompilation
- **License**: AD-Scout is MIT; PingCastle is proprietary/GPL
- **Focus**: AD-Scout emphasizes PowerShell integration; PingCastle emphasizes standalone operation

### vs. BloodHound

- **Purpose**: AD-Scout focuses on configuration assessment; BloodHound focuses on attack path analysis
- **Dependencies**: AD-Scout has no external dependencies; BloodHound requires Neo4j
- **Output**: AD-Scout produces reports; BloodHound produces graphs
- **Complementary**: Both tools serve different purposes and can be used together

### vs. ADRecon

- **Scope**: AD-Scout focuses on security findings; ADRecon focuses on data collection
- **Rules**: AD-Scout has an extensible rule engine; ADRecon has hardcoded checks
- **Framework Mapping**: AD-Scout maps to MITRE/CIS/STIG; ADRecon does not
- **Similar**: Both are pure PowerShell with similar data collection approaches

## Design Decisions

### Rule Format

Rules are PowerShell hashtables, not classes or DSL, because:

- Hashtables are universally understood
- No learning curve for contributors
- Easy to validate with JSON Schema
- No compilation or module import required

### Scoring Model

AD-Scout uses a points-based scoring model:

- Each rule assigns points for findings
- Points accumulate up to a configurable maximum
- Categories have separate scores
- Overall score provides quick assessment

Computation types:
- **TriggerOnPresence**: Fixed points if any findings exist
- **PerDiscover**: Points per finding (most common)
- **TriggerOnThreshold**: Points if count exceeds threshold
- **TriggerIfLessThan**: Points if count is below threshold

### Caching Strategy

AD data is cached during scans to:

- Avoid redundant AD queries
- Enable offline analysis
- Support incremental updates

Cache TTL is configurable (default: 5 minutes).

### Error Handling

AD-Scout follows these error handling principles:

1. **Never crash on missing data**: Skip and warn
2. **Log everything**: Verbose and Debug streams
3. **Aggregate errors**: Report all issues, not just the first
4. **Provide context**: Include relevant object information

## Future Considerations

### Attack Path Analysis

While BloodHound excels at attack paths, AD-Scout may add lightweight path analysis for common scenarios (e.g., path to Domain Admin).

### Agent Mode

A future agent mode could run continuous assessments and report to a central dashboard.

### Cloud Integration

Azure AD and hybrid environment support are planned for future releases.

## Conclusion

AD-Scout is designed to be the community's Active Directory security tool—extensible, accessible, and powerful. By prioritizing PowerShell integration and community contribution, we aim to make AD security assessment available to everyone.
