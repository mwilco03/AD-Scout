# AD-Scout Future Work

> This document outlines planned features and improvements that are not yet implemented. Items are organized by category with detailed descriptions and implementation considerations.

## Rule Testing and Validation

### Comprehensive Test Coverage for All Rules

**Priority**: High
**Effort**: Large

Currently, AD-Scout has 205+ security rules but limited automated testing for individual rule logic. Each rule needs:

- **Unit tests**: Mock AD data to verify rule logic works correctly
- **Edge case coverage**: Empty results, single results, large datasets
- **Scoring validation**: Verify point calculations match specification
- **Regression tests**: Ensure rule changes don't break expected behavior

**Implementation Approach**:
```powershell
# Example test structure for each rule
Describe 'S-PwdNeverExpires Rule' {
    It 'Detects users with DONT_EXPIRE_PASSWORD flag' {
        $mockUsers = @(
            @{ userAccountControl = 65536 }  # DONT_EXPIRE_PASSWORD
            @{ userAccountControl = 512 }    # Normal
        )
        $result = Test-Rule-S-PwdNeverExpires -Users $mockUsers
        $result.FindingCount | Should -Be 1
    }
}
```

**Files to Create**:
- `tests/Rules/*.Tests.ps1` - One test file per rule category
- `tests/Mocks/ADData.ps1` - Shared mock data generators
- `tests/RuleValidation.Tests.ps1` - Meta-tests for rule structure

---

## Distribution and Packaging

### PowerShell Gallery Publishing

**Priority**: High
**Effort**: Medium

Publish AD-Scout to the PowerShell Gallery for easy installation via `Install-Module ADScout`.

**Requirements**:
- NuGet API key for publishing
- Semantic versioning automation
- Release notes generation
- Dependency declaration in manifest
- Gallery metadata (tags, description, license)

**Implementation Steps**:
1. Add `Publish-Module` step to CI/CD pipeline
2. Create `.github/workflows/publish.yml` for release automation
3. Add pre-release tagging support
4. Set up gallery account and API key as repository secret

**Example Workflow**:
```yaml
name: Publish to PowerShell Gallery
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Publish Module
        shell: pwsh
        env:
          NUGET_KEY: ${{ secrets.PSGALLERY_KEY }}
        run: |
          Publish-Module -Path ./src/ADScout -NuGetApiKey $env:NUGET_KEY
```

---

### Community Rule Gallery

**Priority**: Medium
**Effort**: Large

Create a package management system for community-contributed rules, similar to npm or NuGet.

**Features**:
- `Install-ADScoutRulePackage` - Download and install rule packages
- `Publish-ADScoutRulePackage` - Publish custom rules to gallery
- `Find-ADScoutRulePackage` - Search available packages
- Version management and updates
- Rule signing and trust verification

**Architecture**:
```
adscout-rules/
├── packages/
│   ├── contoso-compliance/
│   │   ├── rules.json
│   │   └── Rules/*.ps1
│   └── hipaa-healthcare/
│       ├── rules.json
│       └── Rules/*.ps1
└── registry.json  # Central package index
```

**Storage Options**:
- GitHub Releases for packages
- Dedicated gallery service (future)
- Local file-based packages

---

## IDE and Editor Integration

### VS Code Extension

**Priority**: Medium
**Effort**: Large

Create a Visual Studio Code extension for AD-Scout development and usage.

**Features**:
- **Rule authoring**: IntelliSense for rule properties, category values, MITRE mappings
- **Syntax highlighting**: Custom syntax for rule definitions
- **Linting**: Validate rule structure and required fields
- **Run integration**: Execute scans directly from VS Code
- **Results viewer**: Treeview of findings with severity icons
- **Snippets**: Quick templates for new rules

**Technical Implementation**:
- TypeScript extension using VS Code Extension API
- Language Server Protocol for PowerShell integration
- WebView panels for results visualization

**Project Structure**:
```
vscode-adscout/
├── src/
│   ├── extension.ts
│   ├── providers/
│   │   ├── completionProvider.ts
│   │   └── diagnosticsProvider.ts
│   └── views/
│       └── resultsPanel.ts
├── syntaxes/
│   └── adscout-rule.tmLanguage.json
└── package.json
```

---

## CI/CD Integration

### GitHub Actions Task Template

**Priority**: Medium
**Effort**: Small

Create a reusable GitHub Action for running AD-Scout scans in CI/CD pipelines.

**Features**:
- Configurable scan categories and rules
- Fail pipeline on score threshold
- Artifact upload for reports
- PR comments with summary
- Badge generation

**Usage Example**:
```yaml
- uses: mwilco03/ad-scout-action@v1
  with:
    categories: 'PrivilegedAccounts,StaleObjects'
    fail-on-score: 50
    output-format: 'SARIF'
```

**Implementation**:
- `action.yml` - Action metadata and inputs
- `entrypoint.ps1` - Main execution script
- Docker container or composite action

---

### Azure DevOps Task

**Priority**: Medium
**Effort**: Medium

Create an Azure DevOps extension with pipeline tasks for AD-Scout.

**Features**:
- Visual task configuration
- Azure AD integration for credentials
- Test results publishing
- Build artifacts for reports
- Marketplace distribution

**Task Definition**:
```json
{
  "id": "ad-scout-scan",
  "name": "ADScoutScan",
  "friendlyName": "AD-Scout Security Scan",
  "inputs": [
    { "name": "categories", "type": "multiLine" },
    { "name": "failOnScore", "type": "string" },
    { "name": "outputFormat", "type": "pickList" }
  ]
}
```

---

## Monitoring and Visualization

### Grafana Data Source

**Priority**: Low
**Effort**: Large

Create a Grafana data source plugin for visualizing AD-Scout results.

**Features**:
- Query historical scan results
- Score trend graphs
- Category breakdown panels
- Alerting integration
- Annotation support for scan events

**Technical Approach**:
- Go-based backend data source
- Query endpoint returns time-series or table data
- Storage backend: JSON files, SQLite, or external database

**Dashboard Examples**:
- Security score over time
- Top findings by category
- Remediation progress tracking
- Compliance status heatmaps

---

### Real-Time WebSocket Updates

**Priority**: Low
**Effort**: Medium

Enhance the web dashboard with WebSocket support for real-time updates during scans.

**Current State**: Dashboard polls `/api/results` every 30 seconds.

**Proposed Enhancement**:
```javascript
// Client-side WebSocket connection
const ws = new WebSocket('ws://localhost:8080/ws');
ws.onmessage = (event) => {
    const update = JSON.parse(event.data);
    switch(update.type) {
        case 'progress':
            updateProgressBar(update.percent);
            break;
        case 'finding':
            addFinding(update.finding);
            break;
        case 'complete':
            showSummary(update.results);
            break;
    }
};
```

**Server-Side Changes**:
- Add WebSocket handler to HttpListener
- Broadcast progress during scan execution
- Push findings as they're discovered

---

## Documentation

### Documentation Site

**Priority**: Medium
**Effort**: Medium

Create a dedicated documentation website using a static site generator.

**Content Structure**:
- Getting Started guide
- Rule reference (auto-generated from rule metadata)
- API documentation
- Integration guides (SIEM, CI/CD)
- Contributing guide
- FAQ

**Technical Options**:
- MkDocs with Material theme (Python)
- Docusaurus (React)
- Hugo (Go)
- GitHub Pages hosting

**Auto-Generation**:
```powershell
# Generate rule reference from metadata
$rules = Get-ADScoutRule
$rules | ForEach-Object {
    @"
## $($_.Id) - $($_.Name)

**Category**: $($_.Category)
**Points**: $($_.Points) (Max: $($_.MaxPoints))

$($_.Description)

### MITRE ATT&CK
$($_.MITRE -join ', ')

### Remediation
$($_.Remediation)
"@
} | Out-File docs/rules-reference.md
```

---

## Event and Log Integration

### Windows Event Log Integration

**Priority**: Medium
**Effort**: Medium

Add capability to analyze Windows Security Event Logs for additional context.

**Target Events**:
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4720 | User account created |
| 4722 | User account enabled |
| 4728 | Member added to security group |
| 4732 | Member added to local group |
| 4756 | Member added to universal group |

**Implementation**:
```powershell
function Get-ADScoutEventData {
    param(
        [string[]]$EventId = @(4624, 4625),
        [datetime]$StartTime = (Get-Date).AddDays(-7),
        [string]$ComputerName
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = $EventId
        StartTime = $StartTime
    } -ComputerName $ComputerName
}
```

**New Rules Using Event Data**:
- Detect password spraying (many 4625 events)
- Detect unusual logon patterns
- Identify dormant accounts with recent activity
- Track privilege escalation chains

**Considerations**:
- Requires elevated permissions to read Security log
- May need remote collection for distributed DCs
- Large log volumes require efficient filtering
- Optional module to avoid dependency on all systems

---

## Contributing

Contributions to any of these features are welcome. Please:

1. Open an issue to discuss the approach before starting work
2. Follow the existing code style and patterns
3. Include tests for new functionality
4. Update documentation as needed

## Priority Legend

| Priority | Meaning |
|----------|---------|
| High | Important for core functionality or user adoption |
| Medium | Valuable enhancement, implement when resources allow |
| Low | Nice to have, consider for future releases |

## Effort Legend

| Effort | Meaning |
|--------|---------|
| Small | < 1 day of work |
| Medium | 1-5 days of work |
| Large | > 1 week of work |
