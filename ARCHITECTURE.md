# AD-Scout Architecture

> **Status**: STATIC - This document defines implementation details. Changes require maintainer approval.

## Module Structure

```
src/ADScout/
├── ADScout.psd1           # Module manifest
├── ADScout.psm1           # Module loader (dot-sources all files)
├── Public/                # Exported functions
├── Private/               # Internal functions
│   ├── Collectors/        # AD data gathering
│   ├── Scanners/          # Analysis engines
│   ├── Compatibility/     # Cross-version support
│   ├── Statistics/        # Statistical analysis for anomaly detection
│   └── Helpers/           # Utility functions
├── Rules/                 # Security rules by category
├── Reporters/             # Output formatters
├── Schemas/               # JSON Schema definitions
├── Templates/             # Report templates
└── en-US/                 # Help files
```

## Component Details

### Module Loader (ADScout.psm1)

The module loader:
1. Dot-sources all Private functions (recursively)
2. Dot-sources all Public functions
3. Exports Public functions by name
4. Initializes module-level configuration
5. Registers argument completers

```powershell
# Load order
Private/Compatibility/* → Private/Helpers/* → Private/Collectors/* → Public/*
```

### Public Functions

#### Core Scanning

| Function | Purpose |
|----------|---------|
| `Invoke-ADScoutScan` | Main entry point for security scans |
| `Get-ADScoutRule` | List and filter available rules |
| `New-ADScoutRule` | Create new rule from template |
| `Register-ADScoutRule` | Add custom rule paths |
| `Export-ADScoutReport` | Output findings in various formats |
| `Get-ADScoutRemediation` | Get remediation scripts for findings |
| `Set-ADScoutConfig` | Configure module settings |
| `Get-ADScoutConfig` | Retrieve current configuration |
| `Show-ADScoutDashboard` | Interactive web dashboard (disk-backed) |

#### SIEM Integrations

| Function | Purpose |
|----------|---------|
| `Export-ADScoutElasticsearch` | Send results to Elasticsearch/OpenSearch |
| `Export-ADScoutSplunk` | Send results to Splunk HEC |
| `Export-ADScoutSentinel` | Send results to Azure Sentinel |
| `New-ADScoutSentinelAnalyticsRule` | Generate KQL for Sentinel alerts |

#### Engagement Management

| Function | Purpose |
|----------|---------|
| `New-ADScoutEngagement` | Create named assessment context |
| `Get-ADScoutEngagement` | List/retrieve engagements |
| `Set-ADScoutEngagement` | Update engagement metadata |
| `Remove-ADScoutEngagement` | Delete or archive engagement |
| `Invoke-ADScoutEngagementScan` | Run scan within engagement |
| `Get-ADScoutEngagementScans` | View engagement scan history |

#### Exception Management

| Function | Purpose |
|----------|---------|
| `New-ADScoutException` | Create finding exception |
| `Get-ADScoutException` | List/retrieve exceptions |
| `Set-ADScoutException` | Update exception status |
| `Remove-ADScoutException` | Delete or revoke exception |
| `Test-ADScoutException` | Check if finding is exempted |
| `Get-ADScoutExceptionReport` | Generate exception report |

### Data Flow

```
1. User calls Invoke-ADScoutScan
          │
          ▼
2. Load applicable rules (by category, ID, or all)
          │
          ▼
3. Collect AD data via Collectors (cached)
          │
          ▼
4. Execute each rule's ScriptBlock with AD data
          │
          ▼
5. Aggregate findings with scores and metadata
          │
          ▼
6. Output via specified Reporter (or pipeline)
```

## Collectors

Collectors gather data from Active Directory with these priorities:

1. **ActiveDirectory module** (if available)
2. **DirectorySearcher** (.NET fallback)
3. **ADSI** (legacy fallback)

### Collector Pattern

```powershell
function Get-ADScoutUserData {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase,
        [string[]]$Properties = @('*')
    )

    # Check cache first
    $cacheKey = "Users:$Domain"
    if ($cached = Get-ADScoutCache -Key $cacheKey) {
        return $cached
    }

    # Try AD module
    if (Get-Module -ListAvailable ActiveDirectory) {
        $params = @{
            Filter = '*'
            Properties = $Properties
        }
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }
        if ($SearchBase) { $params.SearchBase = $SearchBase }

        $users = Get-ADUser @params
    }
    else {
        # Fallback to DirectorySearcher
        $users = Get-ADScoutUserDataFallback @PSBoundParameters
    }

    # Normalize and cache
    $normalized = $users | ConvertTo-ADScoutUser
    Set-ADScoutCache -Key $cacheKey -Value $normalized

    return $normalized
}
```

### Available Collectors

| Collector | Data Type |
|-----------|-----------|
| `Get-ADScoutUserData` | User accounts |
| `Get-ADScoutComputerData` | Computer accounts |
| `Get-ADScoutGroupData` | Groups and membership |
| `Get-ADScoutTrustData` | Domain trusts |
| `Get-ADScoutGPOData` | Group Policy Objects |
| `Get-ADScoutCertificateData` | PKI certificates |

## Statistics

Statistical helper functions for frequency-based anomaly detection. These functions calculate metrics used by Anomaly rules to identify outliers.

### Statistical Functions

| Function | Purpose |
|----------|---------|
| `Get-ADScoutStatistics` | Calculate mean, stddev, quartiles, IQR for a dataset |
| `Get-ADScoutZScore` | Calculate Z-scores and identify outliers |
| `Get-ADScoutIQROutliers` | Identify outliers using Interquartile Range method |
| `Get-ADScoutPeerBaseline` | Group objects by OU for peer comparison |

### Get-ADScoutStatistics

Returns comprehensive statistics for a numeric dataset:

```powershell
$stats = Get-ADScoutStatistics -Values @(1, 2, 3, 4, 5, 100)

# Returns:
@{
    Count    = 6
    Mean     = 19.17
    Median   = 3.5
    StdDev   = 38.89
    Min      = 1
    Max      = 100
    Q1       = 2        # 25th percentile
    Q3       = 5        # 75th percentile
    IQR      = 3        # Interquartile range (Q3 - Q1)
}
```

### Get-ADScoutZScore

Calculates Z-scores and filters outliers:

```powershell
# Get all users with group membership Z-score > 2
$groupCounts = $ADData.Users | ForEach-Object { @($_.MemberOf).Count }
$outliers = Get-ADScoutZScore -Values $groupCounts -Threshold 2.0

# Returns objects where Z-score exceeds threshold
```

### Get-ADScoutIQROutliers

More robust outlier detection for skewed distributions:

```powershell
# IQR method: outlier if value > Q3 + (1.5 * IQR)
$outliers = Get-ADScoutIQROutliers -Values $groupCounts -Multiplier 1.5
```

### Usage in Rules

```powershell
# Example: A-ExcessiveGroupMembership rule
ScriptBlock = {
    param($ADData)

    $userGroups = $ADData.Users | ForEach-Object {
        @{ User = $_; GroupCount = @($_.MemberOf).Count }
    }

    $stats = Get-ADScoutStatistics -Values ($userGroups.GroupCount)

    $userGroups | Where-Object {
        $zscore = ($_.GroupCount - $stats.Mean) / $stats.StdDev
        $zscore -gt 2.0
    } | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.User.SamAccountName
            GroupCount     = $_.GroupCount
            ZScore         = [math]::Round($zscore, 2)
            EnvironmentMean = [math]::Round($stats.Mean, 1)
        }
    }
}
```

## Rule Engine

### Rule Definition

Rules are PowerShell hashtables with this structure:

```powershell
@{
    # === IDENTITY ===
    Id          = "S-PwdNeverExpires"        # Unique identifier
    Name        = "Password Never Expires"   # Human-readable name
    Category    = "StaleObjects"             # Rule category
    Model       = "AccountPolicy"            # Subcategory
    Version     = "1.0.0"                    # Rule version

    # === SCORING ===
    Computation = "PerDiscover"              # Scoring method
    Points      = 1                          # Points per finding
    MaxPoints   = 100                        # Maximum total points
    Threshold   = $null                      # For threshold-based rules

    # === FRAMEWORK MAPPINGS ===
    MITRE       = @("T1078.002")             # ATT&CK techniques
    CIS         = @("5.1.2")                 # CIS control IDs
    STIG        = @()                        # STIG IDs
    ANSSI       = @()                        # ANSSI recommendations

    # === THE CHECK ===
    ScriptBlock = {
        param([hashtable]$ADData)
        # Return objects that violate this rule
        $ADData.Users | Where-Object { ... }
    }

    # === OUTPUT ===
    DetailProperties = @("SamAccountName", "DistinguishedName")
    DetailFormat     = "{SamAccountName}"

    # === REMEDIATION ===
    Remediation = {
        param($Finding)
        "Set-ADUser -Identity $($Finding.SamAccountName) -PasswordNeverExpires `$false"
    }

    # === DOCUMENTATION ===
    Description          = "Brief description"
    TechnicalExplanation = "Detailed explanation"
    References           = @("https://...")

    # === PREREQUISITES ===
    Prerequisites = { param($ADData) $true }
    AppliesTo     = @("OnPremises", "Hybrid")
}
```

### Scoring Computation Types

| Type | Behavior |
|------|----------|
| `TriggerOnPresence` | Award `Points` if any findings exist |
| `PerDiscover` | Award `Points` for each finding, up to `MaxPoints` |
| `TriggerOnThreshold` | Award `Points` if count exceeds `Threshold` |
| `TriggerIfLessThan` | Award `Points` if count is below `Threshold` |

### Rule Loading

Rules are loaded from:
1. Built-in rules: `$PSScriptRoot/Rules/**/*.ps1`
2. User rules: Paths registered via `Register-ADScoutRule`
3. Session rules: Paths from `$env:ADSCOUT_RULE_PATHS`

Order determines precedence (later overrides earlier for same ID).

## Reporters

Reporters transform findings into output formats:

```powershell
# Reporter interface
@{
    Name      = "HTMLReporter"
    Extension = ".html"
    MimeType  = "text/html"

    Export = {
        param(
            [ADScoutResult[]]$Results,
            [string]$Path,
            [hashtable]$Options
        )
        # Generate and save/return HTML
    }
}
```

### Built-in Reporters

| Reporter | Output | Use Case |
|----------|--------|----------|
| `ConsoleReporter` | Terminal | Real-time feedback |
| `HTMLReporter` | .html file | Management reporting |
| `JSONReporter` | .json file | Automation/SIEM |
| `CSVReporter` | .csv file | Spreadsheet analysis |

## Compatibility Layer

### PowerShell Version Detection

```powershell
function Test-PSVersion {
    param([version]$MinimumVersion)
    $PSVersionTable.PSVersion -ge $MinimumVersion
}
```

### Parallel Execution

Tiered approach for parallel execution:

1. **PowerShell 7+**: `ForEach-Object -Parallel`
2. **ThreadJob module**: `Start-ThreadJob`
3. **Runspace pools**: Custom implementation
4. **Sequential**: Fallback for all versions

```powershell
function Invoke-ADScoutParallel {
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$InputObject,
        [int]$ThrottleLimit = [Environment]::ProcessorCount
    )

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $InputObject | ForEach-Object -Parallel $ScriptBlock -ThrottleLimit $ThrottleLimit
    }
    elseif (Get-Module -ListAvailable ThreadJob) {
        # ThreadJob implementation
    }
    else {
        # Runspace or sequential fallback
    }
}
```

### CIM/WMI Abstraction

```powershell
function Get-CimOrWmi {
    param(
        [string]$ClassName,
        [string]$ComputerName,
        [PSCredential]$Credential
    )

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Get-CimInstance @PSBoundParameters
    }
    else {
        Get-WmiObject @PSBoundParameters
    }
}
```

## Caching

### Cache Structure

```powershell
$script:ADScoutCache = @{
    Data      = @{}  # Key-value store
    Timestamps = @{}  # Expiration tracking
}
```

### Cache Operations

```powershell
function Get-ADScoutCache {
    param([string]$Key)

    $timestamp = $script:ADScoutCache.Timestamps[$Key]
    if ($timestamp -and ((Get-Date) - $timestamp).TotalSeconds -lt $script:ADScoutConfig.CacheTTL) {
        return $script:ADScoutCache.Data[$Key]
    }
    return $null
}

function Set-ADScoutCache {
    param([string]$Key, [object]$Value)

    $script:ADScoutCache.Data[$Key] = $Value
    $script:ADScoutCache.Timestamps[$Key] = Get-Date
}
```

## Configuration

### Default Configuration

```powershell
$script:ADScoutConfig = @{
    ParallelThrottleLimit = [Environment]::ProcessorCount
    DefaultReporter       = 'Console'
    RulePaths            = @()
    CacheTTL             = 300  # seconds
    LogLevel             = 'Warning'
}
```

### Configuration Persistence

Configuration can be persisted to:
- User scope: `~/.adscout/config.json`
- Machine scope: `/etc/adscout/config.json` or `$env:ProgramData\ADScout\config.json`

## Logging

### Log Levels

| Level | Stream | Use |
|-------|--------|-----|
| Error | Error | Failures that stop execution |
| Warning | Warning | Issues that allow continuation |
| Info | Information | Progress and status |
| Verbose | Verbose | Detailed operation info |
| Debug | Debug | Developer diagnostics |

### Logging Helper

```powershell
function Write-ADScoutLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')]
        [string]$Level = 'Info',

        [object]$Context
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formatted = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Error'   { Write-Error $formatted }
        'Warning' { Write-Warning $formatted }
        'Info'    { Write-Information $formatted -InformationAction Continue }
        'Verbose' { Write-Verbose $formatted }
        'Debug'   { Write-Debug $formatted }
    }
}
```

## Testing Strategy

### Unit Tests

- Mock AD dependencies
- Test each function in isolation
- Cover edge cases and error conditions

### Integration Tests

- Require AD environment (or mock server)
- Test end-to-end workflows
- Validate reporter output

### Rule Tests

- Each rule has dedicated test file
- Test ScriptBlock with mock data
- Validate scoring calculations

### Test Structure

```
tests/
├── Unit/
│   ├── Public/
│   │   ├── Invoke-ADScoutScan.Tests.ps1
│   │   └── Get-ADScoutRule.Tests.ps1
│   └── Private/
│       ├── Collectors/
│       └── Helpers/
├── Integration/
│   └── FullScan.Tests.ps1
├── Rules/
│   └── S-PwdNeverExpires.Tests.ps1
└── ADScout.Tests.ps1  # Main entry point
```

## Performance Considerations

1. **Lazy loading**: Load rules only when needed
2. **Caching**: Avoid redundant AD queries
3. **Parallel execution**: Use available cores
4. **Streaming**: Pipeline support for large datasets
5. **Selective properties**: Request only needed AD attributes

## Session Persistence (Disk-First Architecture)

### Design Rationale

AD-Scout uses a **disk-first, memory-cached** architecture for session data. This design choice addresses several operational requirements:

| Problem | Solution |
|---------|----------|
| Large AD queries are expensive | Query once, persist to disk, serve from cache |
| Scans can be interrupted | Resume from last saved state |
| Process crashes lose data | Disk persistence survives restarts |
| Multiple dashboards need same data | Shared disk storage, memory sync |

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Disk-First Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Scan Executes                                              │
│         │                                                        │
│         ▼                                                        │
│   2. Results → DISK (immediately)                               │
│         │     ~/.adscout/sessions/{session-id}/                 │
│         │       ├── results.json    ← Full scan results         │
│         │       ├── state.json      ← Status, timestamps        │
│         │       └── progress.json   ← Resume checkpoint         │
│         │                                                        │
│         ▼                                                        │
│   3. Memory Cache ← Load from disk                              │
│         │                                                        │
│         ▼                                                        │
│   4. API Serves from Memory (fast reads)                        │
│         │                                                        │
│         ▼                                                        │
│   5. Periodic Sync: if disk newer → reload memory               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Not Memory-First?

Memory-first approaches (query AD → store in memory → optionally save) have drawbacks:

1. **Data loss on crash**: All results lost if process terminates
2. **No resume capability**: Must restart entire scan from beginning
3. **Single-process limitation**: Can't share between dashboard instances
4. **Expensive re-queries**: Must re-run AD queries after restart

### Session Management Functions

| Function | Purpose |
|----------|---------|
| `Get-ADScoutSessionPath` | Creates/retrieves session storage directory |
| `Save-ADScoutSessionState` | Persists results and progress to disk |
| `Get-ADScoutSessionState` | Loads session state from disk |
| `Get-ADScoutLatestSession` | Finds most recent session for resume |
| `Sync-ADScoutDashboardFromDisk` | Reloads memory if disk is newer |

### Session Storage Structure

```
~/.adscout/sessions/
├── 20240104-143022/              # Session ID (timestamp-based)
│   ├── results.json              # Full scan results
│   ├── state.json                # { Status, LastUpdated, ResultCount }
│   └── progress.json             # Resume checkpoint for partial scans
├── 20240103-091500/
│   └── ...
└── ...

# Engagement-scoped sessions
~/.adscout/engagements/{engagement-id}/sessions/
├── 20240104-143022/
│   └── ...
```

### Resume Capability

When a dashboard starts without results:

```powershell
# Check for existing session
$latestSession = Get-ADScoutLatestSession -EngagementId $EngagementId

if ($latestSession) {
    # Load from disk instead of running new scan
    $Results = (Get-ADScoutSessionState -SessionPath $latestSession.Path).Results
    Write-Host "Resuming from session: $($latestSession.SessionId)"
}
```

### Multi-Process Synchronization

The dashboard checks if disk data is newer than memory on each API request:

```powershell
function Sync-ADScoutDashboardFromDisk {
    $diskTime = (Get-Item $resultsFile).LastWriteTime

    if ($diskTime -gt $script:DashboardResultsTimestamp) {
        # Another process updated the file - reload
        $script:DashboardResults = Get-Content $resultsFile | ConvertFrom-Json
        $script:DashboardResultsTimestamp = $diskTime
    }
}
```

This enables scenarios like:
- Running a scan from CLI while dashboard is open
- Multiple team members viewing same engagement data
- Background scheduled scans updating dashboard automatically

## SIEM Integrations

### Reporters

| Reporter | Target | Format |
|----------|--------|--------|
| `Export-ADScoutElasticsearch` | Elasticsearch/OpenSearch | NDJSON with optional ECS |
| `Export-ADScoutSplunk` | Splunk HEC | JSON with optional CIM |
| `Export-ADScoutSentinel` | Azure Log Analytics | Data Collector API |

### Export Flow

```
Results → Transform to target schema → Batch → Send via API
            │
            ├── ECS (Elastic Common Schema)
            ├── CIM (Splunk Common Information Model)
            └── Custom (Log Analytics)
```

## Engagement Management

Engagements provide persistent assessment contexts:

```
~/.adscout/engagements/{engagement-id}/
├── engagement.json       # Metadata, status, tags
├── sessions/             # Scan sessions (disk-first storage)
├── baselines/            # Baseline snapshots
│   └── current.json
├── exceptions/           # Engagement-scoped exceptions
└── reports/              # Generated reports
```

### Engagement Lifecycle

```
New-ADScoutEngagement → Invoke-ADScoutEngagementScan → Set-ADScoutEngagement -Status Completed
         │                        │
         ▼                        ▼
    Creates folder           Saves to engagement/sessions/
    structure                with baseline comparison
```

## Exception Management

Exceptions suppress specific findings with audit trails:

### Exception Types

| Type | Scope |
|------|-------|
| Rule | All findings for a rule ID |
| Object | Specific AD objects (by SamAccountName/DN) |
| Category | All rules in a category |

### Exception Storage

```json
{
  "Id": "abc12345",
  "Type": "Object",
  "RuleId": "S-PwdNeverExpires",
  "ObjectIdentity": ["svc_backup", "svc_monitoring"],
  "Justification": "Service accounts managed by CyberArk",
  "ApprovedBy": "security@contoso.com",
  "ExpirationDate": "2025-01-04T00:00:00Z",
  "TicketReference": "CHG0012345",
  "AuditLog": [
    { "Action": "Created", "Timestamp": "...", "User": "..." },
    { "Action": "Modified", "Timestamp": "...", "Changes": [...] }
  ]
}
```

## Security Considerations

1. **No credential storage**: Use secure credential methods
2. **Least privilege**: Document minimum required permissions
3. **Output security**: Reports contain sensitive data
4. **Input validation**: Validate all user inputs
5. **Dependency minimization**: Reduce attack surface
6. **Session data protection**: Results contain sensitive AD information
7. **Exception audit trails**: All changes are logged with user/timestamp
