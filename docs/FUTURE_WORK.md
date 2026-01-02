# AD-Scout Future Work Specifications

This document contains detailed specifications for future features, organized as self-contained prompts. Each section can be used as a standalone implementation request.

---

## Table of Contents

1. [Deployment Mode Configuration](#prompt-1-deployment-mode-configuration)
2. [Elasticsearch/OpenSearch Integration](#prompt-2-elasticsearchopensearch-integration)
3. [Engagement Mode](#prompt-3-engagement-mode)
4. [Exception and Suppression Management](#prompt-4-exception-and-suppression-management)
5. [Delta/Incremental Scanning](#prompt-5-deltaincremental-scanning)
6. [Additional SIEM Integrations](#prompt-6-additional-siem-integrations)

---

## Prompt 1: Deployment Mode Configuration

### Context

This is part of the AD-Scout project, a PowerShell-native Active Directory security assessment framework. The tool currently supports generating static reports and running an interactive web dashboard, but lacks a unified configuration system for different deployment scenarios.

### Goal

Implement a configuration layer that allows users to select and persist their preferred deployment mode. The configuration should be cross-platform and support three primary modes:

1. **Session (One-and-Done)**: Run assessment, generate reports, exit. No persistence.
2. **Dashboard**: Local web dashboard with baseline tracking and history.
3. **SIEM Export**: Send findings to external platforms (Elasticsearch, Splunk, etc.)

### Implementation Requirements

#### Config Location
- Path: `$HOME/.adscout/config.json`
- Cross-platform compatible (Windows, Linux, macOS)
- Created on first run or via `Initialize-ADScout`

#### Config Schema
```json
{
  "version": "1.0",
  "deploymentMode": "Session | Dashboard | SIEM",
  "dashboard": {
    "defaultPort": 8080,
    "autoRefresh": false,
    "refreshInterval": 60
  },
  "siem": {
    "type": "Elasticsearch | Splunk | Sentinel | Webhook",
    "url": null,
    "index": "adscout-findings",
    "apiKey": null,
    "verifySsl": true
  },
  "defaults": {
    "baselinePath": null,
    "historyPath": null,
    "outputFormat": "Console"
  }
}
```

#### Commands to Implement

**Initialize-ADScout**
```powershell
function Initialize-ADScout {
    <#
    .SYNOPSIS
        Configures AD-Scout deployment mode and settings.

    .DESCRIPTION
        Interactive or parameter-driven setup for AD-Scout configuration.
        Creates config file at $HOME/.adscout/config.json

    .PARAMETER Mode
        Deployment mode: Session, Dashboard, or SIEM

    .PARAMETER SIEMType
        For SIEM mode: Elasticsearch, Splunk, Sentinel, Webhook

    .PARAMETER SIEMUrl
        SIEM endpoint URL

    .PARAMETER Interactive
        Run interactive setup wizard

    .EXAMPLE
        Initialize-ADScout -Interactive
        # Prompts user through setup wizard

    .EXAMPLE
        Initialize-ADScout -Mode SIEM -SIEMType Elasticsearch -SIEMUrl "https://elastic:9200"
        # Non-interactive configuration
    #>
}
```

**Get-ADScoutConfig** (enhance existing)
- Add deployment mode to output
- Show SIEM configuration if applicable

**Set-ADScoutConfig** (enhance existing)
- Add `-DeploymentMode` parameter
- Add `-SIEMType`, `-SIEMUrl`, `-SIEMApiKey` parameters

### Validations

- [ ] Config file created at correct cross-platform path
- [ ] Interactive mode prompts for all required settings
- [ ] Parameter mode skips prompts when values provided
- [ ] Config persists between sessions
- [ ] `Get-ADScoutConfig` displays current settings
- [ ] Invalid SIEM URL rejected with helpful error
- [ ] Config migration path for future schema changes (version field)

### Complete Looks Like

1. User runs `Initialize-ADScout -Interactive`
2. Wizard asks: "Select deployment mode: [1] Session [2] Dashboard [3] SIEM"
3. If SIEM selected, prompts for type and URL
4. Config saved to `$HOME/.adscout/config.json`
5. Subsequent `Invoke-ADScoutScan` uses configured mode
6. `Get-ADScoutConfig` shows current deployment mode and settings

---

## Prompt 2: Elasticsearch/OpenSearch Integration

### Context

This is part of the AD-Scout project. Organizations using Elasticsearch or OpenSearch for security monitoring need AD-Scout findings ingested into their existing SIEM infrastructure. This enables correlation with other security data and centralized alerting.

### Goal

Implement native Elasticsearch/OpenSearch export capability with:
- NDJSON output format compatible with Elasticsearch Bulk API
- Direct HTTP push to Elasticsearch clusters
- ECS (Elastic Common Schema) compatible field mappings where applicable
- Support for API key and basic authentication

### Implementation Requirements

#### NDJSON Export Format

Each finding becomes one JSON document per line:
```json
{"index":{"_index":"adscout-findings"}}
{"@timestamp":"2026-01-02T12:00:00Z","rule.id":"S-PwdNeverExpires","rule.name":"Password Never Expires","event.category":"configuration","event.type":"indicator","event.severity":3,"host.domain":"contoso.com","adscout.category":"StaleObjects","adscout.score":42,"adscout.finding_count":15,"adscout.mitre":["T1078.002"],"adscout.cis":["5.1.2"],"adscout.nist":["IA-5(1)"],"adscout.description":"User accounts with passwords that never expire"}
```

#### Field Mapping (ECS-aligned)

| AD-Scout Field | ECS Field | Notes |
|----------------|-----------|-------|
| ScanTime | @timestamp | ISO 8601 |
| RuleId | rule.id | |
| RuleName | rule.name | |
| Category | adscout.category | Custom namespace |
| Score | adscout.score | Numeric |
| FindingCount | adscout.finding_count | |
| Severity | event.severity | 1-4 scale |
| MITRE | threat.technique.id | Array |
| Description | rule.description | |
| Domain | host.domain | |

#### Commands to Implement

**Export-ADScoutReport -Format NDJSON**
```powershell
# Add NDJSON format to existing Export-ADScoutReport
Invoke-ADScoutScan | Export-ADScoutReport -Format NDJSON -Path ./findings.ndjson

# Options:
# -Index "adscout-findings"  # Include index metadata for bulk API
# -IncludeFindings           # Expand individual affected objects (verbose)
```

**Send-ADScoutToElastic**
```powershell
function Send-ADScoutToElastic {
    <#
    .SYNOPSIS
        Sends AD-Scout findings directly to Elasticsearch.

    .PARAMETER Results
        ADScoutResult objects from Invoke-ADScoutScan

    .PARAMETER Url
        Elasticsearch URL (e.g., https://elastic.corp:9200)

    .PARAMETER Index
        Target index name (default: adscout-findings-YYYY.MM.DD)

    .PARAMETER ApiKey
        Elasticsearch API key for authentication

    .PARAMETER Credential
        PSCredential for basic auth (alternative to ApiKey)

    .PARAMETER SkipCertificateCheck
        Skip SSL certificate validation (not recommended for production)

    .EXAMPLE
        $results = Invoke-ADScoutScan
        $results | Send-ADScoutToElastic -Url "https://elastic:9200" -ApiKey $key

    .EXAMPLE
        # Using configured SIEM settings
        Invoke-ADScoutScan | Send-ADScoutToElastic
    #>
}
```

#### Index Template (for users to apply to Elasticsearch)

Provide `adscout-index-template.json`:
```json
{
  "index_patterns": ["adscout-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "rule.id": { "type": "keyword" },
        "rule.name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "adscout.category": { "type": "keyword" },
        "adscout.score": { "type": "integer" },
        "adscout.finding_count": { "type": "integer" },
        "adscout.mitre": { "type": "keyword" },
        "adscout.cis": { "type": "keyword" },
        "adscout.nist": { "type": "keyword" },
        "event.severity": { "type": "integer" },
        "host.domain": { "type": "keyword" }
      }
    }
  }
}
```

### Validations

- [ ] NDJSON output valid for Elasticsearch Bulk API
- [ ] `Send-ADScoutToElastic` successfully indexes documents
- [ ] API key authentication works
- [ ] Basic auth (credential) works
- [ ] Uses config file settings when parameters not provided
- [ ] Date-based index naming works (adscout-findings-2026.01.02)
- [ ] Handles connection errors gracefully with retry logic
- [ ] SSL certificate validation can be skipped (with warning)
- [ ] Works with both Elasticsearch and OpenSearch

### Complete Looks Like

1. User configures: `Initialize-ADScout -Mode SIEM -SIEMType Elasticsearch -SIEMUrl "https://elastic:9200"`
2. User runs: `Invoke-ADScoutScan | Send-ADScoutToElastic -ApiKey $key`
3. Findings appear in Elasticsearch index `adscout-findings-2026.01.02`
4. User can query: `GET /adscout-*/_search?q=adscout.category:StaleObjects`
5. Kibana dashboards can visualize findings over time

---

## Prompt 3: Engagement Mode

### Context

This is part of the AD-Scout project. Security assessments often span multiple days or weeks (penetration tests, remediation tracking, compliance audits). Users need to maintain context between scan sessions, track progress over time, and maintain environment-specific configurations.

### Goal

Implement an "engagement" concept that provides:
- Named, persistent assessment contexts
- Automatic baseline and history tracking per engagement
- Environment-specific settings and exceptions
- Ability to switch between engagements

### Implementation Requirements

#### Engagement Structure
```
$HOME/.adscout/
├── config.json                    # Global config
└── engagements/
    └── contoso-2026-Q1/
        ├── engagement.json        # Engagement metadata
        ├── baseline.json          # Initial baseline (auto-saved on first scan)
        ├── history.json           # All scan summaries
        ├── exceptions.json        # Suppressed findings (see Prompt 4)
        └── scans/
            ├── 2026-01-02T09-00-00.json  # Individual scan results
            └── 2026-01-03T14-30-00.json
```

#### Engagement Metadata Schema
```json
{
  "name": "contoso-2026-Q1",
  "displayName": "Contoso Q1 2026 Assessment",
  "created": "2026-01-02T09:00:00Z",
  "domain": "contoso.com",
  "description": "Quarterly security assessment",
  "contact": "security@contoso.com",
  "status": "active",
  "settings": {
    "categories": ["All"],
    "excludedRules": [],
    "scanInterval": null
  }
}
```

#### Commands to Implement

**New-ADScoutEngagement**
```powershell
function New-ADScoutEngagement {
    <#
    .SYNOPSIS
        Creates a new assessment engagement.

    .PARAMETER Name
        Unique engagement identifier (used for folder name)

    .PARAMETER DisplayName
        Human-readable name

    .PARAMETER Domain
        Target domain for this engagement

    .PARAMETER Description
        Optional description

    .EXAMPLE
        New-ADScoutEngagement -Name "contoso-q1" -DisplayName "Contoso Q1 Assessment" -Domain "contoso.com"
    #>
}
```

**Get-ADScoutEngagement**
```powershell
# List all engagements
Get-ADScoutEngagement

# Get specific engagement
Get-ADScoutEngagement -Name "contoso-q1"

# Get current/active engagement
Get-ADScoutEngagement -Current
```

**Set-ADScoutEngagement**
```powershell
# Switch to an engagement (makes it "current")
Set-ADScoutEngagement -Name "contoso-q1"

# Clear current engagement (back to session mode)
Set-ADScoutEngagement -None
```

**Remove-ADScoutEngagement**
```powershell
Remove-ADScoutEngagement -Name "contoso-q1" -Confirm
```

#### Integration with Existing Commands

When an engagement is active:
- `Invoke-ADScoutScan` automatically saves results to engagement folder
- `Save-ADScoutBaseline` saves to engagement's baseline.json
- `Update-ADScoutHistory` appends to engagement's history.json
- `Show-ADScoutDashboard` uses engagement's baseline for comparison

### Validations

- [ ] `New-ADScoutEngagement` creates folder structure correctly
- [ ] `Set-ADScoutEngagement` persists current engagement in config
- [ ] `Invoke-ADScoutScan` saves to engagement when one is active
- [ ] Baseline auto-created on first scan if not exists
- [ ] History appended on each scan
- [ ] `Get-ADScoutEngagement` lists all with status
- [ ] Dashboard shows engagement name and context
- [ ] Can switch between engagements without data loss
- [ ] `Remove-ADScoutEngagement` requires confirmation

### Complete Looks Like

1. User starts engagement: `New-ADScoutEngagement -Name "acme-audit" -Domain "acme.corp"`
2. User activates: `Set-ADScoutEngagement -Name "acme-audit"`
3. User runs scans: `Invoke-ADScoutScan` (auto-saves to engagement)
4. Days later, user returns: `Set-ADScoutEngagement -Name "acme-audit"`
5. Dashboard shows: "Engagement: ACME Audit | Scan 5 of 5 | Baseline: Jan 2"
6. User sees trend across all 5 scans in that engagement

---

## Prompt 4: Exception and Suppression Management

### Context

This is part of the AD-Scout project. In real-world assessments, not all findings are actionable:
- Some are false positives
- Some are accepted risks with compensating controls
- Some are not applicable to the specific environment
- Some are already in remediation

Users need the ability to suppress/shelve findings so they don't count against the security score, while maintaining an audit trail of these decisions.

### Goal

Implement an exception management system that:
- Allows suppressing specific rule findings
- Requires justification and approval metadata
- Supports expiration (temporary suppression)
- Adjusts scoring to reflect exceptions
- Provides audit trail of all exception decisions

### Implementation Requirements

#### Exception Schema
```json
{
  "exceptions": [
    {
      "id": "exc-001",
      "ruleId": "S-PwdNeverExpires",
      "reason": "AcceptedRisk",
      "justification": "Service accounts with compensating controls (MFA, PAM)",
      "approvedBy": "ciso@contoso.com",
      "createdAt": "2026-01-02T10:00:00Z",
      "expiresAt": "2026-04-02T10:00:00Z",
      "scope": {
        "type": "specific",
        "objects": ["svc_backup", "svc_monitoring"]
      },
      "status": "active"
    }
  ]
}
```

#### Exception Reasons (Enum)
- `FalsePositive` - Detection is incorrect
- `AcceptedRisk` - Known risk, accepted by management
- `CompensatingControl` - Mitigated by other security measures
- `NotApplicable` - Rule doesn't apply to this environment
- `InRemediation` - Being fixed, suppress temporarily
- `Deferred` - Acknowledged, will address later

#### Scope Types
- `rule` - Suppress entire rule (all findings)
- `specific` - Suppress specific objects only (by SamAccountName, DN, etc.)
- `pattern` - Suppress matching pattern (e.g., all svc_* accounts)

#### Commands to Implement

**Add-ADScoutException**
```powershell
function Add-ADScoutException {
    <#
    .SYNOPSIS
        Suppresses a finding from scoring.

    .PARAMETER RuleId
        Rule to suppress

    .PARAMETER Reason
        Reason for exception (AcceptedRisk, FalsePositive, etc.)

    .PARAMETER Justification
        Detailed explanation

    .PARAMETER ApprovedBy
        Email or name of approver

    .PARAMETER ExpiresIn
        Days until exception expires (null = permanent)

    .PARAMETER Scope
        "Rule" (entire rule) or specific object names

    .EXAMPLE
        Add-ADScoutException -RuleId "S-PwdNeverExpires" `
            -Reason AcceptedRisk `
            -Justification "Service accounts with PAM controls" `
            -ApprovedBy "security@contoso.com" `
            -ExpiresIn 90 `
            -Scope "svc_backup", "svc_sql"
    #>
}
```

**Get-ADScoutException**
```powershell
# List all exceptions
Get-ADScoutException

# Filter by rule
Get-ADScoutException -RuleId "S-PwdNeverExpires"

# Show expired
Get-ADScoutException -IncludeExpired

# Show by reason
Get-ADScoutException -Reason AcceptedRisk
```

**Remove-ADScoutException**
```powershell
Remove-ADScoutException -Id "exc-001"
# or
Remove-ADScoutException -RuleId "S-PwdNeverExpires" -All
```

**Update-ADScoutException**
```powershell
# Extend expiration
Update-ADScoutException -Id "exc-001" -ExpiresIn 90

# Change reason
Update-ADScoutException -Id "exc-001" -Reason CompensatingControl
```

#### Scoring Integration

When exceptions are applied:
```
Original Score: 45 (15 rules triggered, 120 findings)
Exceptions: 2 rules suppressed (25 findings)
Adjusted Score: 52 (13 rules counted, 95 findings counted)

Dashboard Display:
┌─────────────────────────────────────┐
│  Score: 52  (7 points suppressed)   │
│  Grade: C                           │
│  Exceptions: 2 active               │
└─────────────────────────────────────┘
```

#### Dashboard Integration

- Show exception count in summary
- "Suppressed" badge on excepted rules in findings table
- Separate section showing active exceptions
- Warning for expiring-soon exceptions (< 7 days)

### Validations

- [ ] `Add-ADScoutException` creates exception with all metadata
- [ ] Exceptions persist in engagement or global config
- [ ] `Invoke-ADScoutScan` respects exceptions in scoring
- [ ] Specific-scope exceptions only suppress matching objects
- [ ] Pattern-scope exceptions match correctly
- [ ] Expired exceptions auto-deactivate
- [ ] Dashboard shows adjusted score with suppression note
- [ ] Audit trail maintained (who, when, why)
- [ ] `Get-ADScoutException` shows expiring-soon warnings
- [ ] Export includes exceptions metadata

### Complete Looks Like

1. User runs scan, sees 120 findings, score 45
2. User adds exception: `Add-ADScoutException -RuleId "S-PwdNeverExpires" -Reason AcceptedRisk -Justification "..." -ApprovedBy "ciso@corp.com" -ExpiresIn 90`
3. Next scan shows: "Score: 52 (7 points suppressed)"
4. Dashboard shows: "2 active exceptions, 1 expiring in 12 days"
5. `Get-ADScoutException` lists all with status and expiry
6. After 90 days, exception expires, score returns to original calculation

---

## Prompt 5: Delta/Incremental Scanning

### Context

This is part of the AD-Scout project. For ongoing monitoring (Model 2 and 3 deployments), sending all findings on every scan is inefficient and noisy. Users need the ability to identify only what changed since the last scan or baseline.

### Goal

Implement delta scanning capability that:
- Compares current scan to baseline or previous scan
- Identifies new, resolved, and unchanged findings
- Supports "only send changes" mode for SIEM integration
- Reduces noise in continuous monitoring scenarios

### Implementation Requirements

#### Delta Modes
- `Full` - Send all findings (default, current behavior)
- `Delta` - Send only new and resolved since baseline
- `NewOnly` - Send only new findings (ignore resolved)
- `ChangesOnly` - Send new, resolved, and changed (score/count changed)

#### Delta Result Schema
```json
{
  "scanTime": "2026-01-03T10:00:00Z",
  "comparedTo": "baseline",
  "comparedToTime": "2026-01-02T09:00:00Z",
  "summary": {
    "new": 5,
    "resolved": 3,
    "unchanged": 112,
    "changed": 2
  },
  "new": [
    { "ruleId": "P-NewAdmin", "findingCount": 2, "score": 15 }
  ],
  "resolved": [
    { "ruleId": "S-DisabledWithPwd", "previousCount": 8 }
  ],
  "changed": [
    { "ruleId": "S-PwdNeverExpires", "previousCount": 15, "currentCount": 18 }
  ]
}
```

#### Command Changes

**Invoke-ADScoutScan**
```powershell
# Add -DeltaMode parameter
Invoke-ADScoutScan -DeltaMode Delta -Baseline ./baseline.json

# Compare to previous scan instead of baseline
Invoke-ADScoutScan -DeltaMode Delta -CompareTo Previous
```

**Export-ADScoutReport**
```powershell
# Export only delta
$results = Invoke-ADScoutScan -DeltaMode Delta
$results | Export-ADScoutReport -Format JSON -DeltaOnly
```

**Send-ADScoutToElastic**
```powershell
# Send only new findings (reduce SIEM noise)
Invoke-ADScoutScan -DeltaMode NewOnly | Send-ADScoutToElastic

# Send with delta metadata (event.action: created/deleted)
Invoke-ADScoutScan -DeltaMode Delta | Send-ADScoutToElastic -IncludeDeltaMetadata
```

#### SIEM Event Types (for delta mode)

| Delta Status | ECS event.action | Description |
|--------------|------------------|-------------|
| New | `created` | Finding appeared since baseline |
| Resolved | `deleted` | Finding no longer present |
| Changed | `modified` | Count or score changed |
| Unchanged | (not sent in delta mode) | |

### Validations

- [ ] Delta mode correctly identifies new findings
- [ ] Delta mode correctly identifies resolved findings
- [ ] Delta mode detects count/score changes
- [ ] `-CompareTo Previous` uses last scan in history
- [ ] `-CompareTo Baseline` uses baseline file
- [ ] Delta export includes comparison metadata
- [ ] SIEM export sets correct event.action values
- [ ] NewOnly mode excludes resolved findings
- [ ] Full mode still works as default

### Complete Looks Like

1. Day 1: `Invoke-ADScoutScan | Save-ADScoutBaseline` (120 findings)
2. Day 2: `Invoke-ADScoutScan -DeltaMode Delta`
   - Output: "5 new, 3 resolved, 2 changed, 110 unchanged"
3. SIEM receives 10 events (5 new + 3 resolved + 2 changed) instead of 117
4. Dashboard shows: "Score: 48 (+3 since baseline)"
5. Technician view highlights new findings with "NEW" badge

---

## Prompt 6: Additional SIEM Integrations

### Context

This is part of the AD-Scout project. While Elasticsearch is the priority, enterprises use various SIEM platforms. Future integrations should follow the same pattern established by Elasticsearch.

### Goal

Implement additional SIEM integrations following the established pattern:
- Splunk (HTTP Event Collector)
- Azure Sentinel (Log Analytics)
- Generic Webhook (for custom integrations)
- Windows Event Log (for WEC/WEF scenarios)

### Implementation Requirements

#### Splunk HEC

```powershell
function Send-ADScoutToSplunk {
    <#
    .PARAMETER HecUrl
        Splunk HEC endpoint (https://splunk:8088/services/collector)

    .PARAMETER Token
        HEC token

    .PARAMETER Index
        Target index (default: main)

    .PARAMETER SourceType
        Splunk sourcetype (default: adscout:finding)
    #>
}
```

Splunk CIM mapping:
- `src` = Domain
- `signature_id` = RuleId
- `signature` = RuleName
- `severity` = Severity mapping
- `category` = Category

#### Azure Sentinel

```powershell
function Send-ADScoutToSentinel {
    <#
    .PARAMETER WorkspaceId
        Log Analytics Workspace ID

    .PARAMETER SharedKey
        Primary or secondary key

    .PARAMETER LogType
        Custom log type name (default: ADScout)
    #>
}

# Uses Log Analytics Data Collector API
# Creates ADScout_CL custom table
```

#### Generic Webhook

```powershell
function Send-ADScoutWebhook {
    <#
    .PARAMETER Url
        Webhook endpoint

    .PARAMETER Method
        HTTP method (default: POST)

    .PARAMETER Headers
        Additional headers (hashtable)

    .PARAMETER Format
        Payload format: JSON, NDJSON, Form

    .PARAMETER BatchSize
        Findings per request (default: 100)
    #>
}
```

#### Windows Event Log

```powershell
function Write-ADScoutEventLog {
    <#
    .PARAMETER LogName
        Event log name (default: Application, or custom "AD-Scout")

    .PARAMETER Source
        Event source (default: ADScout)

    .PARAMETER EventIdBase
        Base event ID (findings = base+severity)
    #>
}

# Event IDs:
# 1000 = Scan started
# 1001 = Scan completed (summary)
# 2001 = Critical finding
# 2002 = High finding
# 2003 = Medium finding
# 2004 = Low finding
# 3000 = Error
```

### Validations

Each integration should:
- [ ] Authenticate correctly
- [ ] Format payload for target platform
- [ ] Handle rate limiting
- [ ] Retry on transient failures
- [ ] Log errors appropriately
- [ ] Support delta mode
- [ ] Use configured settings from `config.json`

### Complete Looks Like

All SIEM integrations work uniformly:
```powershell
# Configure once
Initialize-ADScout -Mode SIEM -SIEMType Splunk -SIEMUrl "https://splunk:8088"

# Use interchangeably
Invoke-ADScoutScan | Send-ADScoutToSplunk
Invoke-ADScoutScan | Send-ADScoutToSentinel
Invoke-ADScoutScan | Send-ADScoutWebhook -Url "https://custom.api/ingest"
Invoke-ADScoutScan | Write-ADScoutEventLog
```

---

## Implementation Priority

| Prompt | Priority | Dependency | Effort |
|--------|----------|------------|--------|
| 1. Deployment Mode Config | High | None | Medium |
| 2. Elasticsearch Integration | High | Prompt 1 | Medium |
| 3. Engagement Mode | Medium | Prompt 1 | High |
| 4. Exception Management | Medium | Prompt 3 | High |
| 5. Delta Scanning | Medium | Prompt 3 | Medium |
| 6. Additional SIEM | Low | Prompt 2 | Medium each |

## Notes

- Each prompt is designed to be self-contained for implementation
- Prompts build on each other but can be partially implemented
- Schema versions allow for future migration
- All features should maintain backward compatibility with existing usage
