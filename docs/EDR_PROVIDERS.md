# EDR Provider Integration Guide

> **Status**: LIVING - Updated as new providers are evaluated or API capabilities change.

## Overview

AD-Scout supports remote Active Directory reconnaissance through EDR (Endpoint Detection and Response) platforms and native Windows remoting. This document catalogs providers by their maturity, PowerShell library availability, and suitability for AD-Scout integration.

## Provider Maturity Assessment

### Tier 0: Native (No Agent Required)

Direct PowerShell Remoting - the most straightforward approach when you have network access and credentials.

| Provider | PowerShell Module | Documentation | Status |
|----------|-------------------|---------------|--------|
| PowerShell Remoting (WinRM) | Built-in | Excellent | ✅ Implemented |

### Tier 1: Production-Ready (Implemented)

These providers have mature, well-documented APIs with official or community-maintained PowerShell modules.

| Provider | PowerShell Module | API Documentation | Status |
|----------|-------------------|-------------------|--------|
| CrowdStrike Falcon | [PSFalcon](https://github.com/CrowdStrike/psfalcon) | Excellent | ✅ Implemented |
| Microsoft Defender for Endpoint | Microsoft.Graph.Security | Excellent | ✅ Implemented |

### Tier 2: Integration-Ready (Not Yet Implemented)

These providers have documented APIs and PowerShell capabilities but are not yet integrated into AD-Scout.

| Provider | PowerShell Module | API Documentation | Status |
|----------|-------------------|-------------------|--------|
| SentinelOne | [SentinelOne PowerShell](https://github.com/SentinelOne/s1-api) | Good | 🔄 Candidate |
| VMware Carbon Black | [CarbonBlack PS](https://developer.carbonblack.com/) | Good | 🔄 Candidate |
| Palo Alto Cortex XDR | REST API + Custom | Good | 🔄 Candidate |

### Tier 3: Limited API Support

These providers have APIs but lack mature PowerShell integration or have significant limitations.

| Provider | PowerShell Module | API Documentation | Notes |
|----------|-------------------|-------------------|-------|
| Sophos | REST API only | Moderate | No official PS module |
| Trend Micro Vision One | REST API only | Moderate | Limited remote execution |
| Cybereason | REST API only | Limited | Session-based complexity |
| Elastic Security | REST API only | Good | Query-focused, limited execution |

---

## Tier 0 Provider (Native)

### PowerShell Remoting (WinRM)

**Module**: Built-in (no installation required)

PowerShell Remoting is the native Windows remote execution capability. It's the most direct approach when you have network access and valid credentials - no EDR agent required.

#### When to Use PSRemoting

| Scenario | PSRemoting | EDR Provider |
|----------|------------|--------------|
| Direct network access to DCs | ✅ Best choice | Works |
| No EDR agent deployed | ✅ Only option | ❌ Not available |
| Air-gapped environments | ✅ Works | ❌ Usually not |
| MSSP multi-tenant | ⚠️ Credential management | ✅ Safer |
| Internet-only access | ❌ Rarely exposed | ✅ Designed for this |

#### API Maturity Indicators
- ✅ Built into Windows (no installation)
- ✅ Comprehensive Microsoft documentation
- ✅ Native PowerShell integration
- ✅ Multiple authentication options
- ✅ Supports all PowerShell capabilities
- ✅ No agent required on targets

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote PowerShell Execution | Full | Native `Invoke-Command` |
| Host Discovery | Full | Via AD queries |
| Domain Controller Detection | Full | AD + OU filtering |
| Batch Operations | Full | ThrottleLimit parameter |
| Authentication | Full | Kerberos, NTLM, CredSSP |
| Session Persistence | Full | `New-PSSession` |

#### Constraints & Limits
```
Max connections per host: 25 (configurable)
Max shells per user: 5 (configurable)
Max memory per shell: 150MB (default)
Idle timeout: 2 hours (configurable)
Operation timeout: 60 seconds (default)
```

#### Prerequisites
```powershell
# On target hosts (usually already enabled on servers):
Enable-PSRemoting -Force

# Firewall requirements:
# - TCP 5985 (HTTP) or TCP 5986 (HTTPS)

# For non-domain scenarios, may need:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "targethost"
```

#### Authentication Options

| Method | Use Case | Security |
|--------|----------|----------|
| Kerberos | Domain environments | ✅ Most secure |
| Negotiate | Auto-select best | ✅ Recommended |
| NTLM | Non-domain/fallback | ⚠️ Acceptable |
| CredSSP | Double-hop scenarios | ⚠️ Requires setup |
| Basic | HTTPS only | ❌ Avoid if possible |

#### Usage
```powershell
# Connect with current user (domain environment)
Connect-ADScoutEDR -Provider PSRemoting

# Connect with explicit credentials
$cred = Get-Credential
Connect-ADScoutEDR -Provider PSRemoting -Credential $cred

# Connect with Kerberos to specific domain
Connect-ADScoutEDR -Provider PSRemoting -Credential $cred `
    -Domain 'contoso.com' -DomainController 'DC01.contoso.com'

# Use SSL (port 5986)
Connect-ADScoutEDR -Provider PSRemoting -Credential $cred -UseSSL

# Execute reconnaissance
Invoke-ADScoutEDRCommand -Template 'AD-FullRecon' -TargetHost 'DC01'
```

#### Documentation
- WinRM Overview: https://docs.microsoft.com/en-us/windows/win32/winrm/portal
- PowerShell Remoting: https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands
- Security Considerations: https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity

---

## Tier 1 Providers (Implemented)

### CrowdStrike Falcon

**Module**: [PSFalcon](https://github.com/CrowdStrike/psfalcon)

PSFalcon is the official CrowdStrike PowerShell module, actively maintained by CrowdStrike with comprehensive API coverage.

#### API Maturity Indicators
- ✅ Official vendor-maintained module
- ✅ Active development (regular releases)
- ✅ Comprehensive documentation
- ✅ Real Time Response (RTR) for remote execution
- ✅ Batch operations (up to 10,000 hosts)
- ✅ MSSP multi-tenant support

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote PowerShell Execution | Full | Via RTR `runscript` |
| Host Discovery | Full | Filter by OS, domain, tags |
| Domain Controller Detection | Full | OS filter + role detection |
| Batch Operations | Full | 10,000 hosts per batch |
| MSSP Multi-CID | Full | `MemberCid` parameter |
| Session Management | Full | 500 concurrent sessions |

#### Rate Limits
```
Max concurrent RTR sessions: 500 per CID
Batch host limit: 10,000 per request
API rate limit: 6,000 requests/minute per CID
Session timeout: 10 minutes (idle)
Script size limit: 4MB
Command timeout: 600 seconds
```

#### Installation
```powershell
Install-Module PSFalcon -Scope CurrentUser
```

#### Required API Scopes
- `Real Time Response (Read)`
- `Real Time Response (Write)`
- `Real Time Response (Admin)` - for `runscript`
- `Hosts (Read)` - for host discovery

#### Documentation
- GitHub: https://github.com/CrowdStrike/psfalcon
- API Docs: https://falcon.crowdstrike.com/documentation
- RTR Guide: https://falcon.crowdstrike.com/documentation/page/d3c84a1b/real-time-response-apis

---

### Microsoft Defender for Endpoint (MDE)

**Module**: Microsoft.Graph.Security (via Microsoft Graph API)

Microsoft Defender for Endpoint provides Live Response capabilities through the Microsoft Security Center API, integrated with Microsoft Graph.

#### API Maturity Indicators
- ✅ Official Microsoft APIs
- ✅ Microsoft Graph integration
- ✅ Comprehensive documentation
- ✅ Live Response for remote execution
- ✅ Advanced Hunting (KQL queries)
- ⚠️ Lower concurrency limit than Falcon

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote PowerShell Execution | Full | Via Live Response |
| Host Discovery | Full | Machine API |
| Domain Controller Detection | Full | Via machine properties |
| Batch Operations | Limited | 25 concurrent sessions |
| Multi-Tenant (MSSP) | Full | Via Azure Lighthouse |
| Advanced Hunting | Full | KQL queries |

#### Rate Limits
```
Max concurrent Live Response sessions: 25 (HARD LIMIT)
Max queued sessions: 10 additional
API rate limit: 100 requests/minute per app
Session timeout: 30 minutes (idle)
Script size limit: 8MB
Response size limit: 3MB per output
```

#### Installation
```powershell
# Option 1: Microsoft Graph SDK
Install-Module Microsoft.Graph.Security -Scope CurrentUser

# Option 2: Direct API (no additional modules required)
# AD-Scout uses direct REST calls with managed tokens
```

#### Required API Permissions
- `Machine.Read.All`
- `Machine.LiveResponse`
- `AdvancedQuery.Read.All` (for Advanced Hunting)

#### Licensing Requirements
- Microsoft Defender for Endpoint Plan 2 (E5)
- Or standalone MDE P2 license
- "Advanced" Live Response requires additional licensing

#### Documentation
- API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-reference
- Live Response: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/live-response-api
- Advanced Hunting: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-api

---

## Tier 2 Providers (Candidates)

### SentinelOne

**Status**: Integration Candidate

SentinelOne provides a comprehensive REST API with PowerShell scripting support through their Remote Shell feature.

#### API Maturity Indicators
- ✅ Well-documented REST API
- ✅ Remote Shell capability
- ⚠️ Community PowerShell modules (not official)
- ✅ Multi-tenant console support

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote PowerShell Execution | Full | Remote Shell feature |
| Host Discovery | Full | Agent API |
| Batch Operations | Full | Site/Group filtering |
| Multi-Tenant | Full | Multi-site architecture |

#### Rate Limits
```
API rate limit: 1,000 requests/minute (varies by endpoint)
Remote Shell timeout: Configurable
Max concurrent shells: Varies by license tier
```

#### PowerShell Resources
- Community Module: https://github.com/SentinelOne/s1-api
- API Documentation: https://usea1-partners.sentinelone.net/api-doc/

#### Required Permissions
- Endpoints > Remote Shell
- Endpoints > View
- Account > API Token Generation

---

### VMware Carbon Black

**Status**: Integration Candidate

Carbon Black Cloud provides Live Response capabilities with REST API access.

#### API Maturity Indicators
- ✅ Documented REST API
- ✅ Live Response/Live Query
- ⚠️ Limited PowerShell tooling
- ✅ OSQuery integration for queries

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote Command Execution | Full | Live Response |
| Host Discovery | Full | Device API |
| Live Query (OSQuery) | Full | Cross-platform queries |
| Batch Operations | Moderate | API-based batching |

#### Rate Limits
```
API rate limit: Varies by endpoint type
Live Response sessions: 10 concurrent per org (default)
Session timeout: 4 hours
```

#### PowerShell Resources
- Developer Portal: https://developer.carbonblack.com/
- API Reference: https://developer.carbonblack.com/reference/carbon-black-cloud/

---

### Palo Alto Cortex XDR

**Status**: Integration Candidate

Cortex XDR provides script execution capabilities through its API.

#### API Maturity Indicators
- ✅ REST API with good documentation
- ✅ Script execution support
- ⚠️ No official PowerShell module
- ✅ Investigation and response APIs

#### Key Capabilities
| Feature | Support Level | Notes |
|---------|---------------|-------|
| Remote Script Execution | Full | Response actions API |
| Host Discovery | Full | Endpoint API |
| Incident Context | Full | Useful for targeted collection |

#### Rate Limits
```
API rate limit: 500 requests/minute
Script execution: Queue-based
```

#### Resources
- API Documentation: https://cortex.paloaltonetworks.com/developer

---

## Tier 3 Providers (Limited)

### Sophos Central

**Limitations**: No remote execution API. Query and management only.

- Host inventory available
- No Live Response equivalent
- Would require agent-side scheduled tasks

### Trend Micro Vision One

**Limitations**: Limited remote execution capabilities.

- Investigation APIs available
- Response actions limited
- No arbitrary script execution

### Cybereason

**Limitations**: Complex session management, limited documentation.

- Sensor-based execution possible
- Session complexity makes automation difficult
- API documentation requires vendor engagement

### Elastic Security

**Limitations**: Query-focused, no remote execution.

- Excellent for data already in Elastic
- Osquery integration for queries
- No direct remote command execution
- Would require agent-side Elastic Agent actions

---

## Provider Selection Guide

### Decision Matrix

| Requirement | PSRemoting | CrowdStrike | MDE | SentinelOne | Carbon Black |
|-------------|------------|-------------|-----|-------------|--------------|
| No agent required | ✅ Native | ❌ Agent | ❌ Agent | ❌ Agent | ❌ Agent |
| High concurrency (100+ hosts) | ✅ Good | ✅ Best | ⚠️ 25 limit | ✅ Good | ⚠️ Limited |
| Network access required | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| MSSP multi-tenant | ⚠️ Creds | ✅ Native | ✅ Azure | ✅ Multi-site | ⚠️ Complex |
| PowerShell tooling | ✅ Built-in | ✅ Official | ✅ Graph SDK | ⚠️ Community | ⚠️ Limited |
| AD recon templates | ✅ Full | ✅ Full | ✅ Full | 🔄 Planned | 🔄 Planned |
| License cost | Free | $$$ | $$$ (E5) | $$ | $$ |

### Recommendations

**Direct network access available**: Use PSRemoting provider. No agent or license required, fastest setup.

**Enterprise with CrowdStrike**: Use PSFalcon provider. Best concurrency and batch support.

**Microsoft 365 E5 customers**: Use DefenderATP provider. Leverages existing licensing.

**MSSP environments**: CrowdStrike PSFalcon with MemberCid for multi-tenant, or SentinelOne multi-site.

**Air-gapped or no EDR**: Use PSRemoting provider. Only requirement is WinRM access.

**Mixed environments**: AD-Scout supports multiple simultaneous connections. Use different session names per provider. Can combine PSRemoting + EDR providers.

---

## Contributing New Providers

To add a new EDR provider to AD-Scout:

1. **Evaluate API maturity** using this checklist:
   - [ ] Remote command/script execution capability
   - [ ] Host discovery and filtering API
   - [ ] Documented rate limits
   - [ ] Authentication mechanism (OAuth, API keys, certificates)
   - [ ] Batch operation support

2. **Create provider class** inheriting from `EDRProviderBase`:
   ```powershell
   class NewProvider : EDRProviderBase {
       # Implement required methods:
       # - Connect()
       # - Disconnect()
       # - TestConnection()
       # - ExecuteCommand()
       # - GetAvailableHosts()
       # - GetCommandStatus()
       # - GetCapabilities()
   }
   ```

3. **Document rate limits** in provider header comments

4. **Add to provider registry** in module loader

5. **Create integration tests** (mocked API responses)

6. **Update this document** with provider details

### Provider Template Location
`src/ADScout/Private/EDR/Providers/`

### Reference Implementation
See `PSFalconProvider.ps1` for a complete implementation example.

---

## API Documentation Links

### Implemented Providers
| Provider | Official Docs | PowerShell Module |
|----------|---------------|-------------------|
| PowerShell Remoting | [WinRM Docs](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands) | Built-in |
| CrowdStrike Falcon | [API Docs](https://falcon.crowdstrike.com/documentation) | [PSFalcon](https://github.com/CrowdStrike/psfalcon) |
| Microsoft Defender | [MDE API](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-reference) | [MS Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) |

### Candidate Providers
| Provider | Official Docs | Community Resources |
|----------|---------------|---------------------|
| SentinelOne | [API Docs](https://usea1-partners.sentinelone.net/api-doc/) | [s1-api](https://github.com/SentinelOne/s1-api) |
| Carbon Black | [Developer Portal](https://developer.carbonblack.com/) | - |
| Cortex XDR | [Cortex API](https://cortex.paloaltonetworks.com/developer) | - |

---

## Version History

| Date | Change |
|------|--------|
| 2024-01 | Initial documentation with Tier 1-3 assessment |
| 2024-01 | Added PSFalcon and DefenderATP implementation details |
| 2024-01 | Added Tier 0 PSRemoting provider (native WinRM support) |
