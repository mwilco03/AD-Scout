---
name: New Rule Proposal
about: Propose a new security detection rule
title: '[RULE] '
labels: 'rule, enhancement'
assignees: ''
---

## Rule Name
A short, descriptive name for the rule.

## Rule ID
Proposed rule ID (format: `X-RuleName` where X is category prefix)
- A = Anomalies
- S = StaleObjects
- P = PrivilegedAccounts
- T = Trusts

## Category
- [ ] Anomalies
- [ ] StaleObjects
- [ ] PrivilegedAccounts
- [ ] Trusts

## Description
Brief description of what this rule detects.

## Security Implications
Why is this a security concern? What could an attacker do?

## Detection Logic
How should the rule identify this condition?

```powershell
# Pseudo-code or example logic
$ADData.Users | Where-Object {
    # Your condition
}
```

## Framework Mappings
- **MITRE ATT&CK**: (e.g., T1078.002)
- **CIS Controls**: (e.g., 5.1.2)
- **STIG**: (e.g., V-63337)

## Remediation
How should administrators fix findings?

```powershell
# Example remediation commands
```

## References
- Link to relevant documentation
- Link to security research
- Link to official guidance

## Testing
How can this rule be tested?

## Checklist
- [ ] I have searched existing rules for overlap
- [ ] This rule has clear security value
- [ ] I can provide test cases
- [ ] I'm willing to help implement this rule
