# False Positive Exclusion Rules

Patterns that LOOK like vulnerabilities but are actually safe. Each rule was verified by user rejection of an audit finding.

## How This File Works
- Entries added after Phase 6 feedback (user marks a finding as false positive)
- Each entry includes: the pattern, WHY it's safe, and applicability conditions
- During Phase 0, these rules are loaded to SKIP known false positives
- Reduces noise and saves audit time on subsequent runs

## Format
```
### [FP-ID] Short description
- **Pattern**: What triggers the false positive
- **Why safe**: Explanation of why this is not a vulnerability
- **Conditions**: When this exclusion applies (framework version, config, etc.)
- **Source**: First identified in audit of [project] on [date]
```

## Exclusion Rules

(This file will be populated as audits are completed and false positives identified)
