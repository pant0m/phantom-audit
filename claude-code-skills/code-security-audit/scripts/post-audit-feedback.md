# Phase 6: Post-Audit Feedback Collection

After delivering the audit report, collect user feedback to improve future audits.

## Step 1: Present Findings for Review

For each finding, ask:
- **Confirmed**: This is a real vulnerability → Add to confirmed-patterns.md
- **False Positive**: This is not actually vulnerable → Add to false-positives.md with reason
- **Needs More Info**: Unable to determine without more context → Keep in gray list

## Step 2: Update Knowledge Base

### On CONFIRMED finding:
```
skill_manage(action='patch', name='code-security-audit',
  target_file='references/confirmed-patterns.md',
  append: """
### [PATTERN-XXX] Description
- **Language**: detected_language
- **CWE**: finding_cwe
- **Detection**: grep_or_semgrep_pattern_that_found_it
- **Context**: When this pattern is dangerous
- **Source**: Confirmed in audit of [project] on [date]
""")
```

### On FALSE POSITIVE:
```
memory(action='add', content="""
FP: [description of false positive pattern]
Why safe: [user's explanation]
Conditions: [when this exclusion applies]
Project: [project name], Date: [date]
""")
```

Also append to `references/false-positives.md`.

### On NEW FRAMEWORK KNOWLEDGE:
If the audit revealed framework-specific insights not in fingerprints:
```
Append to references/framework-fingerprints.md:
  - New known risk for this framework/version
  - New common misconfiguration pattern
  - Auth model specifics
```

## Step 3: Save Audit Trajectory

Record audit statistics for trend analysis:
- Project name and tech stack
- Total findings by severity
- False positive rate
- Categories covered vs applicable
- Tools used and their contribution (how many findings from Semgrep vs LLM-only)
- Time spent per phase

## Step 4: Update Scan Priorities

Based on accumulated data, adjust future Agent resource allocation:
- If Java projects consistently have 70% SQLi + Auth findings → allocate more Agents to those categories
- If Python projects rarely have XXE → reduce priority for that category
