# Phase 3.5: Coverage Verification Protocol

After ALL Phase 3 Agents complete, the main session executes this coverage check.

## Step 1: Collect Agent Coverage Declarations

Each Agent MUST return a coverage table in this format:
```
| Category | Status | Files Scanned | Findings | Reason |
|----------|--------|---------------|----------|--------|
| SQLi     | DONE   | 23            | 2        |        |
| CMDi     | DONE   | 15            | 0        |        |
| SSTI     | N/A    | 0             | -        | No template engine detected |
```

Status values: DONE, PARTIAL, SKIPPED, N/A

## Step 2: Build Coverage Matrix

Merge all Agent declarations against the Phase 1 applicability matrix:

```
Category          | Applicable | Agent Covered | Status
─────────────────────────────────────────────────────
1. SQLi           | YES        | Agent 1       | DONE ✅
2. Auth           | YES        | Agent 2       | DONE ✅
3. Data Exposure  | YES        | Agent 2       | DONE ✅
...
16. Log Injection | YES        | ???           | MISSING ❌
17. Mass Assign   | YES        | ???           | MISSING ❌
...
```

## Step 3: Identify Gaps

```
GAPS = [category for category in applicable_categories 
        if category.status not in ("DONE", "N/A")]
```

## Step 4: Auto-remediate Gaps

If GAPS is not empty:
1. Launch a supplementary Agent targeting ONLY the missing categories
2. Agent prompt includes: "You are responsible for categories: [gap_list]. Other categories are already covered."
3. Wait for completion
4. Re-run coverage check (max 2 rounds to prevent infinite loops)

## Step 5: Final Coverage Report

```markdown
## Audit Coverage Summary
- Total categories: 22
- Applicable to this project: N
- Fully scanned: M
- Coverage rate: M/N (XX%)
- Categories marked N/A: [list with reasons]
- Categories with findings: [list]
- Categories clean: [list]
```

This report is included in the Phase 5 final audit report.
