# Write Plan Skill

Interactively generate a prioritized fix plan from the latest security report.

## Trigger

Invoked by the `/write-plan` command.

## Steps

### 1. Find the latest report

```bash
ls -t docs/security/*-security-report.md 2>/dev/null | head -1
```

If no file is found, tell the user:
> "No security report found. Run `/check-security` first."
Then stop.

Read the file content.

### 2. Parse and present the vulnerability list

Extract all vulnerabilities from the report. Present them as a numbered list. For each item show:

```
N. [SEVERITY] <message> — <file>:<line>
   What: <description of the vulnerability and its risk>
   Fix:  <what needs to change and any impact on functionality>
```

To determine the "Fix" description for each vulnerability, use your knowledge of the vulnerability type (SQL injection, XSS, etc.) to describe the idiomatic fix. Be specific to the code shown in `code_snippet`.

After the list:
> "Reply with the numbers of the vulnerabilities you want to fix, separated by commas (e.g. `1,3,5`).
> Vulnerabilities you don't include will be recorded as accepted risks."

### 3. Collect user selection

Wait for the user's response. Parse the comma-separated numbers.

If the user provides numbers outside the valid range, ask them to correct the input.

### 4. Collect justifications for accepted risks

For each vulnerability NOT in the user's selection:
> "You excluded [N]. [SEVERITY] [message] — optional justification? (press Enter to skip)"

Collect responses one at a time.

### 5. Generate the fix plan

For each selected vulnerability, generate:
- A description of the fix
- The specific code change needed (show the current code from `code_snippet` and the corrected version)
- The estimated functional impact

For each unselected vulnerability, record it as an accepted risk with the justification provided (or "No justification provided" if skipped).

### 6. Write the plan

Save to `docs/security/YYYY-MM-DD-fix-plan.md` (today's date). Format:

```markdown
# Fix Plan — YYYY-MM-DD
Generated from: `docs/security/<report-filename>`

## Fixes

### <index>. [SEVERITY] <message> — <file>:<line>
- **Fix:** <description of what to change>
- **Functional impact:** <None | describe impact>
- **Current code:**
  ```
  <code_snippet from report>
  ```
- **Suggested fix:**
  ```
  <corrected code>
  ```

## Accepted Risks

### [SEVERITY] <message> — <file>:<line>
- **Reason:** <justification or "No justification provided">
- **Decision recorded:** <today's date>
```

### 7. Confirm to the user

> "Fix plan saved to `docs/security/YYYY-MM-DD-fix-plan.md`.
> X fixes included, Y risks accepted.
> Run `/execute-plan` to apply the fixes to your source files."
