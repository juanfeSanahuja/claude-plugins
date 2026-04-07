# Execute Plan Skill

Apply fixes from the latest fix plan to local source files, one at a time with user confirmation.

## Trigger

Invoked by the `/execute-plan` command.

## Steps

### 1. Find the latest fix plan

```bash
ls -t docs/security/*-fix-plan.md 2>/dev/null | head -1
```

If no file is found, tell the user:
> "No fix plan found. Run `/write-plan` first."
Then stop.

Read the file content.

### 2. Extract fixes

Parse all items under `## Fixes`. For each fix, extract:
- `file` (path relative to project root)
- `line` (line number from the original report)
- The "Current code" block
- The "Suggested fix" block
- Severity and message

Skip the `## Accepted Risks` section entirely.

### 3. Apply fixes one by one

For each fix:

**a)** Display:
```
── Fix <index>/<total> ──────────────────────────────
[SEVERITY] <message> — <file>:<line>

Current code:
  <current code block>

Suggested fix:
  <suggested fix block>

Apply this fix? [y/n/skip all remaining]
>
```

**b)** Wait for user response:

- `y` — determine if this is a local code fix or a server/web fix:
  - **Local fix** (file exists on disk): use the Edit tool to apply the change. Find the current code in the file and replace it with the suggested fix. If the exact text is not found, warn the user:
    > "Could not locate the exact code in `<file>`. The file may have changed since the scan. Please apply this fix manually."
  - **Server/web fix** (source is `nikto`, file is a URL path): display:
    > "This is a server configuration change. Apply it manually on your server. Here is what to change: [show suggested fix again]"

- `n` — skip this fix silently and move to the next.

- `skip all remaining` — stop processing further fixes and go to the summary.

### 4. Print summary

```
Execute plan complete.
  ✓ Applied:  X fixes
  ✗ Skipped: Y fixes
  ⚠ Manual:  Z fixes (server/web — apply on server)

Run /check-security again to verify the fixes resolved the vulnerabilities.
```
