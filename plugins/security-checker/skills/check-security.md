# Check Security Skill

Scan the current project for security vulnerabilities and generate a structured report.

## Trigger

This skill is invoked by the `/check-security` command. Arguments passed to the command are passed here.

## Arguments

- `--stack <js|java|php>` (optional) — override auto-detection
- `--url <server-url>` (optional) — also run nikto against this URL

## Steps

### 1. Parse arguments

Extract `--stack` and `--url` from the command arguments if present.

### 2. Run detect-stack.sh

```bash
bash scripts/detect-stack.sh . [--stack <override-if-provided>]
```

Parse the JSON output. If `error` is present and no `--stack` was given, tell the user:
> "Could not auto-detect the stack. Please specify one with `--stack js`, `--stack java`, or `--stack php`."
Then stop.

### 3. Run install-tools.sh

```bash
bash scripts/install-tools.sh <stack1> [stack2] [web-if-url-provided]
```

Read the JSON output. For any tool with `"status": "failed"`, warn the user:
> "[tool] could not be installed: [reason]. This scan will be incomplete."

Do NOT stop — continue with available tools.

### 4. Run scan scripts

For each detected stack, run the corresponding script:

```bash
bash scripts/scan-js.sh .       # if js
bash scripts/scan-java.sh .     # if java
bash scripts/scan-php.sh .      # if php
bash scripts/scan-web.sh <url>  # if --url was provided
```

Collect all JSON outputs.

### 5. Process findings

From all JSON outputs, collect every object in `findings` arrays. Then:

1. **Deduplicate** — if two findings have the same `file` + `line` + `cwe`, keep the one with higher severity.
2. **Enrich** — for findings missing `cwe` or `owasp`, look up by `check_id` or `message` content and fill in if you can determine them with confidence. Do not guess.
3. **Sort** — CRITICAL first, then HIGH, MEDIUM, LOW.
4. **Count** per severity level.

### 6. Create output directory

```bash
mkdir -p docs/security
```

### 7. Write the report

Save to `docs/security/YYYY-MM-DD-security-report.md` (use today's date). Format:

```markdown
# Security Report — YYYY-MM-DD

## Executive Summary
- **CRITICAL:** X
- **HIGH:** X
- **MEDIUM:** X
- **LOW:** X
- **Detected stack:** js, php
- **Tools used:** semgrep, npm-audit, phpcs

## Vulnerabilities

### [CRITICAL] <message> — <file>:<line>
- **CWE:** <cwe or N/A>
- **OWASP:** <owasp or N/A>
- **Tool:** <source>
- **Description:** <message>
- **Code:**
  ```
  <code_snippet>
  ```

(repeat for each finding, sorted CRITICAL → HIGH → MEDIUM → LOW)
```

### 8. Confirm to the user

> "Scan complete. Found X vulnerabilities (Y CRITICAL, Z HIGH, ...).
> Report saved to `docs/security/YYYY-MM-DD-security-report.md`.
> Run `/write-plan` to generate a prioritized fix plan."
