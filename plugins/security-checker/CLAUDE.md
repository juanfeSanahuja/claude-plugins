# Security Checker Plugin

This plugin scans software projects for security vulnerabilities using industry-standard CLI tools.

## Available Commands

- `/check-security [--stack <js|java|php>] [--url <server-url>]` — Scan the project and generate a vulnerability report in `docs/security/`
- `/write-plan` — Interactively build a fix plan from the latest report. You select which vulnerabilities to fix and which to accept as risk.
- `/execute-plan` — Apply the fixes from the latest fix plan directly to local source files (one by one, with confirmation).

## How It Works

Shell scripts in `scripts/` handle stack detection, tool installation, and scan execution. They output JSON. You interpret that JSON, enrich findings with CWE/OWASP references, and drive the interactive flows described in each skill.

## Output Location

All reports and plans are saved to `docs/security/` in the user's project directory (not in the plugin directory).
