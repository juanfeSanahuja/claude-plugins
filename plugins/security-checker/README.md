# security-checker

A Claude Code plugin that scans your project for security vulnerabilities, generates a prioritized fix plan, and applies fixes directly to your source files.

## Features

- Scans **JS/Node**, **Java** and **PHP/MySQL** projects using industry-standard CLI tools
- Auto-detects your stack from project files (`package.json`, `pom.xml`, `composer.json`)
- Auto-installs any missing security tools
- Generates a structured vulnerability report with CWE/OWASP references
- Interactive fix plan: you choose which vulnerabilities to fix and which to accept as risk (with justification for audit traceability)
- Applies fixes directly to your local source files with per-fix confirmation
- Optional pre-commit hook that blocks commits when unresolved CRITICAL vulnerabilities exist
- Optional web server scan via nikto (`--url` flag)

## Installation

### From Claude Code (recommended)

```
/plugin install juanfeSanahuja/security-checker
```

### Manual

Clone the repository and copy it to your Claude Code plugins directory:

```bash
git clone https://github.com/juanfeSanahuja/security-checker.git
```

Then install from local path in Claude Code:
```
/plugin install ./security-checker
```

## Supported Stacks

| Stack | Tools used |
|-------|-----------|
| JS/Node | npm audit + semgrep (p/javascript) |
| Java | semgrep (p/java) + OWASP Dependency-Check |
| PHP/MySQL | semgrep (p/php) + phpcs + phpcs-security-audit |
| Web server (optional) | **OWASP ZAP** (spider + passive scan) + **nikto** (server-level) |

The web scan uses a **hybrid model**:
- **OWASP ZAP** crawls the site from the entry URL, follows all links within the same domain, and runs a passive security scan on every page discovered (XSS, injection, auth issues, insecure headers, CSRF, etc.). Runs via Docker.
- **Nikto** complements ZAP with server-level detection: outdated software versions, dangerous files, and server misconfigurations that ZAP doesn't cover.

Missing tools are installed automatically on first run. Docker is required for the web scan.

## Commands

### `/check-security`

Scans the current project and generates a vulnerability report.

```
/check-security [--stack <js|java|php>] [--url <server-url>]
```

**Options:**
- `--stack` — Override auto-detection. Use when the stack cannot be detected automatically.
- `--url` — Also scan a live web server with nikto (e.g. `--url http://localhost:8080`)

**Output:** `docs/security/YYYY-MM-DD-security-report.md`

**Example report:**
```
# Security Report — 2026-04-06

## Executive Summary
- CRITICAL: 2
- HIGH: 3
- MEDIUM: 1
- LOW: 1
- Detected stack: php
- Tools used: semgrep, phpcs

## Vulnerabilities

### [CRITICAL] SQL Injection — UserController.php:45
- CWE: CWE-89
- OWASP: A03:2021 - Injection
- Tool: semgrep
...
```

---

### `/write-plan`

Reads the latest security report and presents an interactive list of vulnerabilities. You select which ones to include in the fix plan — vulnerabilities you skip are recorded as **accepted risks** with an optional justification (useful for audits).

**Output:** `docs/security/YYYY-MM-DD-fix-plan.md`

**Example session:**
```
1. [CRITICAL] SQL Injection — UserController.php:45
   What: User input concatenated directly into SQL query
   Fix:  Use PDO prepared statements — no functional impact

2. [HIGH] XSS — CommentView.php:78
   What: User content rendered without HTML escaping
   Fix:  Apply htmlspecialchars() before output — no functional impact

Reply with the numbers to fix, separated by commas (e.g. 1,2):
> 1,2
```

---

### `/execute-plan`

Reads the latest fix plan and applies each fix to your local source files one by one, asking for confirmation before each change.

```
── Fix 1/2 ──────────────────────────────────
[CRITICAL] SQL Injection — UserController.php:45

Current code:
  $query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";

Suggested fix:
  $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
  $stmt->bind_param("s", $_POST['email']);
  $stmt->execute();

Apply this fix? [y/n/skip all remaining]
> y
✓ Applied — UserController.php updated
```

Server/web vulnerabilities (nikto findings) are shown as diffs only — you apply those manually on the server.

---

## Pre-commit Hook (optional)

Blocks commits when there are unresolved CRITICAL vulnerabilities in the latest report.

**Setup:**

1. Copy the hook to your project:
```bash
cp path/to/security-checker/hooks/pre-commit-security.sh .claude/hooks/pre-commit-security.sh
chmod +x .claude/hooks/pre-commit-security.sh
```

2. Add to `.claude/settings.json` in your project root:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/pre-commit-security.sh"
          }
        ]
      }
    ]
  }
}
```

**Behavior:**
- Passes silently if no report exists or CRITICAL count is 0
- Passes if all CRITICALs are recorded as accepted risks in the fix plan
- Blocks with a clear message if unresolved CRITICALs exist

---

## Typical Workflow

```
1. Open your project in Claude Code
2. Run /check-security
3. Review the report in docs/security/
4. Run /write-plan — select which vulnerabilities to fix
5. Run /execute-plan — apply fixes with confirmation
6. Run /check-security again to verify
```

---

## Requirements

- Claude Code (CLI or desktop app)
- Python 3 (used internally by scan scripts for JSON parsing)
- Internet access on first run (for auto-installing missing tools)
- **Docker** (required only for web scanning with OWASP ZAP)

The plugin auto-installs: `semgrep` (via pip), `phpcs` + `phpcs-security-audit` (via composer), `OWASP Dependency-Check` (via curl), `nikto` (via apt/brew), `owasp/zap2docker-stable` (via docker pull).

---

## Output Files

All output goes to `docs/security/` in your project directory:

| File | Description |
|------|-------------|
| `YYYY-MM-DD-security-report.md` | Full vulnerability report with CWE/OWASP references |
| `YYYY-MM-DD-fix-plan.md` | Prioritized fix plan with before/after code and accepted risks |

---

## License

MIT
