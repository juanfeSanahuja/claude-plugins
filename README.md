# juanfeSanahuja Claude Plugins

Private plugin marketplace for Claude Code.

## Add this marketplace

Run once in Claude Code:

```
/plugin marketplace add juanfeSanahuja/claude-plugins
```

## Available plugins

### security-checker

Scan JS/Node, Java and PHP/MySQL projects for security vulnerabilities. Generates structured reports and fix plans.

**Install:**
```
/plugin install security-checker
```

**Commands:**
- `/check-security` — Scan current project for vulnerabilities
- `/write-plan` — Generate a fix plan from the latest report
- `/execute-plan` — Apply fixes interactively

**Requirements:** semgrep, npm (JS), OWASP Dependency-Check (Java), phpcs (PHP), Docker/nikto (web scan)

See [plugins/security-checker/README.md](plugins/security-checker/README.md) for full documentation.
