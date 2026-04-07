#!/bin/bash
# Pre-commit hook: blocks commits when unresolved CRITICAL vulnerabilities exist.
# Install: copy to .claude/hooks/pre-commit-security.sh in your project.
# Activate: add to .claude/settings.json (see plugin README).

SECURITY_DIR="docs/security"

# No reports yet → nothing to check, allow commit
LATEST_REPORT=$(ls -t "$SECURITY_DIR"/*-security-report.md 2>/dev/null | head -1)
if [ -z "$LATEST_REPORT" ]; then
  exit 0
fi

# Count CRITICAL vulnerabilities in the report
CRITICAL_COUNT=$(grep -oP '(?<=\*\*CRITICAL:\*\* )\d+' "$LATEST_REPORT" 2>/dev/null | head -1)
CRITICAL_COUNT="${CRITICAL_COUNT:-0}"

# No criticals → allow commit
if [ "$CRITICAL_COUNT" -eq 0 ]; then
  exit 0
fi

# Check if all criticals are covered by accepted risks in the latest fix plan
LATEST_PLAN=$(ls -t "$SECURITY_DIR"/*-fix-plan.md 2>/dev/null | head -1)
if [ -n "$LATEST_PLAN" ]; then
  # Count CRITICAL entries in Accepted Risks section
  ACCEPTED_CRITICAL_COUNT=$(awk '/^## Accepted Risks/,0' "$LATEST_PLAN" | grep -c '^\### \[CRITICAL\]' || echo 0)
  if [ "$ACCEPTED_CRITICAL_COUNT" -ge "$CRITICAL_COUNT" ]; then
    exit 0
  fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         security-checker: COMMIT BLOCKED                ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  %d CRITICAL vulnerability/ies are unresolved.             ║\n" "$CRITICAL_COUNT"
echo "║                                                          ║"
echo "║  To proceed:                                             ║"
echo "║  1. Run /check-security to see the latest findings.      ║"
echo "║  2. Run /write-plan to create or update your fix plan.   ║"
echo "║     (You can mark vulnerabilities as accepted risk.)     ║"
echo "║  3. Run /execute-plan to apply fixes.                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
exit 1
