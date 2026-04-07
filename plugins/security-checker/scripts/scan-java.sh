#!/bin/bash
# Scans a Java project using semgrep + OWASP Dependency-Check.
# Usage: ./scan-java.sh [project-dir]
# Output: standardized JSON findings

set -uo pipefail

PROJECT_DIR="${1:-.}"
FINDINGS=()

map_semgrep_severity() {
  case "$1" in
    ERROR)   echo "CRITICAL" ;;
    WARNING) echo "HIGH" ;;
    INFO)    echo "MEDIUM" ;;
    *)       echo "LOW" ;;
  esac
}

escape_json() {
  printf '%s' "$1" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null | sed 's/^"//;s/"$//'
}

# --- semgrep ---
if command -v semgrep &>/dev/null; then
  SEMGREP_OUT=$(semgrep --config "p/java" --json "$PROJECT_DIR" 2>/dev/null || echo '{"results":[],"errors":[]}')
  while IFS= read -r finding; do
    check_id=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('check_id','unknown'))" 2>/dev/null || echo "unknown")
    path=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('path','unknown'))" 2>/dev/null || echo "unknown")
    line=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('start',{}).get('line',0))" 2>/dev/null || echo "0")
    severity_raw=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('extra',{}).get('severity','INFO'))" 2>/dev/null || echo "INFO")
    message=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('extra',{}).get('message',''))" 2>/dev/null || echo "")
    code=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('extra',{}).get('lines',''))" 2>/dev/null || echo "")
    cwe=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); cwe=d.get('extra',{}).get('metadata',{}).get('cwe',[]); print(cwe[0] if cwe else '')" 2>/dev/null || echo "")
    owasp=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); o=d.get('extra',{}).get('metadata',{}).get('owasp',[]); print(o[0] if o else '')" 2>/dev/null || echo "")
    severity=$(map_semgrep_severity "$severity_raw")
    message_esc=$(escape_json "$message")
    code_esc=$(escape_json "$code")
    FINDINGS+=("{\"id\": \"$check_id\", \"severity\": \"$severity\", \"message\": \"$message_esc\", \"file\": \"$path\", \"line\": $line, \"code_snippet\": \"$code_esc\", \"cwe\": \"$cwe\", \"owasp\": \"$owasp\", \"source\": \"semgrep\"}")
  done < <(echo "$SEMGREP_OUT" | python3 -c "import sys,json; [print(json.dumps(r)) for r in json.load(sys.stdin).get('results',[])]" 2>/dev/null)
fi

# --- OWASP Dependency-Check ---
DC_BIN="$HOME/.owasp-dependency-check/bin/dependency-check.sh"
if [ -x "$DC_BIN" ]; then
  REPORT_DIR=$(mktemp -d)
  "$DC_BIN" --project "security-scan" --scan "$PROJECT_DIR" --out "$REPORT_DIR" --format JSON --noupdate 2>/dev/null || true
  REPORT_FILE="$REPORT_DIR/dependency-check-report.json"
  if [ -f "$REPORT_FILE" ]; then
    while IFS= read -r vuln_line; do
      dep=$(echo "$vuln_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dep',''))" 2>/dev/null || echo "")
      name=$(echo "$vuln_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','CVE-unknown'))" 2>/dev/null || echo "CVE-unknown")
      severity=$(echo "$vuln_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('severity','HIGH').upper())" 2>/dev/null || echo "HIGH")
      description=$(echo "$vuln_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('description',''))" 2>/dev/null || echo "")
      cwe=$(echo "$vuln_line" | python3 -c "import sys,json; d=json.load(sys.stdin); cwes=d.get('cwes',[]); print(cwes[0] if cwes else '')" 2>/dev/null || echo "")
      description_esc=$(escape_json "$description")
      dep_esc=$(escape_json "$dep")
      FINDINGS+=("{\"id\": \"$name\", \"severity\": \"$severity\", \"message\": \"$description_esc\", \"file\": \"$dep_esc\", \"line\": 0, \"code_snippet\": \"\", \"cwe\": \"$cwe\", \"owasp\": \"\", \"source\": \"owasp-dc\"}")
    done < <(python3 - "$REPORT_FILE" << 'PY'
import sys, json
with open(sys.argv[1]) as f:
    data = json.load(f)
for dep in data.get("dependencies", []):
    fname = dep.get("fileName", "unknown")
    for vuln in dep.get("vulnerabilities", []):
        vuln["dep"] = fname
        print(json.dumps(vuln))
PY
    )
  fi
  rm -rf "$REPORT_DIR"
fi

FINDINGS_JSON=""
for i in "${!FINDINGS[@]}"; do
  [ $i -gt 0 ] && FINDINGS_JSON+=", "
  FINDINGS_JSON+="${FINDINGS[$i]}"
done

echo "{\"stack\": \"java\", \"findings\": [$FINDINGS_JSON]}"
