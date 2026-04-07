#!/bin/bash
# Scans a JS/Node project using npm audit + semgrep.
# Usage: ./scan-js.sh [project-dir]
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
  SEMGREP_OUT=$(semgrep --config "p/javascript" --json "$PROJECT_DIR" 2>/dev/null || echo '{"results":[],"errors":[]}')
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
    cwe_esc=$(escape_json "$cwe")
    owasp_esc=$(escape_json "$owasp")
    FINDINGS+=("{\"id\": \"$check_id\", \"severity\": \"$severity\", \"message\": \"$message_esc\", \"file\": \"$path\", \"line\": $line, \"code_snippet\": \"$code_esc\", \"cwe\": \"$cwe_esc\", \"owasp\": \"$owasp_esc\", \"source\": \"semgrep\"}")
  done < <(echo "$SEMGREP_OUT" | python3 -c "import sys,json; [print(json.dumps(r)) for r in json.load(sys.stdin).get('results',[])]" 2>/dev/null)
fi

# --- npm audit ---
if command -v npm &>/dev/null && [ -f "$PROJECT_DIR/package.json" ]; then
  pushd "$PROJECT_DIR" > /dev/null 2>&1
  NPM_OUT=$(npm audit --json 2>/dev/null || echo '{"vulnerabilities":{}}')
  popd > /dev/null 2>&1

  map_npm_severity() {
    case "$1" in
      critical) echo "CRITICAL" ;;
      high)     echo "HIGH" ;;
      moderate) echo "MEDIUM" ;;
      low)      echo "LOW" ;;
      *)        echo "LOW" ;;
    esac
  }

  while IFS= read -r vuln; do
    name=$(echo "$vuln" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','unknown'))" 2>/dev/null || echo "unknown")
    severity_raw=$(echo "$vuln" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('severity','low'))" 2>/dev/null || echo "low")
    title=$(echo "$vuln" | python3 -c "import sys,json; d=json.load(sys.stdin); via=d.get('via',[]); print(via[0].get('title','Vulnerability') if via and isinstance(via[0],dict) else d.get('name','Vulnerability'))" 2>/dev/null || echo "Vulnerability")
    cwe=$(echo "$vuln" | python3 -c "import sys,json; d=json.load(sys.stdin); via=d.get('via',[]); cwe=via[0].get('cwe',[]) if via and isinstance(via[0],dict) else []; print(cwe[0] if cwe else '')" 2>/dev/null || echo "")
    range=$(echo "$vuln" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('range','unknown'))" 2>/dev/null || echo "unknown")
    severity=$(map_npm_severity "$severity_raw")
    title_esc=$(escape_json "$title")
    cwe_esc=$(escape_json "$cwe")
    FINDINGS+=("{\"id\": \"npm-$name\", \"severity\": \"$severity\", \"message\": \"Vulnerable dependency: $name ($range) — $title_esc\", \"file\": \"package.json\", \"line\": 0, \"code_snippet\": \"\", \"cwe\": \"$cwe_esc\", \"owasp\": \"\", \"source\": \"npm-audit\"}")
  done < <(echo "$NPM_OUT" | python3 -c "import sys,json; [print(json.dumps(v)) for v in json.load(sys.stdin).get('vulnerabilities',{}).values()]" 2>/dev/null)
fi

# Build output JSON
FINDINGS_JSON=""
for i in "${!FINDINGS[@]}"; do
  [ $i -gt 0 ] && FINDINGS_JSON+=", "
  FINDINGS_JSON+="${FINDINGS[$i]}"
done

echo "{\"stack\": \"js\", \"findings\": [$FINDINGS_JSON]}"
