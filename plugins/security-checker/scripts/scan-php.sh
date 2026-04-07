#!/bin/bash
# Scans a PHP project using semgrep + phpcs (phpcs-security-audit ruleset).
# Usage: ./scan-php.sh [project-dir]
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
  SEMGREP_OUT=$(semgrep --config "p/php" --json "$PROJECT_DIR" 2>/dev/null || echo '{"results":[],"errors":[]}')
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

# --- phpcs + phpcs-security-audit ---
if command -v phpcs &>/dev/null; then
  PHPCS_OUT=$(phpcs --standard=Security --report=json "$PROJECT_DIR" 2>/dev/null || phpcs --report=json "$PROJECT_DIR" 2>/dev/null || echo '{"files":{}}')
  while IFS= read -r msg_line; do
    file=$(echo "$msg_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('file','unknown'))" 2>/dev/null || echo "unknown")
    message=$(echo "$msg_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null || echo "")
    msg_type=$(echo "$msg_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('type','WARNING'))" 2>/dev/null || echo "WARNING")
    line=$(echo "$msg_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('line',0))" 2>/dev/null || echo "0")
    source_id=$(echo "$msg_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('source','phpcs'))" 2>/dev/null || echo "phpcs")
    severity=$([ "$msg_type" = "ERROR" ] && echo "HIGH" || echo "MEDIUM")
    message_esc=$(escape_json "$message")
    FINDINGS+=("{\"id\": \"phpcs-$source_id\", \"severity\": \"$severity\", \"message\": \"$message_esc\", \"file\": \"$file\", \"line\": $line, \"code_snippet\": \"\", \"cwe\": \"\", \"owasp\": \"\", \"source\": \"phpcs\"}")
  done < <(echo "$PHPCS_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for filepath, fdata in data.get('files', {}).items():
    for msg in fdata.get('messages', []):
        msg['file'] = filepath
        print(json.dumps(msg))
" 2>/dev/null)
fi

FINDINGS_JSON=""
for i in "${!FINDINGS[@]}"; do
  [ $i -gt 0 ] && FINDINGS_JSON+=", "
  FINDINGS_JSON+="${FINDINGS[$i]}"
done

echo "{\"stack\": \"php\", \"findings\": [$FINDINGS_JSON]}"
