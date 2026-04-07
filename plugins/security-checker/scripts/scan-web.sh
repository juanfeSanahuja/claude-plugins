#!/bin/bash
# Scans a web server using OWASP ZAP (spider + passive scan) + nikto (server-level).
# ZAP crawls the site following links within the same domain.
# Nikto complements with server-level vulnerability detection.
# Usage: ./scan-web.sh <server-url>
# Output: standardized JSON findings

set -uo pipefail

SERVER_URL="${1:-}"
FINDINGS=()

if [ -z "$SERVER_URL" ]; then
  echo '{"stack": "web", "findings": [], "error": "No URL provided. Usage: scan-web.sh <url>"}'
  exit 1
fi

escape_json() {
  printf '%s' "$1" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null | sed 's/^"//;s/"$//'
}

map_zap_severity() {
  case "$1" in
    3) echo "CRITICAL" ;;
    2) echo "HIGH" ;;
    1) echo "MEDIUM" ;;
    *) echo "LOW" ;;
  esac
}

# ── OWASP ZAP (spider + passive scan via Docker) ──────────────────────────────
if command -v docker &>/dev/null; then
  ZAP_OUTPUT_DIR=$(mktemp -d /tmp/zap-XXXXXX)

  docker run --rm -u zap \
    --volume "${ZAP_OUTPUT_DIR}:/zap/wrk:rw" \
    owasp/zap2docker-stable \
    zap-baseline.py \
    -t "$SERVER_URL" \
    -J zap-report.json \
    -d \
    2>/dev/null || true

  ZAP_REPORT="$ZAP_OUTPUT_DIR/zap-report.json"

  if [ -f "$ZAP_REPORT" ]; then
    while IFS= read -r alert_line; do
      alert_name=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name',''))" 2>/dev/null || echo "")
      riskcode=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('riskcode','0'))" 2>/dev/null || echo "0")
      desc=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('desc',''))" 2>/dev/null || echo "")
      solution=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('solution',''))" 2>/dev/null || echo "")
      cweid=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cweid',''))" 2>/dev/null || echo "")
      pluginid=$(echo "$alert_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pluginid',''))" 2>/dev/null || echo "")
      severity=$(map_zap_severity "$riskcode")
      cwe=$([ -n "$cweid" ] && echo "CWE-$cweid" || echo "")

      # One finding per affected URL (ZAP groups instances under each alert)
      while IFS= read -r instance; do
        uri=$(echo "$instance" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uri',''))" 2>/dev/null || echo "")
        method=$(echo "$instance" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('method','GET'))" 2>/dev/null || echo "GET")
        evidence=$(echo "$instance" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('evidence',''))" 2>/dev/null || echo "")

        name_esc=$(escape_json "$alert_name")
        desc_esc=$(escape_json "$desc")
        solution_esc=$(escape_json "$solution")
        uri_esc=$(escape_json "$uri")
        evidence_esc=$(escape_json "$evidence")
        cwe_esc=$(escape_json "$cwe")

        FINDINGS+=("{\"id\": \"zap-$pluginid\", \"severity\": \"$severity\", \"message\": \"$name_esc\", \"file\": \"$uri_esc\", \"line\": 0, \"code_snippet\": \"$evidence_esc\", \"cwe\": \"$cwe_esc\", \"owasp\": \"\", \"source\": \"zap\", \"fix\": \"$solution_esc\", \"method\": \"$method\"}")
      done < <(echo "$alert_line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
[print(json.dumps(i)) for i in d.get('instances', [])]
" 2>/dev/null)
    done < <(python3 - "$ZAP_REPORT" << 'PY'
import sys, json
with open(sys.argv[1]) as f:
    data = json.load(f)
for site in data.get("site", []):
    for alert in site.get("alerts", []):
        print(json.dumps(alert))
PY
    )
  fi

  rm -rf "$ZAP_OUTPUT_DIR"
fi

# ── Nikto (server-level: software versions, dangerous files, misconfigs) ──────
if command -v nikto &>/dev/null; then
  NIKTO_OUT=$(nikto -h "$SERVER_URL" -Format json -output /dev/stdout 2>/dev/null || echo "[]")

  while IFS= read -r finding; do
    id=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id','nikto-unknown'))" 2>/dev/null || echo "nikto-unknown")
    description=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('description',''))" 2>/dev/null || echo "")
    url=$(echo "$finding" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url','/'))" 2>/dev/null || echo "/")
    description_esc=$(escape_json "$description")
    url_esc=$(escape_json "$url")
    FINDINGS+=("{\"id\": \"nikto-$id\", \"severity\": \"HIGH\", \"message\": \"$description_esc\", \"file\": \"$url_esc\", \"line\": 0, \"code_snippet\": \"\", \"cwe\": \"\", \"owasp\": \"\", \"source\": \"nikto\"}")
  done < <(echo "$NIKTO_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data if isinstance(data, list) else data.get('vulnerabilities', [])
[print(json.dumps(i)) for i in items]
" 2>/dev/null)
fi

# ── Warn if neither tool is available ─────────────────────────────────────────
if [ ${#FINDINGS[@]} -eq 0 ] && ! command -v docker &>/dev/null && ! command -v nikto &>/dev/null; then
  echo '{"stack": "web", "findings": [], "error": "Neither docker (for ZAP) nor nikto found. Run install-tools.sh web first."}'
  exit 1
fi

# ── Build output JSON ──────────────────────────────────────────────────────────
FINDINGS_JSON=""
for i in "${!FINDINGS[@]}"; do
  [ $i -gt 0 ] && FINDINGS_JSON+=", "
  FINDINGS_JSON+="${FINDINGS[$i]}"
done

echo "{\"stack\": \"web\", \"findings\": [$FINDINGS_JSON]}"
