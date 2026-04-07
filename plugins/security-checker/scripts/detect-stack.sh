#!/bin/bash
# Detects the technology stack of a project by examining its files.
# Usage: ./detect-stack.sh [project-dir] [--stack <override>]
# Output: JSON {"stacks": ["js", "php"], "override": false}
#         JSON {"stacks": [], "override": false, "error": "..."}  on failure

set -euo pipefail

PROJECT_DIR="."
OVERRIDE_STACK=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack)
      if [[ $# -lt 2 ]]; then
        echo '{"stacks": [], "override": false, "error": "--stack requires a value (js|java|php)."}'
        exit 1
      fi
      OVERRIDE_STACK="$2"; shift 2 ;;
    *) PROJECT_DIR="$1"; shift ;;
  esac
done

# Validate project directory exists
if [ ! -d "$PROJECT_DIR" ]; then
  echo "{\"stacks\": [], \"override\": false, \"error\": \"Directory not found: $PROJECT_DIR\"}"
  exit 1
fi

# Override mode: skip detection entirely
if [ -n "$OVERRIDE_STACK" ]; then
  echo "{\"stacks\": [\"$OVERRIDE_STACK\"], \"override\": true}"
  exit 0
fi

STACKS=()

# Detect JS/Node
if [ -f "$PROJECT_DIR/package.json" ]; then
  STACKS+=("js")
fi

# Detect Java
if [ -f "$PROJECT_DIR/pom.xml" ] || [ -f "$PROJECT_DIR/build.gradle" ]; then
  STACKS+=("java")
fi

# Detect PHP (composer.json or any .php file within 3 levels)
if [ -f "$PROJECT_DIR/composer.json" ] || find "$PROJECT_DIR" -maxdepth 3 -name "*.php" 2>/dev/null | grep -q .; then
  STACKS+=("php")
fi

if [ ${#STACKS[@]} -eq 0 ]; then
  echo '{"stacks": [], "override": false, "error": "Could not detect stack. Use --stack flag (js|java|php)."}'
  exit 1
fi

# Build JSON array
STACKS_JSON=""
for i in "${!STACKS[@]}"; do
  [ $i -gt 0 ] && STACKS_JSON+=", "
  STACKS_JSON+="\"${STACKS[$i]}\""
done

echo "{\"stacks\": [$STACKS_JSON], \"override\": false}"
