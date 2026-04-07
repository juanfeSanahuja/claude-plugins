#!/bin/bash
# Verifies and installs required security tools for the given stack(s).
# Usage: ./install-tools.sh <stack1> [stack2] ...
# Output: JSON array of {"tool": "...", "status": "already_installed|installed|failed", "reason": "..."}

set -uo pipefail

RESULTS=()

add_result() {
  local tool="$1" status="$2" reason="${3:-}"
  if [ -n "$reason" ]; then
    RESULTS+=("{\"tool\": \"$tool\", \"status\": \"$status\", \"reason\": \"$reason\"}")
  else
    RESULTS+=("{\"tool\": \"$tool\", \"status\": \"$status\"}")
  fi
}

install_with_pip() {
  local package="$1"
  if command -v pip3 &>/dev/null; then
    pip3 install "$package" -q 2>/dev/null && return 0
  elif command -v pip &>/dev/null; then
    pip install "$package" -q 2>/dev/null && return 0
  fi
  return 1
}

check_semgrep() {
  if command -v semgrep &>/dev/null; then
    add_result "semgrep" "already_installed"
  elif install_with_pip semgrep; then
    add_result "semgrep" "installed"
  else
    add_result "semgrep" "failed" "pip/pip3 not found. Install Python 3 first: https://python.org"
  fi
}

check_npm() {
  if command -v npm &>/dev/null; then
    add_result "npm" "already_installed"
  else
    add_result "npm" "failed" "npm not found. Install Node.js first: https://nodejs.org"
  fi
}

check_owasp_dc() {
  local dc_bin="$HOME/.owasp-dependency-check/bin/dependency-check.sh"
  if [ -x "$dc_bin" ]; then
    add_result "owasp-dependency-check" "already_installed"
  elif command -v curl &>/dev/null; then
    local version="9.0.9"
    local url="https://github.com/jeremylong/DependencyCheck/releases/download/v${version}/dependency-check-${version}-release.zip"
    mkdir -p "$HOME/.owasp-dependency-check"
    curl -sSL "$url" -o /tmp/dependency-check.zip \
      && unzip -q /tmp/dependency-check.zip -d "$HOME" \
      && mv "$HOME/dependency-check" "$HOME/.owasp-dependency-check" \
      && add_result "owasp-dependency-check" "installed" \
      || add_result "owasp-dependency-check" "failed" "Download failed. Install manually from https://jeremylong.github.io/DependencyCheck/"
    rm -f /tmp/dependency-check.zip
  else
    add_result "owasp-dependency-check" "failed" "curl not found. Cannot download OWASP Dependency-Check automatically."
  fi
}

check_phpcs() {
  if command -v phpcs &>/dev/null; then
    add_result "phpcs" "already_installed"
  elif command -v composer &>/dev/null; then
    composer global require "squizlabs/php_codesniffer" -q \
      && add_result "phpcs" "installed" \
      || add_result "phpcs" "failed" "composer global require failed"
  else
    add_result "phpcs" "failed" "composer not found. Install Composer first: https://getcomposer.org"
  fi
}

check_phpcs_security_audit() {
  if composer global show 2>/dev/null | grep -q "pheromone/phpcs-security-audit"; then
    add_result "phpcs-security-audit" "already_installed"
  elif command -v composer &>/dev/null; then
    composer global require "pheromone/phpcs-security-audit" -q \
      && add_result "phpcs-security-audit" "installed" \
      || add_result "phpcs-security-audit" "failed" "composer global require failed"
  else
    add_result "phpcs-security-audit" "failed" "composer not found. Install Composer first: https://getcomposer.org"
  fi
}

check_nikto() {
  if command -v nikto &>/dev/null; then
    add_result "nikto" "already_installed"
  elif command -v apt-get &>/dev/null; then
    apt-get install -y nikto -q \
      && add_result "nikto" "installed" \
      || add_result "nikto" "failed" "apt-get install nikto failed"
  elif command -v brew &>/dev/null; then
    brew install nikto -q \
      && add_result "nikto" "installed" \
      || add_result "nikto" "failed" "brew install nikto failed"
  else
    add_result "nikto" "failed" "No supported package manager found (apt/brew). Install nikto manually."
  fi
}

check_zap() {
  if ! command -v docker &>/dev/null; then
    add_result "owasp-zap" "failed" "Docker not found. Install Docker first: https://docs.docker.com/get-docker/ — ZAP runs as a Docker container."
    return
  fi
  if docker image inspect owasp/zap2docker-stable &>/dev/null 2>&1; then
    add_result "owasp-zap" "already_installed"
  else
    docker pull owasp/zap2docker-stable -q 2>/dev/null \
      && add_result "owasp-zap" "installed" \
      || add_result "owasp-zap" "failed" "docker pull owasp/zap2docker-stable failed. Check your internet connection."
  fi
}

# Process each requested stack
for stack in "$@"; do
  case "$stack" in
    js)
      check_semgrep
      check_npm
      ;;
    java)
      check_semgrep
      check_owasp_dc
      ;;
    php)
      check_semgrep
      check_phpcs
      check_phpcs_security_audit
      ;;
    web)
      check_zap
      check_nikto
      ;;
    *)
      add_result "$stack" "failed" "Unknown stack: $stack. Supported: js, java, php, web"
      ;;
  esac
done

# Build JSON output
OUTPUT="["
for i in "${!RESULTS[@]}"; do
  [ $i -gt 0 ] && OUTPUT+=", "
  OUTPUT+="${RESULTS[$i]}"
done
OUTPUT+="]"

echo "$OUTPUT"
