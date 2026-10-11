#!/usr/bin/env bash
// dotnet-codereview-framework — scripts/validate.sh
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
# Validates the dotnet-codereview-framework installation and reports which tools are supported.
#
# Answers three questions, in order, without scanning anything:
#   1. Is the framework itself healthy?  (runs the 11-gate self check)
#   2. Which integrations can actually run here, and which cannot, and why?
#   3. Is AI review enabled?  It is OPTIONAL and OFF by default.
#
# Nothing here requires any scanner to be installed. Missing tools are reported as capability gaps
# with the exact install command — never as a clean result.
#
# Usage:
#   ./scripts/validate.sh
#   ./scripts/validate.sh --source /path/to/solution --fix

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE_PATH=""
FIX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SOURCE_PATH="${2:-}"; shift 2 ;;
    --fix)    FIX=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'; C_CYAN=$'\033[36m'; C_DIM=$'\033[90m'
else
  C_RESET=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""; C_DIM=""
fi

FAILURES=0
MISSING_REQUIRED=()
MISSING_OPTIONAL=()
INSTALL_CMDS=()

section() { printf '\n%s%s%s\n' "$C_CYAN" "$1" "$C_RESET"; printf '%s%s%s\n' "$C_DIM" "$(printf '%*s' "${#1}" '' | tr ' ' '-')" "$C_RESET"; }
row() { # status name detail
  local c
  case "$1" in
    OK) c="$C_GREEN" ;; MISSING) c="$C_YELLOW" ;; FAIL) c="$C_RED" ;; *) c="$C_DIM" ;;
  esac
  printf '  %s%-9s%s %-22s %s%s%s\n' "$c" "$1" "$C_RESET" "$2" "$C_DIM" "$3" "$C_RESET"
}

# ---------------------------------------------------------------- 1. prerequisites
section '1. Prerequisites'

if command -v node >/dev/null 2>&1; then
  NODE_V="$(node --version)"
  NODE_MAJOR="$(printf '%s' "$NODE_V" | sed 's/^v\([0-9]*\).*/\1/')"
  if [ "${NODE_MAJOR:-0}" -ge 18 ]; then row OK node "$NODE_V"
  else row FAIL node "$NODE_V — Node 18+ required"; FAILURES=$((FAILURES+1)); fi
else
  row FAIL node 'not found on PATH — Node 18+ required'; FAILURES=$((FAILURES+1))
fi

if [ -f package.json ]; then row OK 'framework files' 'package.json present'
else row FAIL 'framework files' 'package.json missing — wrong directory?'; FAILURES=$((FAILURES+1)); fi

if [ "$FAILURES" -gt 0 ]; then
  printf '\n%sCannot continue without the prerequisites above.%s\n' "$C_RED" "$C_RESET"
  exit 1
fi

# ---------------------------------------------------------------- 2. self check
section '2. Framework self check'
printf '  %sRunning 11 internal gates (structure, schema, adapters, catalog, CLI end-to-end)...%s\n\n' "$C_DIM" "$C_RESET"
if ! node tools/selfcheck.js; then
  printf '\n%sSelf check FAILED. Fix this before scanning anything.%s\n' "$C_RED" "$C_RESET"
  exit 1
fi

# ---------------------------------------------------------------- 3. tool support
section '3. Integration support on this machine'

# id|probe-args|kind|install|required
TOOLS=(
  "trivy|--version|dependency|brew install trivy  (or: winget install AquaSecurity.Trivy)|0"
  "snyk|--version|dependency|npm install -g snyk && snyk auth|0"
  "osv-scanner|--version|dependency|go install github.com/google/osv-scanner/cmd/osv-scanner@latest|0"
  "dependency-check|--version|dependency|download from https://github.com/jeremylong/DependencyCheck/releases|0"
  "gitleaks|version|secret|go install github.com/gitleaks/gitleaks/v8@latest|1"
  "semgrep|--version|sast|pip install semgrep|0"
  "dotnet|--version|build|https://dotnet.microsoft.com/download|0"
  "msbuild|-version|build|install Visual Studio Build Tools (Windows) or use dotnet build|0"
)

PRESENT=0
TOTAL=0
for entry in "${TOOLS[@]}"; do
  IFS='|' read -r id probe kind install required <<< "$entry"
  TOTAL=$((TOTAL+1))
  if command -v "$id" >/dev/null 2>&1; then
    ver="$("$id" $probe 2>&1 | head -1 | tr -s ' ')"
    row OK "$id" "$kind  $ver"
    PRESENT=$((PRESENT+1))
  else
    if [ "$required" = "1" ]; then
      row MISSING "$id" "$kind  — recommended: the only tool that finds .NET config secrets"
      MISSING_REQUIRED+=("$id")
    else
      row MISSING "$id" "$kind  — optional"
      MISSING_OPTIONAL+=("$id")
    fi
    INSTALL_CMDS+=("# $id ($kind)"$'\n'"$install")
  fi
done

printf '\n  %s%s of %s integrations available.%s\n' "$C_DIM" "$PRESENT" "$TOTAL" "$C_RESET"
printf '  %sThe framework runs with ZERO scanners installed: discovery alone derives findings,%s\n' "$C_DIM" "$C_RESET"
printf '  %sand every absent tool is reported as a capability gap, never as a clean result.%s\n' "$C_DIM" "$C_RESET"

# ---------------------------------------------------------------- 4. AI review (optional)
section '4. AI-assisted review (OPTIONAL)'

AI_KEY=""
for k in ANTHROPIC_API_KEY OPENAI_API_KEY ZAI_API_KEY; do
  if [ -n "${!k:-}" ]; then AI_KEY="$k"; break; fi
done
if [ -n "$AI_KEY" ]; then row OK 'api key' "$AI_KEY is set in the environment"
else row OPTIONAL 'api key' 'no API key set — AI review will stay disabled'; fi

CFG="${SOURCE_PATH:+$SOURCE_PATH/}moraa.config.json"
[ -f "$CFG" ] || CFG="moraa.config.json"
AI_ENABLED=0
if [ -f "$CFG" ] && command -v node >/dev/null 2>&1; then
  AI_ENABLED="$(node -e "
    try { const c=require('$PWD/$CFG'); process.stdout.write(((c.tools||{})['ai-review']||{}).enabled?'1':'0'); }
    catch { process.stdout.write('0'); }" 2>/dev/null || echo 0)"
fi

if [ "$AI_ENABLED" = "1" ]; then
  row OK 'config' 'ai-review.enabled = true'
  printf '\n  %sNOTE: enabling AI review TRANSMITS SOURCE CODE to a third-party API.%s\n' "$C_YELLOW" "$C_RESET"
  printf '  %sKeys are read from the environment only, never from config or CLI arguments.%s\n' "$C_DIM" "$C_RESET"
  printf '  %sAI findings are capped at confidence POSSIBLE, carry no CVSS, and are marked%s\n' "$C_DIM" "$C_RESET"
  printf '  %sUNVERIFIED: a model assertion is a lead, not a conclusion.%s\n' "$C_DIM" "$C_RESET"
else
  row OPTIONAL 'config' 'ai-review disabled (the default) — everything else works without it'
fi

# ---------------------------------------------------------------- 5. capability detection
if [ -n "$SOURCE_PATH" ]; then
  if [ ! -d "$SOURCE_PATH" ]; then
    printf '\n%sSource path not found: %s%s\n' "$C_RED" "$SOURCE_PATH" "$C_RESET"; exit 1
  fi
  section "5. Capability detection for $SOURCE_PATH"
  node bin/moraa.js discover "$SOURCE_PATH" || FAILURES=$((FAILURES+1))
fi

# ---------------------------------------------------------------- summary
section 'Summary'
if [ "$FAILURES" -eq 0 ]; then printf '  %sFramework: HEALTHY%s\n' "$C_GREEN" "$C_RESET"
else printf '  %sFramework: FAILED%s\n' "$C_RED" "$C_RESET"; fi
printf '  Integrations available: %s/%s\n' "$PRESENT" "$TOTAL"
printf '  AI review: %s\n' "$([ "$AI_ENABLED" = "1" ] && echo enabled || echo 'disabled (optional)')"

if [ "${#INSTALL_CMDS[@]}" -gt 0 ]; then
  if [ "$FIX" = "1" ]; then
    section 'Install commands for missing tools'
    for c in "${INSTALL_CMDS[@]}"; do printf '  %s\n' "$c"; done
  else
    printf '\n  %sRe-run with --fix to print install commands for the missing tools.%s\n' "$C_DIM" "$C_RESET"
  fi
fi

if [ "${#MISSING_REQUIRED[@]}" -gt 0 ]; then
  printf '\n  %sgitleaks is missing. On .NET this matters more than it looks: credentials in%s\n' "$C_YELLOW" "$C_RESET"
  printf '  %sWeb.config are the most common critical finding, and no other tool in the%s\n' "$C_YELLOW" "$C_RESET"
  printf '  %spipeline looks for them. Stock secret-scanner rules do not match XML appSettings.%s\n' "$C_YELLOW" "$C_RESET"
fi

printf '\n  %sNext:  node bin/moraa.js review <sourcePath>%s\n\n' "$C_CYAN" "$C_RESET"
exit "$([ "$FAILURES" -gt 0 ] && echo 1 || echo 0)"
