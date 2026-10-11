#!/usr/bin/env bash
// dotnet-codereview-framework — tools/install-tools.sh
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
# install-tools.sh — install the free, no-auth detectors that raise review accuracy
# on Linux / WSL / CI. Idempotent: re-running skips what is already present.
#
#   gitleaks  CONFIRMED secrets in Web.config/appsettings with the .NET ruleset
#   trivy     second opinion on dependency advisories + manifest misconfigs
#   semgrep   pattern-SAST corroboration via rules/semgrep/dotnet-moraa.yaml
#   snyk      optional, needs a free account (npm i -g snyk && snyk auth)
set -euo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

# --- gitleaks ---
if ! have gitleaks; then
  echo '[install] gitleaks 8.28.0'
  curl -sSL -o /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks
  sudo install /tmp/gitleaks /usr/local/bin/gitleaks
else
  echo "[ok] gitleaks already at $(command -v gitleaks)"
fi

# --- trivy ---
if ! have trivy; then
  echo '[install] trivy 0.75.0'
  curl -sSL -o /tmp/trivy.tar.gz \
    https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz
  tar -xzf /tmp/trivy.tar.gz -C /tmp trivy
  sudo install /tmp/trivy /usr/local/bin/trivy
else
  echo "[ok] trivy already at $(command -v trivy)"
fi

# --- semgrep (python; best on Linux/WSL) ---
if ! have semgrep; then
  if have pip3; then
    echo '[install] semgrep (pip3)'
    pip3 install --user semgrep || echo '[warn] semgrep install failed — pattern-SAST corroboration will be unavailable'
  else
    echo '[skip] semgrep — pip3 not found:  apt install python3-pip && pip3 install semgrep'
  fi
else
  echo "[ok] semgrep already at $(command -v semgrep)"
fi

# --- snyk (opt-in) ---
if ! have snyk; then
  echo '[skip] snyk — optional, needs a free account:  npm i -g snyk && snyk auth'
fi

echo
echo 'Installed state:'
for t in gitleaks trivy semgrep; do
  if have "$t"; then echo "  $t: $("$t" --version 2>&1 | head -1)"; else echo "  $t: NOT INSTALLED"; fi
done
