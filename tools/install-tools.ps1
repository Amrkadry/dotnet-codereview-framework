// dotnet-codereview-framework — tools/install-tools.ps1
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
# ------------------------------------------------------------------------------
# install-tools.ps1 — install the free, no-auth detectors that raise review accuracy.
#
#   .\tools\install-tools.ps1            # machine-wide via winget when available
#   .\tools\install-tools.ps1 -Local     # portable install into .tools-bin\ (add to PATH)
#
# What each tool ADDS to a review (why this script exists):
#   gitleaks  CONFIRMED secrets in Web.config/appsettings with the .NET ruleset — the
#             #1 critical finding class on legacy apps. Turns the native heuristic
#             (POSSIBLE) into cross-tool-confirmed facts.
#   trivy     second opinion on dependency advisories (corroborates the keyless OSV
#             adapter) + manifest misconfigurations on packages.config projects.
#   semgrep   pattern-SAST corroboration via rules/semgrep/dotnet-moraa.yaml.
#             NOT installable natively on Windows — see install-tools.sh (WSL/Linux).
#   snyk      needs a free account + SNYK_TOKEN; skip unless you want its advisory DB.
#   roslyn    needs a buildable SDK-style project; on legacy packages.config apps the
#             adapter will report NOT_APPLICABLE — nothing to install for those.
#
# Idempotent: re-running skips what is already present.

param([switch]$Local)
$ErrorActionPreference = 'Stop'

$binDir = Join-Path $PSScriptRoot '..\.tools-bin'
if ($Local) { New-Item -ItemType Directory -Force $binDir | Out-Null }

function Test-Tool($name) {
  $existing = Get-Command $name -ErrorAction SilentlyContinue
  if ($existing) { return $existing.Source }
  if ($Local -and (Test-Path (Join-Path $binDir "$name.exe"))) { return (Join-Path $binDir "$name.exe") }
  return $null
}

function Get-GitHubReleaseBinary($repo, $version, $asset, $exeName) {
  $url = "https://github.com/$repo/releases/download/v$version/$asset"
  $zip = Join-Path $env:TEMP "$exeName.zip"
  Write-Host "  downloading $asset ..."
  Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  if ($Local) {
    Expand-Archive $zip -DestinationPath $binDir -Force
  } else {
    Expand-Archive $zip -DestinationPath $env:TEMP -Force
    $src = Join-Path $env:TEMP $exeName
    $dest = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps"
    Copy-Item $src $dest -Force
  }
  Remove-Item $zip -Force
}

# --- gitleaks ---
$g = Test-Tool 'gitleaks'
if (-not $g) {
  Write-Host '[install] gitleaks 8.28.0'
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    try { winget install --id gitleaks.gitleaks -e --accept-source-agreements --accept-package-agreements }
    catch { Get-GitHubReleaseBinary 'gitleaks/gitleaks' '8.28.0' 'gitleaks_8.28.0_windows_x64.zip' 'gitleaks.exe' }
  } else {
    Get-GitHubReleaseBinary 'gitleaks/gitleaks' '8.28.0' 'gitleaks_8.28.0_windows_x64.zip' 'gitleaks.exe'
  }
} else { Write-Host "[ok] gitleaks already at $g" }

# --- trivy ---
$t = Test-Tool 'trivy'
if (-not $t) {
  Write-Host '[install] trivy 0.75.0'
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install --id Aquasecurity.Trivy -e --accept-source-agreements --accept-package-agreements
  } else {
    Get-GitHubReleaseBinary 'aquasecurity/trivy' '0.75.0' 'trivy_0.75.0_windows-64bit.zip' 'trivy.exe'
  }
} else { Write-Host "[ok] trivy already at $t" }

# --- semgrep: Windows-native not supported by upstream ---
if (-not (Test-Tool 'semgrep')) {
  Write-Host '[skip] semgrep — not supported natively on Windows.'
  Write-Host '       Run reviews from WSL/Linux after:  pip3 install semgrep   (see tools/install-tools.sh)'
}

# --- snyk: opt-in account ---
if (-not (Test-Tool 'snyk')) {
  Write-Host '[skip] snyk — optional, needs a free account:'
  Write-Host '       npm install -g snyk && snyk auth   (then set SNYK_TOKEN)'
}

Write-Host ''
Write-Host 'Installed state:'
foreach ($tool in 'gitleaks', 'trivy') {
  $found = Test-Tool $tool
  if ($found) { & $found --version 2>&1 | Select-Object -First 1 | Write-Host }
  else { Write-Host "  $tool NOT FOUND" }
}
if ($Local) {
  Write-Host ''
  Write-Host "Portable binaries in $binDir"
  Write-Host 'Add to PATH for the review session:  $env:PATH = ".tools-bin;$env:PATH"'
}
