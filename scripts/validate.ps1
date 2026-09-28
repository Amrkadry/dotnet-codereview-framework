<#
.SYNOPSIS
  Validates the dotnet-codereview-framework installation and reports which tools are supported.

.DESCRIPTION
  Answers three questions, in order, without scanning anything:
    1. Is the framework itself healthy?        (runs the 11-gate self check)
    2. Which integrations can actually run here, and which cannot, and why?
    3. Is AI review enabled?  It is OPTIONAL and OFF by default.

  Nothing here requires any scanner to be installed. Missing tools are reported as capability
  gaps with the exact command to install them — never as a clean result.

.PARAMETER SourcePath
  Optional. A .NET solution folder to also run capability detection against.

.PARAMETER Fix
  Print the install commands for every missing tool, ready to copy.

.EXAMPLE
  .\scripts\validate.ps1
.EXAMPLE
  .\scripts\validate.ps1 -SourcePath D:\src\MyApp -Fix
#>
[CmdletBinding()]
param(
  [string]$SourcePath,
  [switch]$Fix
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$script:fail = 0
$script:warn = 0

function Write-Head($text) {
  Write-Host ''
  Write-Host $text -ForegroundColor Cyan
  Write-Host ('-' * $text.Length) -ForegroundColor DarkGray
}
function Write-Row($status, $name, $detail) {
  $color = switch ($status) {
    'OK'      { 'Green' }
    'MISSING' { 'Yellow' }
    'FAIL'    { 'Red' }
    'OPTIONAL'{ 'DarkGray' }
    default   { 'Gray' }
  }
  Write-Host ('  {0,-9} ' -f $status) -ForegroundColor $color -NoNewline
  Write-Host ('{0,-22} ' -f $name) -NoNewline
  Write-Host $detail -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 1. prerequisites
Write-Head '1. Prerequisites'

$node = $null
try { $node = (& node --version) 2>$null } catch { }
if ($node) {
  $major = [int]($node -replace '^v(\d+).*$', '$1')
  if ($major -ge 18) { Write-Row 'OK' 'node' "$node" }
  else { Write-Row 'FAIL' 'node' "$node — Node 18+ is required"; $script:fail++ }
} else {
  Write-Row 'FAIL' 'node' 'not found on PATH — Node 18+ is required'
  $script:fail++
}

if (Test-Path (Join-Path $root 'package.json')) { Write-Row 'OK' 'framework files' 'package.json present' }
else { Write-Row 'FAIL' 'framework files' 'package.json missing — wrong directory?'; $script:fail++ }

if ($script:fail -gt 0) {
  Write-Host ''
  Write-Host 'Cannot continue without the prerequisites above.' -ForegroundColor Red
  exit 1
}

# ---------------------------------------------------------------- 2. self check
Write-Head '2. Framework self check'
Write-Host '  Running 11 internal gates (structure, schema, adapters, catalog, CLI end-to-end)...' -ForegroundColor DarkGray
Write-Host ''

& node (Join-Path $root 'tools/selfcheck.js')
if ($LASTEXITCODE -ne 0) {
  Write-Host ''
  Write-Host 'Self check FAILED. The framework is not healthy; fix this before scanning anything.' -ForegroundColor Red
  exit 1
}

# ---------------------------------------------------------------- 3. tool support
Write-Head '3. Integration support on this machine'

# id, probe command, args, kind, install command, required?
$tools = @(
  @{ Id='trivy';            Cmd='trivy';     Args=@('--version');  Kind='dependency'; Install='winget install AquaSecurity.Trivy';                          Required=$false }
  @{ Id='snyk';             Cmd='snyk';      Args=@('--version');  Kind='dependency'; Install='npm install -g snyk ; snyk auth';                            Required=$false }
  @{ Id='osv-scanner';      Cmd='osv-scanner';Args=@('--version'); Kind='dependency'; Install='go install github.com/google/osv-scanner/cmd/osv-scanner@latest'; Required=$false }
  @{ Id='dependency-check'; Cmd='dependency-check'; Args=@('--version'); Kind='dependency'; Install='download from https://github.com/jeremylong/DependencyCheck/releases'; Required=$false }
  @{ Id='gitleaks';         Cmd='gitleaks';  Args=@('version');    Kind='secret';     Install='go install github.com/gitleaks/gitleaks/v8@latest';          Required=$true  }
  @{ Id='semgrep';          Cmd='semgrep';   Args=@('--version');  Kind='sast';       Install='pip install semgrep';                                        Required=$false }
  @{ Id='msbuild';          Cmd='MSBuild.exe';Args=@('-version','-nologo'); Kind='build'; Install='install Visual Studio Build Tools';                      Required=$false }
  @{ Id='dotnet';           Cmd='dotnet';    Args=@('--version');  Kind='build';      Install='https://dotnet.microsoft.com/download';                      Required=$false }
)

$present = 0
$missingRequired = @()
$missingOptional = @()

foreach ($t in $tools) {
  $found = $null
  try { $found = (Get-Command $t.Id -ErrorAction SilentlyContinue) } catch { }
  if (-not $found) { try { $found = (Get-Command $t.Cmd -ErrorAction SilentlyContinue) } catch { } }

  if ($found) {
    $ver = ''
    try { $ver = (& $found.Source @($t.Args) 2>&1 | Select-Object -First 1) } catch { $ver = '(version probe failed)' }
    Write-Row 'OK' $t.Id ("{0}  {1}" -f $t.Kind, ($ver -replace '\s+', ' ').Trim())
    $present++
  } else {
    if ($t.Required) {
      Write-Row 'MISSING' $t.Id ("{0}  — recommended: this is the only tool that finds .NET config secrets" -f $t.Kind)
      $missingRequired += $t
      $script:warn++
    } else {
      Write-Row 'MISSING' $t.Id ("{0}  — optional" -f $t.Kind)
      $missingOptional += $t
    }
  }
}

Write-Host ''
Write-Host ("  {0} of {1} integrations available." -f $present, $tools.Count) -ForegroundColor DarkGray
Write-Host '  The framework runs with ZERO scanners installed: discovery alone derives findings,' -ForegroundColor DarkGray
Write-Host '  and every absent tool is reported as a capability gap, never as a clean result.' -ForegroundColor DarkGray

# ---------------------------------------------------------------- 4. AI review (optional)
Write-Head '4. AI-assisted review (OPTIONAL)'

$aiKeys = @('ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'ZAI_API_KEY')
$keyFound = $aiKeys | Where-Object { [Environment]::GetEnvironmentVariable($_) }

if ($keyFound) {
  Write-Row 'OK' 'api key' ("$keyFound is set in the environment")
} else {
  Write-Row 'OPTIONAL' 'api key' 'no API key set — AI review will stay disabled'
}

$cfgPath = if ($SourcePath) { Join-Path $SourcePath 'moraa.config.json' } else { Join-Path $root 'moraa.config.json' }
$aiEnabled = $false
if (Test-Path $cfgPath) {
  try {
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
    $aiEnabled = [bool]$cfg.tools.'ai-review'.enabled
  } catch { }
}
if ($aiEnabled) {
  Write-Row 'OK' 'config' 'ai-review.enabled = true'
  Write-Host ''
  Write-Host '  NOTE: enabling AI review TRANSMITS SOURCE CODE to a third-party API.' -ForegroundColor Yellow
  Write-Host '  Keys are read from the environment only, never from config or CLI arguments.' -ForegroundColor DarkGray
  Write-Host '  AI findings are capped at confidence POSSIBLE, carry no CVSS, and are marked' -ForegroundColor DarkGray
  Write-Host '  UNVERIFIED: a model assertion is a lead, not a conclusion.' -ForegroundColor DarkGray
} else {
  Write-Row 'OPTIONAL' 'config' 'ai-review disabled (the default) — everything else works without it'
}

# ---------------------------------------------------------------- 5. capability detection
if ($SourcePath) {
  if (-not (Test-Path $SourcePath)) {
    Write-Host ''
    Write-Host "SourcePath not found: $SourcePath" -ForegroundColor Red
    exit 1
  }
  Write-Head "5. Capability detection for $SourcePath"
  & node (Join-Path $root 'bin/moraa.js') discover $SourcePath
  if ($LASTEXITCODE -ne 0) { $script:fail++ }
}

# ---------------------------------------------------------------- summary
Write-Head 'Summary'

if ($script:fail -eq 0) {
  Write-Host '  Framework: HEALTHY' -ForegroundColor Green
} else {
  Write-Host '  Framework: FAILED' -ForegroundColor Red
}
Write-Host ("  Integrations available: {0}/{1}" -f $present, $tools.Count)
Write-Host ("  AI review: {0}" -f $(if ($aiEnabled) { 'enabled' } else { 'disabled (optional)' }))

if (($missingRequired.Count + $missingOptional.Count) -gt 0 -and $Fix) {
  Write-Head 'Install commands for missing tools'
  foreach ($t in ($missingRequired + $missingOptional)) {
    Write-Host ("  # {0} ({1})" -f $t.Id, $t.Kind) -ForegroundColor DarkGray
    Write-Host ("  {0}" -f $t.Install)
  }
} elseif (($missingRequired.Count + $missingOptional.Count) -gt 0) {
  Write-Host ''
  Write-Host '  Re-run with -Fix to print install commands for the missing tools.' -ForegroundColor DarkGray
}

Write-Host ''
if ($missingRequired.Count -gt 0) {
  Write-Host '  gitleaks is missing. On .NET this matters more than it looks: credentials in' -ForegroundColor Yellow
  Write-Host '  Web.config are the most common critical finding, and no other tool in the' -ForegroundColor Yellow
  Write-Host '  pipeline looks for them. Stock secret-scanner rules do not match XML appSettings.' -ForegroundColor Yellow
  Write-Host ''
}
Write-Host '  Next:  node bin/moraa.js review <sourcePath>' -ForegroundColor Cyan
Write-Host ''

exit $(if ($script:fail -gt 0) { 1 } else { 0 })
