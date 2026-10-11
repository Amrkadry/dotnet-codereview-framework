# Render a 1280x640 GitHub social-preview card for moraa.
# GitHub's default preview is a generic repo card; a real image is what makes a LinkedIn
# post stop the scroll. Drawn with System.Drawing so it needs nothing installed.
Add-Type -AssemblyName System.Drawing

$W = 1280
$H = 640
$bmp = New-Object System.Drawing.Bitmap($W, $H)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

function RGB([int]$r, [int]$gr, [int]$b) {
  return [System.Drawing.Color]::FromArgb(255, $r, $gr, $b)
}

# --- palette: GitHub-dark so the card sits naturally next to the repo -------------------
$bg       = RGB 13 17 23
$panel    = RGB 22 27 34
$border   = RGB 48 54 61
$fgBright = RGB 230 237 243
$fgDim    = RGB 125 133 144
$cyan     = RGB 86 211 255
$critical = RGB 248 81 73
$high     = RGB 255 123 114
$medium   = RGB 227 179 65
$low      = RGB 88 166 255
$info     = RGB 110 118 129
$green    = RGB 63 185 80

$g.Clear($bg)

# --- fonts: monospace, for the terminal character the tool actually has ------------------
function MonoFont([single]$size, [string]$style = 'Regular') {
  $st = [System.Drawing.FontStyle]::Regular
  if ($style -eq 'Bold') { $st = [System.Drawing.FontStyle]::Bold }
  foreach ($name in @('Cascadia Mono', 'Consolas', 'Courier New')) {
    try {
      $f = New-Object System.Drawing.Font($name, $size, $st)
      if ($f.Name -eq $name) { return $f }
      $f.Dispose()
    } catch { }
  }
  return New-Object System.Drawing.Font('Courier New', $size, $st)
}

$fTitle = MonoFont 72 'Bold'
$fSub   = MonoFont 23
$fTag   = MonoFont 26 'Bold'
$fBody  = MonoFont 17
$fSmall = MonoFont 15
$fBar   = MonoFont 16 'Bold'
$fUrl   = MonoFont 18

function Brush($c) { return New-Object System.Drawing.SolidBrush($c) }
function Pen($c, [single]$w = 1) { return New-Object System.Drawing.Pen($c, $w) }

# --- top accent rule --------------------------------------------------------------------
$g.FillRectangle((Brush $cyan), 0, 0, $W, 6)

$M = 70   # left margin

# --- wordmark ---------------------------------------------------------------------------
$g.DrawString('moraa', $fTitle, (Brush $fgBright), ($M - 8), 52)
$g.DrawString('.NET code review  &  security analysis', $fSub, (Brush $cyan), ($M - 2), 148)

# --- the claim --------------------------------------------------------------------------
$g.DrawString('Evidence-first. Never reports a false clean.', $fTag, (Brush $fgBright), ($M - 2), 206)

# --- severity panel (right) -------------------------------------------------------------
$px = 726; $py = 250; $pw = 484; $ph = 250
$g.FillRectangle((Brush $panel), $px, $py, $pw, $ph)
$g.DrawRectangle((Pen $border 1), $px, $py, $pw, $ph)
$g.DrawString('findings by severity', $fSmall, (Brush $fgDim), ($px + 20), ($py + 14))

$rows = @(
  @{ label = 'CRITICAL'; n = 7;  frac = 0.29; col = $critical },
  @{ label = 'HIGH';     n = 19; frac = 0.79; col = $high },
  @{ label = 'MEDIUM';   n = 24; frac = 1.00; col = $medium },
  @{ label = 'LOW';      n = 9;  frac = 0.37; col = $low },
  @{ label = 'INFO';     n = 4;  frac = 0.17; col = $info }
)
# "CRITICAL" is the widest label; the number column has to clear it or the two collide.
$barX = $px + 178
$barMax = 272
$y = $py + 52
foreach ($r in $rows) {
  $g.DrawString($r.label, $fBar, (Brush $r.col), ($px + 18), $y)
  $numRect = New-Object System.Drawing.RectangleF(($px + 124), $y, 38, 24)
  $sf = New-Object System.Drawing.StringFormat
  $sf.Alignment = [System.Drawing.StringAlignment]::Far
  $g.DrawString([string]$r.n, $fBar, (Brush $fgBright), $numRect, $sf)
  # the empty track, then the filled bar on top of it
  $g.FillRectangle((Brush (RGB 33 38 45)), $barX, ($y + 6), $barMax, 11)
  $g.FillRectangle((Brush $r.col), $barX, ($y + 6), [int]($barMax * $r.frac), 11)
  $y += 38
}

# --- what it is (left column) -----------------------------------------------------------
# Kept to ~38 characters: anything longer runs under the severity panel.
$lines = @(
  @{ t = 'Built-in engine - ZERO external tools'; c = $green },
  @{ t = 'gitleaks trivy semgrep snyk OSV Sonar'; c = $fgDim },
  @{ t = 'Roslyn - merged to one canonical set'; c = $fgDim },
  @{ t = 'MD  JSON  SARIF 2.1  Excel  Obsidian'; c = $fgDim },
  @{ t = 'Legacy ASP.NET is first-class'; c = $green }
)
$y = 262
foreach ($l in $lines) {
  $g.DrawString('>', $fBody, (Brush $cyan), ($M - 2), $y)
  $g.DrawString($l.t, $fBody, (Brush $l.c), ($M + 20), $y)
  $y += 30
}

# --- footer stat strip ------------------------------------------------------------------
$g.DrawLine((Pen $border 1), $M, 548, ($W - $M), 548)
$stats = '304-case catalog   -   zero dependencies   -   183 tests   -   MIT'
$g.DrawString($stats, $fSmall, (Brush $fgDim), ($M - 2), 566)
$g.DrawString('Windows / WSL / Linux', $fSmall, (Brush $fgDim), 990, 566)
$g.DrawString('github.com/Amrkadry/dotnet-codereview-framework', $fUrl, (Brush $cyan), ($M - 2), 596)

# --- save -------------------------------------------------------------------------------
$outDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\assets'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$out = Join-Path $outDir 'social-card.png'
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Output "WROTE $out"
Write-Output ("size: {0} bytes  dimensions: {1}x{2}" -f (Get-Item $out).Length, $W, $H)
