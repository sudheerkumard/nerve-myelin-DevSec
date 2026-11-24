# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# NERvvE DevSecOps — first-time setup on a Windows laptop (PowerShell 5.1 or 7+). Run from the repository folder:
#   powershell -ExecutionPolicy Bypass -File scripts\windows\setup-myelin.ps1                # CLI only
#   powershell -ExecutionPolicy Bypass -File scripts\windows\setup-myelin.ps1 -WithConsole   # + local console
# Creates .venv, installs the myelin CLI (and the console backend with -WithConsole), checks optional tools,
# and runs a self-test. Safe to re-run.
param([switch]$WithConsole)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
function Ok($m)   { Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [note] $m" -ForegroundColor Yellow }
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }

Step "Checking Python (3.10 or newer)"
$py = $null
foreach ($c in @("py -3.12", "py -3.11", "py -3.10", "python", "python3")) {
  $parts = $c.Split(" ")
  if (Get-Command $parts[0] -ErrorAction SilentlyContinue) {
    $v = $null
    try {
      $ErrorActionPreference = "Continue"        # PowerShell 5.1 turns redirected stderr into errors
      $v = & $parts[0] @($parts[1..9] | Where-Object { $_ }) -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { $v = $null } finally { $ErrorActionPreference = "Stop" }
    if ($LASTEXITCODE -eq 0 -and $v -and [version]"$v" -ge [version]"3.10") { $py = $parts; Ok "Python $v ($c)"; break }
  }
}
if (-not $py) {
  throw "Python 3.10+ not found. Install it with:  winget install -e --id Python.Python.3.12   then open a new PowerShell window and re-run."
}

Step "Creating virtual environment .venv"
if (-not (Test-Path ".venv")) { & $py[0] @($py[1..9] | Where-Object { $_ }) -m venv .venv }
$VPy = if (Test-Path ".venv\Scripts\python.exe") { (Resolve-Path ".venv\Scripts\python.exe").Path } else { (Resolve-Path ".venv/bin/python").Path }
Ok $VPy

Step "Installing the myelin CLI"
& $VPy -m pip install -q --upgrade pip
& $VPy -m pip install -q -e .
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
if ($WithConsole) {
  & $VPy -m pip install -q -r backend\requirements.txt
  if ($LASTEXITCODE -ne 0) { throw "console dependencies failed to install" }
  Ok "console backend installed (start it with demo\start-demo.ps1)"
}
& $VPy -c "import myelin_engine, sys; print('  [ok]   myelin', myelin_engine.__version__)"

Step "Optional tools"
foreach ($t in @(@("git", "source checkout"), @("docker", "OWASP ZAP scans (--zap) and container scans"), @("trivy", "container image scans"), @("gitleaks", "extra secret detection"))) {
  if (Get-Command $t[0] -ErrorAction SilentlyContinue) { Ok "$($t[0]) found" } else { Warn "$($t[0]) not found - needed only for $($t[1])" }
}

Step "Self-test"
$ErrorActionPreference = "Continue"                 # Windows PowerShell 5.1 treats any stderr text as an error
$env:PYTHONIOENCODING = "utf-8"
$self = & $VPy -m myelin_engine.cli dast --help 2>&1 | Out-String
$code = $LASTEXITCODE
Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue
$ErrorActionPreference = "Stop"
if ($code -ne 0) {
  Write-Host $self
  throw "self-test failed (exit $code) - copy the output above when asking for help"
}
Ok "myelin dast is ready"

Write-Host "`nSetup complete. In every new PowerShell window, activate the environment first:" -ForegroundColor Cyan
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "Then scan an API you are authorised to test, for example:"
Write-Host '    $env:MYELIN_DAST_AUTH = "Bearer <token>"      # only if the API needs a login'
Write-Host "    myelin dast --target https://api.example.com --openapi https://api.example.com/swagger/v1/swagger.json --json result.json --sarif result.sarif"
Write-Host "Guide: docs\DAST-QUICKSTART.md"
