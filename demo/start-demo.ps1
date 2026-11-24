# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# NERvvE DevSecOps — start the customer live demo on Windows: http://localhost:8080
#   powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1            # Python
#   powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1 -Docker    # Docker Desktop
param([switch]$Docker)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not $env:MYELIN_ENV_FILE) { $env:MYELIN_ENV_FILE = "config/backend/myelin.env.demo" }
$Url = "http://localhost:8080"

if ($Docker) {
  docker compose up --build -d
} else {
  $env:MYELIN_CONSOLE_PATH = (Join-Path (Get-Location) "demo\offline\NERvvE-DevSecOps-Demo-Console.html")
  if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3.10+ is required (or use -Docker)" }
  if (-not (Test-Path .venv)) { python -m venv .venv }
  & .\.venv\Scripts\python.exe -m pip install -q -r backend\requirements.txt
  & .\.venv\Scripts\python.exe -m pip install -q -e . | Out-Null
  & .\.venv\Scripts\python.exe scripts\build_console.py
  $p = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8080" `
       -WorkingDirectory "backend" -RedirectStandardOutput "demo\.demo.log" -RedirectStandardError "demo\.demo.err.log" -PassThru -WindowStyle Hidden
  $p.Id | Out-File demo\.demo.pid
}

for ($i = 0; $i -lt 30; $i++) { try { Invoke-RestMethod "$Url/api/health" | Out-Null; break } catch { Start-Sleep 1 } }
Invoke-RestMethod "$Url/api/health" | Out-Null
Write-Host "NERvvE DevSecOps demo running at $Url  (stop: demo\stop-demo.ps1)"
Start-Process $Url
