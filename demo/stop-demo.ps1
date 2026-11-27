# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
Set-Location (Join-Path $PSScriptRoot "..")
if (Test-Path demo\.demo.pid) { Stop-Process -Id (Get-Content demo\.demo.pid) -ErrorAction SilentlyContinue; Remove-Item demo\.demo.pid }
try { docker compose down 2>$null } catch {}
Write-Host "RAT Flea DevSec demo stopped."
