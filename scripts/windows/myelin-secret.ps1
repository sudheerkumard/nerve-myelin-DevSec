# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# Store a live-scan test account's credential in the local secret vault and print the reference to paste into the
# console (Live app testing -> Register target -> Test identities). The value is typed hidden and never shown again.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\myelin-secret.ps1 -Tenant globex -Name customer-a
#
#   -Tenant   organisation slug of the account you sign in with (alice-admin/sam-lead: acme, gary-admin: globex)
#   -Name     identity name, e.g. customer-a, customer-b, admin
#   -Field    header the value is sent in (default Authorization). Enter the full header value, e.g. "Bearer eyJ..."
[CmdletBinding(PositionalBinding = $false)]   # every value must be named: stray words are an error, not a header or a token
param([Parameter(Mandatory = $true)][string]$Tenant, [Parameter(Mandatory = $true)][string]$Name,
      [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{1,63}$')][string]$Field = "Authorization",
      [ValidateSet("customer", "admin", "user")][string]$Role = "customer",
      [string]$Value = "")   # optional, for automation only: an interactive (hidden) prompt keeps the token out of shell history
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$EnvFile = Join-Path $Root (Join-Path "config" (Join-Path "backend" "enterprise.env"))
$Compose = @("compose", "-f", (Join-Path $Root "docker-compose.enterprise.yml"), "--env-file", $EnvFile)
. (Join-Path $PSScriptRoot "myelin-vault.ps1")

$Name = $Name.ToLowerInvariant()
if ($Name -cnotmatch '^[a-z0-9][a-z0-9._-]{0,62}$') { throw "Name may contain lower-case letters, digits, '.', '_' and '-' only (e.g. customer-a)" }
$tid = Get-MyelinTenantId $Tenant
$root = Get-BaoRootToken

if ($Value) { $val = $Value } else {
  $sec = Read-Host -AsSecureString "$Field header value for '$Name' (e.g. Bearer eyJ...) - input is hidden"
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try { $val = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
if (-not $val.Trim()) { throw "no value entered" }
if ($Field -eq "Authorization" -and $val -notmatch '^(Bearer|Basic|Token|Digest|ApiKey) \S{8,}') {
  throw "an Authorization value normally looks like 'Bearer eyJ...' (scheme, space, token). Nothing was stored."
}

$path = "secret/myelin/tenants/$tid/dast/$Name"
$o = Invoke-Bao @("kv", "put", $path, "token=-") $root $val      # value goes through stdin, never the command line
$val = $null
if ($script:BaoExit -ne 0) { throw "storing the secret failed: $o" }

$ref = "vault://$path#token"
Write-Host "`n  [ok]   stored '$Name' for organisation '$Tenant' in the local vault" -ForegroundColor Green
Write-Host "`nReference:" -ForegroundColor Cyan
Write-Host "  $ref"
Write-Host "`nIdentity line for the console (Test identities):" -ForegroundColor Cyan
Write-Host "  {`"name`": `"$Name`", `"role`": `"$Role`", `"headers`": {`"$Field`": `"$ref`"}}"
