# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# Add an organisation (tenant) to the local stack started by start-enterprise.ps1, and optionally link a Keycloak user
# to it with a role.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\new-tenant.ps1 -Slug rat-flea -Name "RAT Flea Labs"
#   powershell -ExecutionPolicy Bypass -File scripts\windows\new-tenant.ps1 -Slug rat-flea -Name "RAT Flea Labs" -User "sudheer kumar"
#   ... -Role myelin-security-lead      (default myelin-tenant-admin)
param(
  [Parameter(Mandatory = $true)][ValidatePattern("^[a-z0-9-]{2,40}$")][string]$Slug,
  [Parameter(Mandatory = $true)][string]$Name,
  [string]$User = "",
  [ValidateSet("myelin-tenant-admin", "myelin-security-lead", "myelin-developer", "myelin-auditor", "myelin-viewer")]
  [string]$Role = "myelin-tenant-admin"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$EnvFile = Join-Path $Root "config\backend\enterprise.env"
if (-not (Test-Path $EnvFile)) { throw "config\backend\enterprise.env not found - run scripts\windows\start-enterprise.ps1 first" }
$Compose = @("compose", "-f", (Join-Path $Root "docker-compose.enterprise.yml"), "--env-file", $EnvFile)
$Issuer = "https://auth.localtest.me:8444/realms/myelin"
$KcBase = "https://auth.localtest.me:8444"
function Ok($m)   { Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [note] $m" -ForegroundColor Yellow }

# 1. Organisation in the platform, bound to the Keycloak realm with claim value = slug
$ErrorActionPreference = "Continue"
$list = (& docker @Compose run --rm migrate admin tenants 2>$null) -join ""
if ($list -match "`"slug`": `"$Slug`"") { Ok "organisation '$Slug' already exists" }
else {
  & docker @Compose run --rm migrate admin tenant-create --slug $Slug --name $Name --plan enterprise --bind "$Issuer=$Slug" 2>&1 |
    ForEach-Object { "$_" } | Out-Host
  if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = "Stop"; throw "creating organisation '$Slug' failed (is the stack running?)" }
  Ok "organisation '$Name' ($Slug) created and bound to Keycloak"
}
$ErrorActionPreference = "Stop"

if (-not $User) {
  Write-Host "`nNext: in Keycloak ($KcBase/admin, realm 'myelin') open Users, pick or create a user, set the field"
  Write-Host "'RAT Flea DevSec tenant' to '$Slug', assign a role such as myelin-tenant-admin, then sign in again."
  Write-Host "Or re-run this script with -User <username> to do that for you."
  exit 0
}

# 2. Link a Keycloak user: tenant attribute + realm role (temp files: Windows PowerShell 5.1 mangles quotes in native args)
$envMap = @{}; foreach ($l in Get-Content $EnvFile) { if ($l -match "^([A-Z0-9_]+)=(.*)$") { $envMap[$matches[1]] = $matches[2] } }
$tok = (& curl.exe -sk -X POST "$KcBase/realms/master/protocol/openid-connect/token" -d "grant_type=password" -d "client_id=admin-cli" `
         --data-urlencode "username=kcadmin" --data-urlencode "password=$($envMap['KEYCLOAK_ADMIN_PASSWORD'])") -join "" | ConvertFrom-Json
if (-not $tok.access_token) { throw "could not sign in to the Keycloak admin API (is Keycloak running?)" }
$auth = "Authorization: Bearer $($tok.access_token)"
$enc = [uri]::EscapeDataString($User)
$found = @((& curl.exe -sk -H $auth "$KcBase/admin/realms/myelin/users?username=$enc&exact=true") -join "" | ConvertFrom-Json)
if (-not $found -or -not $found[0].id) { throw "Keycloak user '$User' not found in realm 'myelin' (use the Username shown in Keycloak > Users)" }
$id = $found[0].id
$rep = (& curl.exe -sk -H $auth "$KcBase/admin/realms/myelin/users/$id") -join "" | ConvertFrom-Json
if (-not $rep.attributes) { $rep | Add-Member -NotePropertyName attributes -NotePropertyValue ([pscustomobject]@{}) }
$rep.attributes | Add-Member -NotePropertyName tenant -NotePropertyValue @($Slug) -Force
$utf8 = New-Object System.Text.UTF8Encoding $false
$tmp = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllText($tmp, ($rep | ConvertTo-Json -Depth 20 -Compress), $utf8)
$code = & curl.exe -sk -o NUL -w "%{http_code}" -X PUT -H $auth -H "Content-Type: application/json" --data-binary "@$tmp" "$KcBase/admin/realms/myelin/users/$id"
Remove-Item $tmp -ErrorAction SilentlyContinue
if ($code -ne "204") { throw "setting the tenant of '$User' failed (HTTP $code)" }
Ok "user '$User' linked to organisation '$Slug'"

$roleRep = (& curl.exe -sk -H $auth "$KcBase/admin/realms/myelin/roles/$Role") -join "" | ConvertFrom-Json
$tmp = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllText($tmp, ("[" + ($roleRep | ConvertTo-Json -Depth 5 -Compress) + "]"), $utf8)
$code = & curl.exe -sk -o NUL -w "%{http_code}" -X POST -H $auth -H "Content-Type: application/json" --data-binary "@$tmp" "$KcBase/admin/realms/myelin/users/$id/role-mappings/realm"
Remove-Item $tmp -ErrorAction SilentlyContinue
if ($code -ne "204") { throw "assigning role $Role to '$User' failed (HTTP $code)" }
Ok "role $Role assigned"
Write-Host "`nSign out of the console and sign in again as '$User' to open $Name." -ForegroundColor Cyan
