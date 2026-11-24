# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# NERvvE DevSecOps — production-style stack on one Windows machine (Docker Desktop):
#   PostgreSQL 16 (row-level security) · Keycloak 26 (SSO + MFA) · OpenBao secret vault · NERvvE DevSecOps API + console · HTTPS proxy
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\setup-myelin.ps1        # once (creates .venv)
#   powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1    # start / restart
#   powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Stop
#   powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Reset   # delete all data
param([switch]$Stop, [switch]$Reset, [switch]$NoBrowser)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root
$EnvFile = Join-Path $Root (Join-Path "config" (Join-Path "backend" "enterprise.env"))
$Compose = @("compose", "-f", (Join-Path $Root "docker-compose.enterprise.yml"), "--env-file", $EnvFile)
$LicTool = Join-Path $Root (Join-Path "scripts" (Join-Path "licensing" "myelin_license.py"))
$KeysDir = Join-Path $Root (Join-Path "backend" (Join-Path "app" "licensing_keys"))
$Console = "https://myelin.localtest.me:8443"
$Issuer = "https://auth.localtest.me:8444/realms/myelin"
function Ok($m)   { Write-Host "  [ok]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [note] $m" -ForegroundColor Yellow }
function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Dc {   # simple function on purpose: $args passes flags such as -d through untouched
  # docker writes progress to stderr; print it as plain text so Windows PowerShell does not show it as errors
  $ErrorActionPreference = "Continue"; & docker @Compose @args 2>&1 | ForEach-Object { "$_" } | Out-Host; $c = $LASTEXITCODE
  $ErrorActionPreference = "Stop"; return $c }

. (Join-Path $PSScriptRoot "myelin-vault.ps1")

if ($Stop -or $Reset) {
  Step ($(if ($Reset) { "Stopping and DELETING all data" } else { "Stopping" }))
  if ($Reset) { Dc down -v | Out-Null } else { Dc down | Out-Null }
  Ok "stopped"; exit 0
}

function Sync-KeycloakClient([string]$Base, [string]$AdminUser, [string]$AdminPass, [string]$Secret) {
  # Keeps Keycloak's myelin-console client secret equal to MYELIN_OIDC_CLIENT_SECRET (it can drift if regenerated in the
  # admin console). Uses temp files for request bodies: Windows PowerShell 5.1 mangles quotes in native arguments.
  $ErrorActionPreference = "Continue"
  try {
    $tok = (& curl.exe -sk -X POST "$Base/realms/master/protocol/openid-connect/token" -d "grant_type=password" -d "client_id=admin-cli" `
             --data-urlencode "username=$AdminUser" --data-urlencode "password=$AdminPass" 2>$null) -join "" | ConvertFrom-Json
    if (-not $tok.access_token) { return "could not sign in to the Keycloak admin API" }
    $auth = "Authorization: Bearer $($tok.access_token)"
    $clients = (& curl.exe -sk -H $auth "$Base/admin/realms/myelin/clients?clientId=myelin-console" 2>$null) -join "" | ConvertFrom-Json
    if (-not $clients -or -not $clients[0].id) { return "realm 'myelin' or client 'myelin-console' not found - run with -Reset" }
    $id = $clients[0].id
    $cur = (& curl.exe -sk -H $auth "$Base/admin/realms/myelin/clients/$id/client-secret" 2>$null) -join "" | ConvertFrom-Json
    if ($cur.value -eq $Secret) { return "ok" }
    $rep = (& curl.exe -sk -H $auth "$Base/admin/realms/myelin/clients/$id" 2>$null) -join "" | ConvertFrom-Json
    $rep.secret = $Secret
    $tmp = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tmp, ($rep | ConvertTo-Json -Depth 20 -Compress), (New-Object System.Text.UTF8Encoding $false))
    $code = & curl.exe -sk -o NUL -w "%{http_code}" -X PUT -H $auth -H "Content-Type: application/json" --data-binary "@$tmp" "$Base/admin/realms/myelin/clients/$id" 2>$null
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($code -eq "204") { return "repaired" } else { return "update failed (HTTP $code)" }
  } catch { return "check failed: $($_.Exception.Message)" } finally { $ErrorActionPreference = "Stop" }
}

Step "Checking Docker Desktop"
$ErrorActionPreference = "Continue"; docker info *> $null; $dockerOk = ($LASTEXITCODE -eq 0); $ErrorActionPreference = "Stop"
if (-not $dockerOk) { throw "Docker is not running. Start Docker Desktop, wait until it says 'Engine running', then run this again." }
Ok "Docker engine running"

Step "Checking name resolution for *.localtest.me"
try { $ip = [System.Net.Dns]::GetHostAddresses("auth.localtest.me") | Select-Object -First 1 } catch { $ip = $null }
if (-not $ip -or $ip.ToString() -ne "127.0.0.1") {
  Warn "auth.localtest.me does not resolve to 127.0.0.1 (no internet DNS, or the router blocks it)."
  Warn "Fix: run Notepad as Administrator, open C:\Windows\System32\drivers\etc\hosts and add the line:"
  Warn "      127.0.0.1 myelin.localtest.me auth.localtest.me"
  throw "name resolution check failed"
}
Ok "myelin.localtest.me and auth.localtest.me -> 127.0.0.1"

$VPy = Join-Path $Root (Join-Path ".venv" (Join-Path "Scripts" "python.exe"))
if (-not (Test-Path $VPy)) { throw "Run scripts\windows\setup-myelin.ps1 first (it creates .venv)." }

Step "Secrets"
# Generated in PowerShell (no Python): Windows PowerShell 5.1 mangles quotes in multi-line native arguments.
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function New-Secret([int]$n) { $b = New-Object byte[] $n; $rng.GetBytes($b); ([Convert]::ToBase64String($b)).TrimEnd("=").Replace("+", "-").Replace("/", "_") }
function New-Key32 { $b = New-Object byte[] 32; $rng.GetBytes($b); [Convert]::ToBase64String($b) }
$required = [ordered]@{
  MYELIN_DB_OWNER_PASSWORD = { New-Secret 24 }; MYELIN_DB_APP_PASSWORD = { New-Secret 24 }; KEYCLOAK_DB_PASSWORD = { New-Secret 24 }
  KEYCLOAK_ADMIN_PASSWORD = { New-Secret 18 }; MYELIN_OIDC_CLIENT_SECRET = { New-Secret 32 }; MYELIN_SESSION_SECRET = { New-Secret 48 }
  MYELIN_API_KEY_PEPPER = { New-Secret 48 }; MYELIN_EVIDENCE_SIGNING_KEY = { New-Key32 }
}
$existing = @{}
if (Test-Path $EnvFile) {
  foreach ($l in Get-Content $EnvFile) { if ($l -match "^\s*([A-Z0-9_]+)=(.*)$") { $existing[$matches[1]] = $matches[2] } }
}
$added = @()
foreach ($k in $required.Keys) {
  if (-not $existing[$k]) { $existing[$k] = & $required[$k]; $added += $k }
}
if ($added.Count) {
  $out = foreach ($k in $existing.Keys | Sort-Object) { "$k=$($existing[$k])" }
  Set-Content -Path $EnvFile -Value ($out -join "`n") -Encoding ascii
  Ok "generated $($added.Count) secret(s) in $EnvFile (private; git-ignored)"
} else { Ok "all secrets present in $EnvFile" }

if (-not (Test-Path $LicTool)) {
  Ok "Community edition: no licence key needed (all features enabled)"
} elseif (-not (Select-String -Path $EnvFile -Pattern "^MYELIN_LICENSE=NMLIC1\." -Quiet)) {
  Step "Licence"
  $KeyDir = Join-Path $HOME "nerve-keys"
  $existing = Get-ChildItem $KeyDir -Filter "*.key" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $existing) {
    $kid = "nerve-local-" + (Get-Date -Format "yyyyMMdd")
    & $VPy $LicTool keygen --kid $kid --out (Join-Path $KeyDir "$kid.key")
    if ($LASTEXITCODE -ne 0) { throw "licence key generation failed" }
    $existing = Get-Item (Join-Path $KeyDir "$kid.key")
    Warn "Your vendor signing key is $($existing.FullName) - back it up; it is NOT in the repository."
  } else {
    $kid = $existing.BaseName
    if (-not (Test-Path (Join-Path $KeysDir "$kid.pem"))) {
      throw "Found $($existing.FullName) but its public key backend\app\licensing_keys\$kid.pem is missing. Copy it back or delete the key file to create a new one."
    }
  }
  $lic = Join-Path $env:TEMP "myelin-local.lic"
  & $VPy $LicTool issue --key $existing.FullName --licensee "NERvvE DevSecOps - local installation" `
      --plan enterprise --addons dast --max-tenants 5 --days 365 --out $lic | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "licence issue failed" }
  $token = (Get-Content $lic -Raw).Trim(); Remove-Item $lic
  $content = (Get-Content $EnvFile | Where-Object { $_ -notmatch "^MYELIN_LICENSE=" }) + "MYELIN_LICENSE=$token"
  Set-Content -Path $EnvFile -Value ($content -join "`n") -Encoding ascii
  Ok "365-day Enterprise licence installed (signed by $kid)"
}

Step "Building and starting (first run downloads ~1.5 GB and takes several minutes)"
if ((Dc up -d --build) -ne 0) {
  Write-Host "`n--- logs of the services that did not start (paste these when asking for help) ---" -ForegroundColor Yellow
  Dc logs --no-color --tail 60 migrate myelin-api keycloak | Out-Null
  throw "docker compose up failed - see the logs above"
}
Ok "containers started"

Step "Waiting for the platform"
$ready = $false
for ($i = 0; $i -lt 90; $i++) {
  $ErrorActionPreference = "Continue"
  $h = & curl.exe -sk --max-time 5 "$Console/api/health" 2>$null
  $k = & curl.exe -sk --max-time 5 "$Issuer/.well-known/openid-configuration" 2>$null
  $ErrorActionPreference = "Stop"
  if ($h -match '"mode":"enterprise"' -and $k -match '"issuer"') { $ready = $true; break }
  Start-Sleep 5
}
if (-not $ready) { throw "the platform did not become ready in 7 minutes. Check: docker compose -f docker-compose.enterprise.yml logs --tail 50" }
Ok "API, console and Keycloak are up"

Step "Keycloak client"
$envMap = @{}; foreach ($l in Get-Content $EnvFile) { if ($l -match "^([A-Z0-9_]+)=(.*)$") { $envMap[$matches[1]] = $matches[2] } }
$kcBase = $Issuer -replace "/realms/myelin$", ""
$r = Sync-KeycloakClient $kcBase "kcadmin" $envMap["KEYCLOAK_ADMIN_PASSWORD"] $envMap["MYELIN_OIDC_CLIENT_SECRET"]
switch ($r) { "ok" { Ok "client secret in Keycloak matches the platform" } "repaired" { Ok "client secret in Keycloak was different - re-synchronised" } default { Warn $r } }

Step "Secret vault (test-account credentials for live scans)"
Initialize-MyelinVault
Ok "vault unsealed; API holds a fresh read-only token"

Step "Tenants"
$ErrorActionPreference = "Continue"; $list = (& docker @Compose run --rm migrate admin tenants 2>$null) -join ""; $ErrorActionPreference = "Stop"
foreach ($t in @(@("acme", "Acme Bank"), @("globex", "Globex Insurance"))) {
  if ($list -match "`"slug`": `"$($t[0])`"") { Ok "$($t[1]) exists"; continue }
  if ((Dc run --rm migrate admin tenant-create --slug $t[0] --name $t[1] --plan enterprise --bind "$Issuer=$($t[0])") -ne 0) {
    throw "creating tenant $($t[0]) failed"
  }
  Ok "$($t[1]) created and bound to Keycloak"
}

Step "Trusting the local HTTPS certificate (one-time, for this Windows user)"
$crt = Join-Path $env:TEMP "myelin-local-ca.crt"
if ((Dc cp "edge:/data/caddy/pki/authorities/local/root.crt" $crt) -eq 0) {
  try {
    $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $crt).Thumbprint
    if (Get-ChildItem Cert:\CurrentUser\Root | Where-Object Thumbprint -eq $thumb) { Ok "already trusted" }
    else {
      Warn "Windows will ask you to confirm installing the 'Caddy Local Authority' certificate - choose Yes."
      Import-Certificate -FilePath $crt -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
      Ok "trusted (restart your browser if it was open)"
    }
  } catch { Warn "could not trust the local CA automatically ($($_.Exception.Message)); your browser will show a warning you can accept" }
} else { Warn "could not copy the local CA; your browser will show a certificate warning you can accept" }

$kcPass = ((Select-String -Path $EnvFile -Pattern "^KEYCLOAK_ADMIN_PASSWORD=").Line -split "=", 2)[1]
Write-Host "`nNERvvE DevSecOps is running." -ForegroundColor Cyan
Write-Host "  Console        $Console"
Write-Host "  Sign in as     alice-admin (tenant admin, Acme)  |  sam-lead (security lead)  |  audit-arun (auditor)"
Write-Host "                 gary-admin (admin of a second tenant, Globex - sees none of Acme's data)"
Write-Host "  First password ChangeMe!Myelin-2026  -> you will set a new password and scan a QR code with"
Write-Host "                 Microsoft Authenticator or Google Authenticator (MFA is mandatory)"
Write-Host "  Keycloak admin https://auth.localtest.me:8444/admin   user kcadmin   password $kcPass"
Write-Host "  Live-scan test accounts: powershell -ExecutionPolicy Bypass -File scripts\windows\myelin-secret.ps1 -Tenant globex -Name customer-a"
Write-Host "  Stop           powershell -ExecutionPolicy Bypass -File scripts\windows\start-enterprise.ps1 -Stop"
if (-not $NoBrowser) { Start-Process $Console }
