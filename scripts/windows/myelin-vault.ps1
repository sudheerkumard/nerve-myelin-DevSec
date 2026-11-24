# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# Helpers for the local OpenBao secret vault of the evaluation stack. Dot-sourced by start-enterprise.ps1 and
# myelin-secret.ps1 (both define $Compose first). Works on Windows PowerShell 5.1 and PowerShell 7.

$BaoInitFile = Join-Path (Join-Path $HOME "nerve-keys") "openbao-init.json"   # unseal key + root token: never in the repository

function Invoke-Bao($Argv, $Token = "", $StdIn = $null) {
  # Runs `bao` inside the vault container. Returns the output as one string; exit code in $script:BaoExit.
  $ErrorActionPreference = "Continue"
  $x = @("exec", "-T")
  if ($Token) { $x += @("-e", "BAO_TOKEN=$Token") }
  $x += @("vault", "bao") + $Argv
  if ($null -ne $StdIn) { $out = $StdIn | & docker @Compose @x 2>&1 } else { $out = & docker @Compose @x 2>&1 }
  $script:BaoExit = $LASTEXITCODE
  $ErrorActionPreference = "Stop"
  return (($out | ForEach-Object { "$_" }) -join "`n")
}

function Get-BaoStatus {
  for ($i = 0; $i -lt 30; $i++) {
    $s = Invoke-Bao @("status", "-format=json")
    if ($script:BaoExit -eq 0 -or $script:BaoExit -eq 2) {     # 2 = sealed, still a valid answer
      try { return ($s.Substring($s.IndexOf("{")) | ConvertFrom-Json) } catch { }
    }
    Start-Sleep 2
  }
  throw "the secret vault did not respond. Check: docker compose -f docker-compose.enterprise.yml logs --tail 40 vault"
}

function Get-BaoRootToken {
  if (-not (Test-Path $BaoInitFile)) { throw "vault keys not found at $BaoInitFile - run start-enterprise.ps1 first" }
  return (Get-Content $BaoInitFile -Raw | ConvertFrom-Json).root_token
}

function Initialize-MyelinVault {
  # Initialise once, unseal on every start, ensure the KV engine and policy, and issue a fresh read-only token for the API.
  $st = Get-BaoStatus
  if (-not $st.initialized) {
    $init = Invoke-Bao @("operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json")
    if ($script:BaoExit -ne 0) { throw "vault initialisation failed: $init" }
    New-Item -ItemType Directory -Force (Split-Path $BaoInitFile) | Out-Null
    Set-Content -Path $BaoInitFile -Value $init.Substring($init.IndexOf("{")) -Encoding ascii
    Write-Host "  [note] Vault unseal key and root token saved to $BaoInitFile - back it up; it is NOT in the repository." -ForegroundColor Yellow
    $st = Get-BaoStatus
  }
  if (-not (Test-Path $BaoInitFile)) {
    throw "the vault is initialised but $BaoInitFile is missing. Restore that file, or run start-enterprise.ps1 -Reset (deletes all data)."
  }
  $keys = Get-Content $BaoInitFile -Raw | ConvertFrom-Json
  if ($st.sealed) {
    $null = Invoke-Bao @("operator", "unseal", $keys.unseal_keys_b64[0])
    if ((Get-BaoStatus).sealed) { throw "could not unseal the vault - is $BaoInitFile from this installation?" }
  }
  $root = $keys.root_token
  $mounts = Invoke-Bao @("secrets", "list", "-format=json") $root
  if ($script:BaoExit -ne 0) { throw "vault rejected the root token: $mounts" }
  if ($mounts -notmatch '"secret/"') {
    $o = Invoke-Bao @("secrets", "enable", "-path=secret", "kv-v2") $root
    if ($script:BaoExit -ne 0) { throw "enabling the key/value engine failed: $o" }
  }
  # The API reads test-account credentials and stores repository tokens pasted in the console (tenant paths only)
  $o = Invoke-Bao @("policy", "write", "myelin-dast-read", "-") $root 'path "secret/data/myelin/tenants/*" { capabilities = ["create", "read", "update"] } path "secret/metadata/myelin/tenants/*" { capabilities = ["delete"] }'
  if ($script:BaoExit -ne 0) { throw "writing the vault policy failed: $o" }
  $tok = (Invoke-Bao @("token", "create", "-policy=myelin-dast-read", "-orphan", "-period=768h", "-field=token") $root).Trim()
  if ($script:BaoExit -ne 0 -or -not $tok) { throw "issuing the API token failed: $tok" }
  $ErrorActionPreference = "Continue"
  $null = $tok | & docker @Compose exec -T vault sh -c "umask 077; tr -d '\r\n' > /openbao/token/api-token.new && chown 10001:10001 /openbao/token/api-token.new && mv /openbao/token/api-token.new /openbao/token/api-token" 2>&1
  $rc = $LASTEXITCODE; $ErrorActionPreference = "Stop"
  if ($rc -ne 0) { throw "handing the token to the API failed" }
}

function Get-MyelinTenantId([string]$Slug) {
  $ErrorActionPreference = "Continue"
  $raw = (& docker @Compose run --rm migrate admin tenants 2>$null) -join "`n"
  $ErrorActionPreference = "Stop"
  try { $list = $raw.Substring($raw.IndexOf("[")) | ConvertFrom-Json } catch { throw "could not list organisations - is the stack running?" }
  $t = @($list | Where-Object { $_.slug -eq $Slug })
  if (-not $t) { throw "no organisation '$Slug'. Available: $((@($list | ForEach-Object { $_.slug })) -join ', ')" }
  return $t[0].id
}
