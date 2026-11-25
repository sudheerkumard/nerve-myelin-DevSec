# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
#
# Save-NetworkCA: on networks that inspect HTTPS, save the company CA certificates to config\certs so container
# builds trust them (see config\certs\README.md). Dot-sourced by start-enterprise.ps1 and demo\start-demo.ps1.
function Save-NetworkCA([string]$Root) {
  # Corporate networks that inspect HTTPS re-sign traffic with the company root certificate. Windows trusts it; a
  # container build does not, so pip fails with CERTIFICATE_VERIFY_FAILED. Detect that and hand the image build the
  # company CA certificates (config\certs, git-ignored). Certificate checking is never switched off.
  $dir = Join-Path $Root (Join-Path "config" "certs")
  if (Get-ChildItem $dir -Filter "*.crt" -ErrorAction SilentlyContinue) { Write-Host "  [ok]   using the CA certificates in config\certs" -ForegroundColor Green; return }
  try {
    $tcp = New-Object Net.Sockets.TcpClient("pypi.org", 443)
    $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false)
    $ssl.AuthenticateAsClient("pypi.org")
    $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    [void]$chain.Build($leaf)
    $ssl.Dispose(); $tcp.Close()
  } catch { Write-Host "  [note] could not check the network's HTTPS certificates ($($_.Exception.Message)); continuing" -ForegroundColor Yellow; return }
  $certs = @($chain.ChainElements | ForEach-Object { $_.Certificate })
  $rootCert = $certs[-1]
  if ($rootCert.Subject -match "GlobalSign|DigiCert|ISRG|Sectigo|USERTrust|Amazon|Baltimore|GTS Root|Google Trust|Starfield|Go Daddy|Entrust|Microsoft") {
    Write-Host "  [ok]   no HTTPS inspection on this network" -ForegroundColor Green; return
  }
  New-Item -ItemType Directory -Force $dir | Out-Null
  $i = 0
  foreach ($c in ($certs | Select-Object -Skip 1)) {
    $b64 = [Convert]::ToBase64String($c.RawData) -replace '(.{64})', "`$1`n"
    $pem = "-----BEGIN CERTIFICATE-----`n" + $b64.TrimEnd("`n") + "`n-----END CERTIFICATE-----`n"
    [IO.File]::WriteAllText((Join-Path $dir ("network-ca-{0}.crt" -f $i)), $pem)
    $i++
  }
  if ($i -eq 0) { Write-Host "  [note] HTTPS inspection suspected but no CA certificate could be exported; see config\certs\README.md" -ForegroundColor Yellow; return }
  Write-Host "  [ok]   HTTPS inspection detected (root: $($rootCert.Subject)); saved $i CA certificate(s) to config\certs for the image build" -ForegroundColor Green
}
