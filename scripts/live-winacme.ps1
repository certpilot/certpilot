# Does win-acme get certificates from the core's ACME server?
#
# win-acme is how most Windows servers run ACME, and it runs only on Windows,
# so it cannot join the Linux checks in live-acme.sh. This runs it, as
# released, on a Windows machine against a core built from this tree and the
# released self-signed gateway, both started here:
#
#   registers with a credential and is issued a certificate, recorded as held
#   by the client; then renews it, and the record is renewed in place
#
# win-acme refuses a plain-HTTP directory like lego does, so the core is put
# behind a TLS proxy whose CA is added to the machine's trusted roots for the
# run and removed after it. Needs Go and an administrator shell, which a
# GitHub Windows runner has. Exit status is the verdict.
#
#   pwsh ./scripts/live-winacme.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root = (Resolve-Path "$PSScriptRoot/..").Path
$Work = Join-Path $Root '.live/winacme'
if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
New-Item -ItemType Directory -Force "$Work/bin", "$Work/tlsproxy", "$Work/pem" | Out-Null

$CorePort = 18095
$GwPort = 19095
$TlsPort = 18496
$Api = "http://127.0.0.1:$CorePort"
$Directory = "https://localhost:$TlsPort/acme/live-web/directory"
$GwVersion = ((Get-Content "$Root/Makefile" | Select-String '^GW_VERSION\s*:=\s*(\S+)').Matches[0].Groups[1].Value)
$WacsVersion = 'v2.2.9.1701'
$WacsZip = "win-acme.$WacsVersion.x64.trimmed.zip"
$WacsSha256 = 'f4dc3b144841ffdba391ce168c273d7a686d45a359075e30ee4bf4ee186857d6'

$started = @()
$trusted = $null

function Say($m) { Write-Host $m }
function Pass($m) { Write-Host "  ok   $m" }
function Die($m) {
  Write-Host "FAIL: $m"
  # Without the bootstrap password the core prints at start: a CI log is
  # public, and a throwaway password is still a password.
  foreach ($log in 'core.log', 'core.out') {
    if (Test-Path "$Work/$log") {
      Write-Host "-- $log"
      Get-Content "$Work/$log" -Tail 25 | Where-Object { $_ -notmatch 'password' }
    }
  }
  throw $m
}

try {
  # ── The self-signed gateway, then the core ──────────────────────────────────

  Say "starting the self-signed gateway on :$GwPort ($GwVersion)"
  $env:GOWORK = 'off'; $env:GOBIN = "$Work/bin"
  go install "github.com/certpilot/certpilot-gateway-selfsigned/cmd@$GwVersion"
  if ($LASTEXITCODE -ne 0) { Die "could not fetch the self-signed gateway $GwVersion" }
  Remove-Item Env:GOWORK, Env:GOBIN
  $started += Start-Process "$Work/bin/cmd.exe" -ArgumentList "--port=$GwPort", '--insecure' -PassThru -NoNewWindow `
    -RedirectStandardOutput "$Work/gw.out" -RedirectStandardError "$Work/gw.log"

  @"
server:
  host: 127.0.0.1
  port: $CorePort
  mode: development
auth:
  bootstrap_admins:
    - admin@certpilot.local
plugins:
  tls:
    insecure: true
  gateways:
    - name: selfsigned
      addr: 127.0.0.1:$GwPort
      type: selfsigned
acme:
  enabled: true
  external_url: https://localhost:$TlsPort
"@ | Set-Content "$Work/core.yaml"

  Say 'building the core'
  Push-Location $Root
  go build -o "$Work/certpilot-core.exe" ./core/cmd/
  $built = $LASTEXITCODE
  Pop-Location
  if ($built -ne 0) { Die 'the core did not build' }
  # Cleared so an exported one cannot point this at a real database.
  $env:CERTPILOT_DB_URL = ''
  $started += Start-Process "$Work/certpilot-core.exe" -ArgumentList "--config=$Work/core.yaml" -PassThru -NoNewWindow `
    -RedirectStandardOutput "$Work/core.out" -RedirectStandardError "$Work/core.log"

  $logs = { (Get-Content "$Work/core.log", "$Work/core.out" -Raw -ErrorAction SilentlyContinue) -join "`n" }
  $deadline = (Get-Date).AddSeconds(120)
  while (-not ((& $logs) -match 'gateway registered successfully')) {
    if ((Get-Date) -gt $deadline) { Die 'the core never registered the gateway' }
    Start-Sleep -Milliseconds 200
  }
  while (-not ((& $logs) -match 'password:\s+(\S+)')) {
    if ((Get-Date) -gt $deadline) { Die 'the core printed no bootstrap password' }
    Start-Sleep -Milliseconds 200
  }
  $password = $Matches[1]
  while (-not ((& $logs) -match 'created the first administrator')) {
    if ((Get-Date) -gt $deadline) { Die 'the core never created the bootstrap administrator' }
    Start-Sleep -Milliseconds 200
  }
  Invoke-RestMethod -Method Post "$Api/api/v1/auth/login" -ContentType 'application/json' -SessionVariable session `
    -Body (@{ email = 'admin@certpilot.local'; password = $password } | ConvertTo-Json) | Out-Null
  Pass 'core up, gateway registered, signed in'

  function Api($method, $path, $body) {
    $request = @{ Method = $method; Uri = "$Api$path"; WebSession = $session; ContentType = 'application/json' }
    if ($body) { $request.Body = ($body | ConvertTo-Json -Depth 5) }
    Invoke-RestMethod @request
  }

  # ── A template and a credential ─────────────────────────────────────────────

  $ca = Api Post '/api/v1/ca-accounts' @{ name = 'selfsigned'; provider_type = 'selfsigned'; gateway_addr = "127.0.0.1:$GwPort" }
  $caId = if ($ca.data) { $ca.data.id } else { $ca.id }
  Api Post '/api/v1/certificate-templates' @{
    slug = 'live-web'; name = 'Live web'; ca_account_id = $caId; subject_mode = 'SUPPLIED'
    allowed_key_types = @('RSA', 'ECDSA'); key_custody_required = 'ANY'; renew_before_days = 30; is_enabled = $true
    san_rules = @{ suffixes = @('.example.com') }
  } | Out-Null
  $cred = Api Post '/api/v1/acme/credentials' @{ name = 'win-acme'; template = 'live-web' }

  function Record($name) {
    @((Api Get '/api/v1/certificates?limit=500' $null).data | Where-Object {
      $_.discovered_via -eq 'ACME' -and ($_.common_name -eq $name -or $_.sans -contains $name) })
  }

  # ── TLS in front of it ──────────────────────────────────────────────────────
  #
  # The proxy makes its own CA and certificate as it starts and writes the CA
  # out, so the run needs no openssl.

  @'
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	target, _ := url.Parse(os.Args[1])
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CertPilot live-winacme CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	_ = os.WriteFile(os.Args[3], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	srv := &http.Server{Addr: os.Args[2], Handler: httputil.NewSingleHostReverseProxy(target),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}}}
	panic(srv.ListenAndServeTLS("", ""))
}
'@ | Set-Content "$Work/tlsproxy/main.go"
  "module tlsproxy`n`ngo 1.26`n" | Set-Content "$Work/tlsproxy/go.mod"
  Push-Location "$Work/tlsproxy"
  $env:GOWORK = 'off'
  go build -o "$Work/bin/tlsproxy.exe" .
  $built = $LASTEXITCODE
  Remove-Item Env:GOWORK
  Pop-Location
  if ($built -ne 0) { Die 'could not build the TLS proxy' }
  # Loopback only: nothing off this machine needs to reach it.
  $started += Start-Process "$Work/bin/tlsproxy.exe" -ArgumentList $Api, "127.0.0.1:$TlsPort", "$Work/ca.pem" -PassThru -NoNewWindow `
    -RedirectStandardOutput "$Work/tlsproxy.out" -RedirectStandardError "$Work/tlsproxy.log"
  $deadline = (Get-Date).AddSeconds(30)
  while (-not (Test-Path "$Work/ca.pem")) {
    if ((Get-Date) -gt $deadline) { Die 'the TLS proxy never wrote its CA' }
    Start-Sleep -Milliseconds 200
  }
  $trusted = Import-Certificate -FilePath "$Work/ca.pem" -CertStoreLocation Cert:\LocalMachine\Root
  $deadline = (Get-Date).AddSeconds(30)
  while ($true) {
    try { Invoke-WebRequest $Directory -UseBasicParsing | Out-Null; break } catch {
      if ((Get-Date) -gt $deadline) { Die "the directory never answered through the TLS proxy: $_" }
      Start-Sleep -Milliseconds 300
    }
  }

  # ── win-acme ────────────────────────────────────────────────────────────────

  Say "fetching win-acme $WacsVersion"
  Invoke-WebRequest "https://github.com/win-acme/win-acme/releases/download/$WacsVersion/$WacsZip" -OutFile "$Work/wacs.zip"
  $sum = (Get-FileHash "$Work/wacs.zip" -Algorithm SHA256).Hash.ToLower()
  if ($sum -ne $WacsSha256) { Die "win-acme's zip is not the one pinned: $sum" }
  Expand-Archive "$Work/wacs.zip" "$Work/wacs"
  $wacs = "$Work/wacs/wacs.exe"

  $common = @('--baseuri', $Directory, '--notaskscheduler', '--closeonfinish')
  $out = & $wacs @common --source manual --host winacme.example.com --store pemfiles --pemfilespath "$Work/pem" `
    --installation none --accepttos --emailaddress ops@example.com `
    --eab-key-identifier $cred.data.kid --eab-key $cred.hmac_key 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Die "win-acme was not issued a certificate:`n$out" }
  $r = Record 'winacme.example.com'
  if ($r.Count -ne 1 -or $r[0].key_custody -ne 'EXTERNAL' -or $r[0].auto_renew) {
    Die "win-acme's certificate is not recorded as held by the client: $($r | ConvertTo-Json -Compress)`n$out"
  }
  if (-not (Get-ChildItem "$Work/pem" -Filter '*.pem')) { Die "win-acme wrote no PEM files:`n$out" }
  Pass 'win-acme: registered with a credential and issued, recorded as the client''s key'

  $out = & $wacs @common --renew --force --nocache 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Die "win-acme could not renew:`n$out" }
  $r = Record 'winacme.example.com'
  if ($r.Count -ne 1 -or $r[0].renewal_count -ne 1) {
    Die "win-acme's renewal did not renew the record in place: $($r | ConvertTo-Json -Compress)`n$out"
  }
  Pass 'win-acme: renewed in place'

  Say "winacme: every check passed — win-acme $WacsVersion against the core's ACME server"
}
finally {
  foreach ($p in $started) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
  if ($trusted) { Remove-Item "Cert:\LocalMachine\Root\$($trusted.Thumbprint)" -ErrorAction SilentlyContinue }
}
