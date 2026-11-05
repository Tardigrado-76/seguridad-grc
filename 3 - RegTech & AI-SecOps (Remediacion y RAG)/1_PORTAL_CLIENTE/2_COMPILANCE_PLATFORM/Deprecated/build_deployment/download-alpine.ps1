$ErrorActionPreference = 'Stop'

$DOMPURIFY_VERSION  = '3.1.6'
$DOMPURIFY_URL      = "https://cdn.jsdelivr.net/npm/dompurify@$DOMPURIFY_VERSION/dist/purify.min.js"
$DOMPURIFY_SHA384   = 'sha384-+VfUPEb0PdtChMwmBcBmykRMDd+v6D/oFmB3rZM/puCMDYcIvF968OimRh4KQY9a'

$ALPINE_VERSION     = '3.14.1'
$ALPINE_URL         = "https://cdn.jsdelivr.net/npm/alpinejs@$ALPINE_VERSION/dist/cdn.min.js"
$ALPINE_SHA384      = 'sha384-l8f0VcPi/M1iHPv8egOnY/15TDwqgbOR1anMIJWvU6nLRgZVLTLSaNqi/TOoT5Fh'

function Test-FileIntegrity {
  param([string]$Path, [string]$ExpectedHash)
  $bytes  = [System.IO.File]::ReadAllBytes($Path)
  $sha384 = [System.Security.Cryptography.SHA384]::Create()
  $b64    = [System.Convert]::ToBase64String($sha384.ComputeHash($bytes))
  $actual = "sha384-$b64"
  if ($actual -ne $ExpectedHash) {
    Remove-Item $Path -Force
    throw "[SECURITY-GATE] Integrity check FAILED for $Path`n  Expected: $ExpectedHash`n  Actual:   $actual"
  }
  Write-Host "[OK] $Path - $actual" -ForegroundColor Green
  return $actual
}

if (-not (Test-Path 'static')) {
    New-Item -ItemType Directory -Force -Path 'static' | Out-Null
}

Write-Host "Downloading DOMPurify v$DOMPURIFY_VERSION..."
Invoke-WebRequest -Uri $DOMPURIFY_URL -OutFile 'static/dompurify.min.js'

Write-Host "Downloading AlpineJS v$ALPINE_VERSION..."
Invoke-WebRequest -Uri $ALPINE_URL -OutFile 'static/alpine.min.js'

$manifest = @{
  dompurify = Test-FileIntegrity -Path "$PWD/static/dompurify.min.js" -ExpectedHash $DOMPURIFY_SHA384
  alpine    = Test-FileIntegrity -Path "$PWD/static/alpine.min.js" -ExpectedHash $ALPINE_SHA384
}

# Preserve css and wasm if they exist in an older manifest
$manifestPath = "$PWD/static/.sri-manifest.json"
if (Test-Path $manifestPath) {
    try {
        $oldManifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($oldManifest.css) { $manifest.css = $oldManifest.css }
        if ($oldManifest.wasm) { $manifest.wasm = $oldManifest.wasm }
    } catch {}
}

$manifest | ConvertTo-Json | Set-Content $manifestPath -Encoding UTF8
Write-Host "SRI manifest generated at $manifestPath" -ForegroundColor Cyan
