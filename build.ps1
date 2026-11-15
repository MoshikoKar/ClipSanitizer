# Build ClipSanitizer release assets expected by the in-app updater:
#   dist/ClipSanitizer-Setup.exe
#   dist/ClipSanitizer-portable.zip
#   dist/SHA256SUMS.txt
#
# Usage (from repo root, app closed):
#   .\build.ps1
#   .\build.ps1 -SkipInstaller   # portable + checksums only

[CmdletBinding()]
param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Tauri = Join-Path $Root "src-tauri"
$Dist = Join-Path $Root "dist"
$AppName = "ClipSanitizer"

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Get-ChildItem -LiteralPath $Dist -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "$AppName*" -or $_.Name -eq "SHA256SUMS.txt" } |
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

Push-Location $Tauri
try {
    Write-Host "Building release binary..."
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }

    if (-not $SkipInstaller) {
        Write-Host "Building NSIS installer (cargo tauri build)..."
        cargo tauri build --bundles nsis
        if ($LASTEXITCODE -ne 0) {
            Write-Host "cargo tauri not available or build failed; trying npx @tauri-apps/cli..."
            npx --yes @tauri-apps/cli@2 build --bundles nsis
            if ($LASTEXITCODE -ne 0) { throw "NSIS installer build failed" }
        }
    }
}
finally {
    Pop-Location
}

$ReleaseExe = Join-Path $Tauri "target\release\clip-sanitizer.exe"
if (-not (Test-Path -LiteralPath $ReleaseExe)) {
    throw "Missing release exe: $ReleaseExe"
}

$PortableDir = Join-Path $Dist "portable-staging"
New-Item -ItemType Directory -Force -Path $PortableDir | Out-Null
Copy-Item -LiteralPath $ReleaseExe -Destination (Join-Path $PortableDir "$AppName.exe") -Force
Set-Content -LiteralPath (Join-Path $PortableDir "portable.txt") -Value "portable" -NoNewline -Encoding ascii

$PortableZip = Join-Path $Dist "$AppName-portable.zip"
if (Test-Path -LiteralPath $PortableZip) { Remove-Item -LiteralPath $PortableZip -Force }
Compress-Archive -Path (Join-Path $PortableDir "*") -DestinationPath $PortableZip -Force
Remove-Item -LiteralPath $PortableDir -Recurse -Force

$SetupOut = Join-Path $Dist "$AppName-Setup.exe"
if (-not $SkipInstaller) {
    $NsisDir = Join-Path $Tauri "target\release\bundle\nsis"
    $SetupSrc = Get-ChildItem -LiteralPath $NsisDir -Filter "*-setup.exe" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $SetupSrc) {
        throw "NSIS setup exe not found under $NsisDir"
    }
    Copy-Item -LiteralPath $SetupSrc.FullName -Destination $SetupOut -Force
}

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$SumsPath = Join-Path $Dist "SHA256SUMS.txt"
$lines = @()
$lines += "$(Get-Sha256Hex $PortableZip)  $AppName-portable.zip"
if (Test-Path -LiteralPath $SetupOut) {
    $lines += "$(Get-Sha256Hex $SetupOut)  $AppName-Setup.exe"
}
Set-Content -LiteralPath $SumsPath -Value ($lines -join "`n") -Encoding ascii
Write-Host "Wrote:"
Get-ChildItem -LiteralPath $Dist | ForEach-Object { Write-Host "  $($_.FullName)" }
Get-Content -LiteralPath $SumsPath | ForEach-Object { Write-Host "  $_" }
