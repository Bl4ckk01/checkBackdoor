<#
.SYNOPSIS
    Prepares a CheckBackdoor release in dist\: app, installer, scripts and hashes.

.DESCRIPTION
    1. Runs the tests (unless -SkipTests).
    2. Publishes the self-contained app for Windows x64 (no .NET install needed).
    3. If you pass a certificate, signs CheckBackdoor.exe, the scripts and the installer.
    4. Creates:
       - CheckBackdoor-<version>-win-x64.zip   portable app
       - CheckBackdoor-<version>-setup.exe     installer (Inno Setup 6)
       - CheckBackdoor-<version>-script.zip    the PowerShell engine only
       - SHA256SUMS.txt                        hashes to verify the downloads

    Without a certificate the files stay unsigned: Windows SmartScreen will show a warning.
    You need a code signing certificate issued by a recognized authority; a self-signed
    certificate removes the warning for nobody but you.

.PARAMETER CertThumbprint
    Thumbprint of a code signing certificate in Cert:\CurrentUser\My.

.PARAMETER PfxPath
    Alternatively, a .pfx file (with -PfxPassword). The GitHub Actions release uses it.

.EXAMPLE
    .\tools\Build-Release.ps1
.EXAMPLE
    .\tools\Build-Release.ps1 -CertThumbprint 0123ABCD...
#>
[CmdletBinding()]
param(
    [string]$CertThumbprint,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = [regex]::Match([IO.File]::ReadAllText((Join-Path $root 'CheckBackdoor.ps1')), "\`$Version = '([\d.]+)'").Groups[1].Value
$csproj = Join-Path $root 'app\CheckBackdoor.App\CheckBackdoor.App.csproj'
$appVersion = [regex]::Match([IO.File]::ReadAllText($csproj), '<Version>([\d.]+)</Version>').Groups[1].Value
if (-not $version -or $version -ne $appVersion) { throw "Version mismatch: engine '$version', app '$appVersion'. Align them before the release." }

$dist = Join-Path $root 'dist'
$pub = Join-Path $dist "CheckBackdoor-$version-win-x64"
Remove-Item -LiteralPath $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dist -Force | Out-Null
Write-Host "CheckBackdoor $version" -ForegroundColor Cyan

# --- 1. Tests --------------------------------------------------------------------------
if (-not $SkipTests) {
    Write-Host '1/5 Tests' -ForegroundColor Cyan
    & (Join-Path $root 'tests\Invoke-Tests.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'The tests fail: release cancelled.' }
}

# --- 2. Self-contained app ---------------------------------------------------------------
Write-Host '2/5 Publishing the app' -ForegroundColor Cyan
& dotnet publish $csproj -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true -o $pub -nologo
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }
foreach ($need in 'CheckBackdoor.exe', 'ui\index.html', 'engine\CheckBackdoor.ps1', 'engine\Actions.ps1', 'engine\modules\Common.ps1') {
    if (-not (Test-Path -LiteralPath (Join-Path $pub $need))) { throw "$need is missing from the published app." }
}
Get-ChildItem -LiteralPath $pub -Filter '*.pdb' -Recurse | Remove-Item -Force

# --- 3. Signing (optional) ---------------------------------------------------------------
$cert = $null
if ($PfxPath) {
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword)
} elseif ($CertThumbprint) {
    $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertThumbprint"
}
$signtool = $null
if ($cert) {
    if ($cert.Subject -eq $cert.Issuer) { Write-Warning 'The certificate is self-signed: fine for testing, not for a public release.' }
    $signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if (-not $signtool) { throw 'signtool.exe not found: install the Windows SDK.' }
}
function Invoke-Sign([string[]]$Files) {
    if (-not $cert) { return }
    $exe = @($Files | Where-Object { $_ -match '\.(exe|dll)$' })
    if ($exe) {
        $a = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
        if ($PfxPath) { $a += @('/f', $PfxPath, '/p', $PfxPassword) } else { $a += @('/sha1', $cert.Thumbprint) }
        & $signtool.FullName @($a + $exe)
        if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }
    }
    foreach ($ps in @($Files | Where-Object { $_ -match '\.ps1$' })) {
        $r = Set-AuthenticodeSignature -FilePath $ps -Certificate $cert -TimestampServer $TimestampUrl -HashAlgorithm SHA256
        if ($r.Status -notin 'Valid', 'UnknownError') { throw "Signing $ps failed: $($r.StatusMessage)" }
    }
}
Write-Host "3/5 Signing: $(if ($cert) { $cert.Subject } else { 'no certificate, files left unsigned' })" -ForegroundColor Cyan
Invoke-Sign (@(Join-Path $pub 'CheckBackdoor.exe'; Join-Path $pub 'CheckBackdoor.dll') + @(Get-ChildItem -LiteralPath (Join-Path $pub 'engine') -Filter '*.ps1' -Recurse | ForEach-Object FullName))

# --- 4. Packages -------------------------------------------------------------------------
Write-Host '4/5 Packages' -ForegroundColor Cyan
# Compress-Archive in PowerShell 5.1 cannot handle paths with [ ]: .NET is used directly
Add-Type -AssemblyName System.IO.Compression.FileSystem
function New-Zip([string]$From, [string]$To) {
    [IO.Compression.ZipFile]::CreateFromDirectory($From, $To, [IO.Compression.CompressionLevel]::Optimal, $false)
}
New-Zip $pub (Join-Path $dist "CheckBackdoor-$version-win-x64.zip")

# The engine only, for those who prefer the script: same files as the repository, signed if there is a certificate
$scriptDir = Join-Path $dist "CheckBackdoor-$version-script"
New-Item -ItemType Directory -Path (Join-Path $scriptDir 'modules') -Force | Out-Null
foreach ($f in 'CheckBackdoor.ps1', 'Actions.ps1', 'Start-Scan.bat', 'Check-File.bat', 'allowlist.json', 'LICENSE', 'README.md', 'SECURITY.md', 'CHANGELOG.md') {
    $src = Join-Path $root $f
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $scriptDir }
}
Get-ChildItem -LiteralPath (Join-Path $root 'modules') -Filter '*.ps1' | Copy-Item -Destination (Join-Path $scriptDir 'modules')
Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination $scriptDir -Recurse
Invoke-Sign @(Get-ChildItem -LiteralPath $scriptDir -Filter '*.ps1' -Recurse | ForEach-Object FullName)
New-Zip $scriptDir (Join-Path $dist "CheckBackdoor-$version-script.zip")

$iscc = @(Get-ChildItem "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe', 'C:\Program Files\Inno Setup 6\ISCC.exe' -ErrorAction SilentlyContinue) | Select-Object -First 1
if ($iscc) {
    & $iscc.FullName /Q "/DAppVersion=$version" "/DSourceDir=$pub" "/DOutputDir=$dist" "/DRootDir=$root" (Join-Path $root 'installer\CheckBackdoor.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed.' }
    Invoke-Sign @(Join-Path $dist "CheckBackdoor-$version-setup.exe")
} else {
    Write-Warning 'Inno Setup 6 not found (winget install JRSoftware.InnoSetup): no installer, only the zips.'
}

# --- 5. Hashes ---------------------------------------------------------------------------
Write-Host '5/5 SHA-256 hashes' -ForegroundColor Cyan
$sums = Get-ChildItem -LiteralPath $dist -File | Where-Object { $_.Extension -in '.zip', '.exe' } | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
}
[IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS.txt'), [string[]]$sums)
Remove-Item -LiteralPath $scriptDir -Recurse -Force
Get-ChildItem -LiteralPath $dist -File | ForEach-Object { '{0,-40} {1,8:N1} MB' -f $_.Name, ($_.Length / 1MB) }
