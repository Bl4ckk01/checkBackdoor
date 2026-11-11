<#
.SYNOPSIS
    Prepara una release di CheckBackdoor in dist\: app, installatore, script e impronte.

.DESCRIPTION
    1. Esegue i test (salvo -SkipTests).
    2. Pubblica l'app autonoma per Windows x64 (non serve installare .NET).
    3. Se indichi un certificato, firma CheckBackdoor.exe, gli script e l'installatore.
    4. Crea:
       - CheckBackdoor-<versione>-win-x64.zip   app portatile
       - CheckBackdoor-<versione>-setup.exe     installatore per l'utente (Inno Setup 6)
       - CheckBackdoor-<versione>-script.zip    solo il motore PowerShell
       - SHA256SUMS.txt                         impronte per verificare i download

    Senza certificato i file restano non firmati: Windows SmartScreen mostrera' un avviso.
    Serve un certificato di firma del codice rilasciato da un'autorita' riconosciuta; un
    certificato autofirmato non toglie l'avviso a nessuno tranne che a te.

.PARAMETER CertThumbprint
    Impronta di un certificato di firma del codice in Cert:\CurrentUser\My.

.PARAMETER PfxPath
    In alternativa, un file .pfx (con -PfxPassword). Lo usa la release su GitHub Actions.

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
if (-not $version -or $version -ne $appVersion) { throw "Versioni diverse: motore '$version', app '$appVersion'. Allineale prima della release." }

$dist = Join-Path $root 'dist'
$pub = Join-Path $dist "CheckBackdoor-$version-win-x64"
Remove-Item -LiteralPath $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dist -Force | Out-Null
Write-Host "CheckBackdoor $version" -ForegroundColor Cyan

# --- 1. Test -----------------------------------------------------------------------
if (-not $SkipTests) {
    Write-Host '1/5 Test' -ForegroundColor Cyan
    & (Join-Path $root 'tests\Invoke-Tests.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'I test non passano: release annullata.' }
}

# --- 2. App autonoma -----------------------------------------------------------------
Write-Host '2/5 Pubblicazione dell''app' -ForegroundColor Cyan
& dotnet publish $csproj -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true -o $pub -nologo
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish non riuscito.' }
foreach ($need in 'CheckBackdoor.exe', 'ui\index.html', 'engine\CheckBackdoor.ps1', 'engine\Azioni.ps1', 'engine\modules\Common.ps1') {
    if (-not (Test-Path -LiteralPath (Join-Path $pub $need))) { throw "Manca $need nell'app pubblicata." }
}
Get-ChildItem -LiteralPath $pub -Filter '*.pdb' -Recurse | Remove-Item -Force

# --- 3. Firma (facoltativa) -----------------------------------------------------------------
$cert = $null
if ($PfxPath) {
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword)
} elseif ($CertThumbprint) {
    $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertThumbprint"
}
$signtool = $null
if ($cert) {
    if ($cert.Subject -eq $cert.Issuer) { Write-Warning 'Il certificato e'' autofirmato: va bene per provare, non per una release pubblica.' }
    $signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if (-not $signtool) { throw 'signtool.exe non trovato: installa Windows SDK.' }
}
function Invoke-Sign([string[]]$Files) {
    if (-not $cert) { return }
    $exe = @($Files | Where-Object { $_ -match '\.(exe|dll)$' })
    if ($exe) {
        $a = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
        if ($PfxPath) { $a += @('/f', $PfxPath, '/p', $PfxPassword) } else { $a += @('/sha1', $cert.Thumbprint) }
        & $signtool.FullName @($a + $exe)
        if ($LASTEXITCODE -ne 0) { throw 'Firma non riuscita.' }
    }
    foreach ($ps in @($Files | Where-Object { $_ -match '\.ps1$' })) {
        $r = Set-AuthenticodeSignature -FilePath $ps -Certificate $cert -TimestampServer $TimestampUrl -HashAlgorithm SHA256
        if ($r.Status -notin 'Valid', 'UnknownError') { throw "Firma di $ps non riuscita: $($r.StatusMessage)" }
    }
}
Write-Host "3/5 Firma: $(if ($cert) { $cert.Subject } else { 'nessun certificato, file non firmati' })" -ForegroundColor Cyan
Invoke-Sign (@(Join-Path $pub 'CheckBackdoor.exe'; Join-Path $pub 'CheckBackdoor.dll') + @(Get-ChildItem -LiteralPath (Join-Path $pub 'engine') -Filter '*.ps1' -Recurse | ForEach-Object FullName))

# --- 4. Pacchetti ---------------------------------------------------------------------------------
Write-Host '4/5 Pacchetti' -ForegroundColor Cyan
# Compress-Archive di PowerShell 5.1 non regge i percorsi con [ ]: si usa .NET direttamente
Add-Type -AssemblyName System.IO.Compression.FileSystem
function New-Zip([string]$From, [string]$To) {
    [IO.Compression.ZipFile]::CreateFromDirectory($From, $To, [IO.Compression.CompressionLevel]::Optimal, $false)
}
New-Zip $pub (Join-Path $dist "CheckBackdoor-$version-win-x64.zip")

# Solo il motore, per chi preferisce lo script: stessi file della repository, firmati se c'e' il certificato
$scriptDir = Join-Path $dist "CheckBackdoor-$version-script"
New-Item -ItemType Directory -Path (Join-Path $scriptDir 'modules') -Force | Out-Null
foreach ($f in 'CheckBackdoor.ps1', 'Azioni.ps1', 'Avvia-Scansione.bat', 'Controlla-File.bat', 'allowlist.json', 'LICENSE', 'README.md', 'README.en.md', 'SECURITY.md', 'CHANGELOG.md') {
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
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup non riuscito.' }
    Invoke-Sign @(Join-Path $dist "CheckBackdoor-$version-setup.exe")
} else {
    Write-Warning 'Inno Setup 6 non trovato (winget install JRSoftware.InnoSetup): niente installatore, solo gli zip.'
}

# --- 5. Impronte ------------------------------------------------------------------------------------------
Write-Host '5/5 Impronte SHA-256' -ForegroundColor Cyan
$sums = Get-ChildItem -LiteralPath $dist -File | Where-Object { $_.Extension -in '.zip', '.exe' } | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
}
[IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS.txt'), [string[]]$sums)
Remove-Item -LiteralPath $scriptDir -Recurse -Force
Get-ChildItem -LiteralPath $dist -File | ForEach-Object { '{0,-40} {1,8:N1} MB' -f $_.Name, ($_.Length / 1MB) }
