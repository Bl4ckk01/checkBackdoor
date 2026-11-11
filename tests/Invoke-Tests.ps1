<#
.SYNOPSIS
    Esegue i test di CheckBackdoor con Pester 5 o successivo.
.EXAMPLE
    .\tests\Invoke-Tests.ps1                  # tutti i test
    .\tests\Invoke-Tests.ps1 -ExcludeTag E2E  # senza la scansione end-to-end (piu' veloce)
    .\tests\Invoke-Tests.ps1 -CI              # per GitHub Actions: risultati in testResults.xml
#>
param(
    [string[]]$Tag,
    [string[]]$ExcludeTag,
    [switch]$CI
)
$ErrorActionPreference = 'Stop'
$pester = Get-Module -ListAvailable Pester | Where-Object Version -ge '5.5.0' | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    throw 'Serve Pester 5.5 o successivo: Install-Module Pester -Scope CurrentUser -SkipPublisherCheck'
}
Import-Module $pester.Path -Force

$projectRoot = Split-Path -Parent $PSScriptRoot

# Pester non sa eseguire file in cartelle con [ ] nel nome (come "[Progetti]"):
# in quel caso i test partono da una giunzione temporanea senza parentesi.
$junction = $null
$testRoot = $projectRoot
if ($projectRoot -match '[\[\]]') {
    $junction = Join-Path ([IO.Path]::GetTempPath()) ("checkbackdoor-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    cmd /c mklink /J "$junction" "$projectRoot" | Out-Null
    if (-not (Test-Path -LiteralPath $junction)) { throw "Impossibile creare la giunzione $junction" }
    $testRoot = $junction
}

try {
    $config = New-PesterConfiguration
    $config.Run.Path = @(Get-ChildItem -LiteralPath (Join-Path $testRoot 'tests') -Filter '*.Tests.ps1' | ForEach-Object { $_.FullName })
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    if ($Tag) { $config.Filter.Tag = $Tag }
    if ($ExcludeTag) { $config.Filter.ExcludeTag = $ExcludeTag }
    if ($CI) {
        $config.TestResult.Enabled = $true
        # Attraverso la giunzione: Pester non sa scrivere in percorsi con [ ]
        $config.TestResult.OutputPath = Join-Path $testRoot 'testResults.xml'
    }
    $result = Invoke-Pester -Configuration $config
} finally {
    # rmdir su una giunzione rimuove solo il collegamento, non i file del progetto
    if ($junction) { cmd /c rmdir "$junction" | Out-Null }
}
# Nessun risultato significa che Pester stesso si e' interrotto: e' un fallimento
if (-not $result -or $result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) { exit 1 }
