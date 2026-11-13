<#
.SYNOPSIS
    Runs the CheckBackdoor tests with Pester 5 or later.
.EXAMPLE
    .\tests\Invoke-Tests.ps1                  # all tests
    .\tests\Invoke-Tests.ps1 -ExcludeTag E2E  # without the end-to-end scan (faster)
    .\tests\Invoke-Tests.ps1 -CI              # for GitHub Actions: results in testResults.xml
#>
param(
    [string[]]$Tag,
    [string[]]$ExcludeTag,
    [switch]$CI
)
$ErrorActionPreference = 'Stop'
$pester = Get-Module -ListAvailable Pester | Where-Object Version -ge '5.5.0' | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    throw 'Pester 5.5 or later is needed: Install-Module Pester -Scope CurrentUser -SkipPublisherCheck'
}
Import-Module $pester.Path -Force

$projectRoot = Split-Path -Parent $PSScriptRoot

# Pester cannot run files in folders with [ ] in their name (like "[Projects]"):
# in that case the tests start from a temporary junction without brackets.
$junction = $null
$testRoot = $projectRoot
if ($projectRoot -match '[\[\]]') {
    $junction = Join-Path ([IO.Path]::GetTempPath()) ("checkbackdoor-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    cmd /c mklink /J "$junction" "$projectRoot" | Out-Null
    if (-not (Test-Path -LiteralPath $junction)) { throw "Cannot create the junction $junction" }
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
        # Through the junction: Pester cannot write to paths with [ ]
        $config.TestResult.OutputPath = Join-Path $testRoot 'testResults.xml'
    }
    $result = Invoke-Pester -Configuration $config
} finally {
    # rmdir on a junction removes only the link, not the project files
    if ($junction) { cmd /c rmdir "$junction" | Out-Null }
}
# No result means Pester itself stopped: that is a failure
if (-not $result -or $result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0) { exit 1 }