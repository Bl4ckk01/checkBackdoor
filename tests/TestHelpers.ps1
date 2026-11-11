# Supporto comune ai test: si carica con  . "$PSScriptRoot\TestHelpers.ps1"
# (Invoke-Tests.ps1 fa partire i test da un percorso senza [ ], quindi va bene).
# I moduli si caricano leggendone il testo, come fa CheckBackdoor.ps1.
#
# I campioni di comandi malevoli nei test sono innocui e composti a runtime: scritti per
# intero (un download in Base64, certutil -urlcache) farebbero bloccare il file da AMSI.

$script:ProjectRoot = Split-Path -Parent $PSScriptRoot

# Base64 di un comando innocuo, lungo quanto un payload vero
function New-HarmlessEncodedCommand {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "CheckBackdoor test"; Start-Sleep 0'))
}

function Get-ModuleScript {
    param([Parameter(Mandatory)][string]$Name)
    [scriptblock]::Create([IO.File]::ReadAllText((Join-Path $script:ProjectRoot "modules\$Name.ps1")))
}

# Una segnalazione minima, con i campi che Add-Finding produce
function New-TestFinding {
    param([string]$Severity = 'Medio', [string]$Category = 'Avvio automatico', [string]$Title = 'Voce di prova', [string]$Path, [string]$Evidence, [string[]]$Reasons = @('Motivo di prova'), [string]$Sha256)
    [pscustomobject]@{
        Id = (Get-FindingId $Category $Title $Path $Evidence); Check = 'Test'
        Category = $Category; Severity = $Severity; Title = $Title; Detail = $null; Path = $Path; Evidence = $Evidence
        Mitre = 'T1547.001'; Recommendation = 'Cosa fare di prova'; Reasons = $Reasons; Sha256 = $Sha256; Signer = $null; VirusTotal = $null
    }
}

# Caratteri accentati costruiti dal codice: i file di test restano ASCII, perche'
# Windows PowerShell 5.1 legge i .ps1 senza BOM con la codifica ANSI.
$script:Chr = @{ a = [string][char]0xE0; e = [string][char]0xE8; eAcute = [string][char]0xE9; EUpper = [string][char]0xC8; i = [string][char]0xEC; o = [string][char]0xF2; u = [string][char]0xF9 }
