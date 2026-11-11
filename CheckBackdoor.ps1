<#
.SYNOPSIS
    Cerca backdoor, RAT, miner e altri segni di compromissione su Windows.

.DESCRIPTION
    Analizza in sola lettura i punti in cui un malware si nasconde per sopravvivere
    ai riavvii e comunicare con l'esterno: chiavi di avvio, attivita' pianificate,
    servizi e driver, sottoscrizioni WMI, processi, connessioni di rete, browser,
    esclusioni di Defender, account, certificati e file nelle cartelle utente.
    Non modifica e non cancella nulla. Produce un report HTML, JSON e CSV.

.PARAMETER Deep
    Scansione approfondita delle cartelle utente (piu' profonda, include le DLL). Piu' lenta.

.PARAMETER CompareLast
    Confronta con l'ultima scansione salvata e mostra cosa e' stato aggiunto o rimosso.

.PARAMETER CompareTo
    Confronta con uno specifico file scansione_*.json.

.PARAMETER VirusTotalApiKey
    Chiave API gratuita di VirusTotal: verifica gli hash dei file sospetti (invia solo l'hash).
    In alternativa imposta la variabile d'ambiente VT_API_KEY.

.PARAMETER VirusTotalKeyFile
    File con la chiave di VirusTotal cifrata con DPAPI per l'utente corrente (lo scrive
    l'app). La chiave non passa ne' dalla riga di comando ne' dalle variabili d'ambiente.

.PARAMETER AllowlistFile
    Lista bianca in piu', oltre ad allowlist.json e allowlist.local.json (la usa l'app per
    gli elementi che l'utente sceglie di ignorare).

.PARAMETER Skip
    Controlli da saltare: Persistence, ScheduledTasks, Services, Wmi, Processes, Network,
    Browser, Injections, Security, Accounts, Certificates, FileSystem, Timeline.

.PARAMETER File
    Controlla un solo file o una cartella PRIMA di aprirlo, invece di tutto il PC: firma,
    provenienza, struttura dell'eseguibile, trucchi contro gli antivirus, DLL sostituite.
    Il file viene solo letto, mai eseguito. Non servono i privilegi di amministratore.

.PARAMETER EventsFile
    Scrive l'avanzamento e le segnalazioni, mentre arrivano, in questo file (una riga JSON
    per evento, formato in docs\EVENTI.md). Serve a un'interfaccia che segue la scansione.

.PARAMETER Quiet
    Nessun output in console (e nessuna finestra visibile se serve rilanciarsi come
    amministratore). Da usare insieme a -EventsFile.

.EXAMPLE
    .\CheckBackdoor.ps1
.EXAMPLE
    .\CheckBackdoor.ps1 -CompareLast -VirusTotalApiKey 0123abc...
.EXAMPLE
    .\CheckBackdoor.ps1 -File "$env:USERPROFILE\Downloads\setup.exe"
.EXAMPLE
    .\CheckBackdoor.ps1 -EventsFile "$env:TEMP\scan.jsonl" -Quiet -NoOpen
#>
[CmdletBinding()]
param(
    [string]$File,
    [string]$OutputDir,
    [switch]$Deep,
    [switch]$CompareLast,
    [string]$CompareTo,
    [string]$VirusTotalApiKey = $env:VT_API_KEY,
    [string]$VirusTotalKeyFile,
    [string]$AllowlistFile,
    [int]$VirusTotalMax = 20,
    [string[]]$Skip = @(),
    [string]$EventsFile,
    [switch]$Quiet,
    [switch]$NoOpen,
    [switch]$NoElevate,
    [switch]$PauseAtEnd
)

$Version = '1.2.0'
$ErrorActionPreference = 'Continue'
$ProgressPreference = if ($Quiet) { 'SilentlyContinue' } else { 'Continue' }
if (-not $OutputDir) { $OutputDir = Join-Path $PSScriptRoot 'report' }

# Con "powershell -File" una lista "A,B" arriva come stringa unica: la dividiamo qui
$validChecks = 'Persistence', 'ScheduledTasks', 'Services', 'Wmi', 'Processes', 'Network', 'Browser', 'Injections', 'Security', 'Accounts', 'Certificates', 'FileSystem', 'Timeline'
$Skip = @($Skip | ForEach-Object { $_ -split '\s*,\s*' } | Where-Object { $_ })
foreach ($s in $Skip) {
    if ($s -notin $validChecks) { throw "Controllo sconosciuto in -Skip: '$s'. Valori ammessi: $($validChecks -join ', ')" }
}

# Percorsi assoluti: il processo rilanciato come amministratore parte da System32,
# dove un percorso relativo indicherebbe un'altra cartella.
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
if ($PSBoundParameters.ContainsKey('OutputDir')) { $PSBoundParameters['OutputDir'] = $OutputDir }
if ($EventsFile) {
    $EventsFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EventsFile)
    $PSBoundParameters['EventsFile'] = $EventsFile
}
foreach ($pathParam in 'VirusTotalKeyFile', 'AllowlistFile') {
    $v = Get-Variable -Name $pathParam -ValueOnly
    if ($v) {
        $v = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($v)
        Set-Variable -Name $pathParam -Value $v
        $PSBoundParameters[$pathParam] = $v
    }
}
# Controllo di un solo file: leggere un file non richiede l'amministratore
if ($File) {
    $File = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)
    if (-not (Test-Path -LiteralPath $File)) { throw "File o cartella non trovato: $File" }
    $NoElevate = [switch]$true
}

# --- Caricamento moduli ----------------------------------------------------
# Lettura esplicita del testo: funziona anche con percorsi che contengono [ ]
$script:EngineRoot = $PSScriptRoot
$modules = 'Common', 'Persistence', 'AutorunExtra', 'ScheduledTasks', 'Services', 'Wmi', 'Processes', 'Network', 'Browser', 'Injections', 'Security', 'Accounts', 'Certificates', 'FileSystem', 'Timeline', 'FileCheck', 'VirusTotal', 'Report'
# Un antivirus puo' mettere in quarantena un modulo: meglio dirlo chiaramente che fallire a meta'
$missingModules = @($modules | Where-Object { -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "modules\$_.ps1")) })
if ($missingModules) {
    $msg = "Mancano dei file di CheckBackdoor: modules\$($missingModules -join '.ps1, modules\').ps1. " +
        "Di solito li ha messi in quarantena l'antivirus, perche' CheckBackdoor legge gli stessi punti del sistema che legge un malware. " +
        "Ripristinali dalla quarantena (o scarica di nuovo il progetto) e aggiungi la cartella alle esclusioni dell'antivirus."
    if ($EventsFile) {
        $line = [ordered]@{ schema = 'checkbackdoor.events/1'; seq = 1; time = (Get-Date).ToString('o'); pid = $PID; type = 'scan.failed'; data = [ordered]@{ message = $msg } } | ConvertTo-Json -Compress -Depth 4
        [IO.File]::AppendAllText($EventsFile, $line + "`n")
    }
    if (-not $Quiet) { Write-Host "`n  $msg`n" -ForegroundColor Red }
    if ($PauseAtEnd) { Read-Host '  Premi Invio per chiudere' | Out-Null }
    exit 4
}
foreach ($m in $modules) {
    # Non $file: in PowerShell sarebbe lo stesso nome del parametro -File
    $modulePath = Join-Path $PSScriptRoot "modules\$m.ps1"
    . ([scriptblock]::Create([IO.File]::ReadAllText($modulePath)))
}
$script:QuietMode = [bool]$Quiet
if (-not $VirusTotalApiKey -and $VirusTotalKeyFile) { $VirusTotalApiKey = Read-ProtectedSecret -Path $VirusTotalKeyFile }
if ($EventsFile) {
    $dir = Split-Path -Parent $EventsFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $script:EventSink = $EventsFile
}

function Write-Console {
    param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray, [switch]$NoNewline)
    if (-not $script:QuietMode) { Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline }
}

# Un errore imprevisto chiude la scansione con un evento, cosi' l'interfaccia non resta in attesa.
# Un trap vale per tutto lo script, anche per gli errori prima del caricamento dei moduli
# (come un -Skip sbagliato): in quel caso non c'e' ancora nessun file di eventi.
trap {
    if (Get-Command Write-ScanEvent -ErrorAction SilentlyContinue) {
        Write-ScanEvent 'scan.failed' ([ordered]@{ message = $_.Exception.Message; check = $script:CurrentCheck })
    }
    break
}

# --- Richiesta privilegi di amministratore --------------------------------
if (-not $script:IsAdmin -and -not $NoElevate) {
    Write-Console 'Richiedo i privilegi di amministratore (servono per leggere esclusioni di Defender, WMI e processi di sistema)...' Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-NoElevate')
    if (-not $Quiet) { $argList += '-PauseAtEnd' }
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Key -in 'NoElevate', 'PauseAtEnd') { continue }
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        elseif ($kv.Value -is [array]) { $argList += "-$($kv.Key)"; $argList += ($kv.Value -join ',') }
        else { $argList += "-$($kv.Key)"; $argList += "`"$($kv.Value)`"" }
    }
    $windowStyle = if ($Quiet) { 'Hidden' } else { 'Normal' }
    # Scritto prima di lanciare: gli eventi successivi arrivano dal processo
    # amministratore (stesso file, altro pid) o, se l'UAC viene negato, da questo
    Write-ScanEvent 'scan.elevating' ([ordered]@{ message = 'Richiesta dei privilegi di amministratore.' })
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle $windowStyle -ErrorAction Stop
        return
    } catch {
        Write-ScanWarning 'Privilegi negati: proseguo come utente normale, alcuni controlli saranno incompleti.'
    }
}

$banner = @'

   ____ _               _    ____             _       _
  / ___| |__   ___  ___| | _| __ )  __ _  ___| | ____| | ___   ___  _ __
 | |   | '_ \ / _ \/ __| |/ /  _ \ / _` |/ __| |/ / _` |/ _ \ / _ \| '__|
 | |___| | | |  __/ (__|   <| |_) | (_| | (__|   < (_| | (_) | (_) | |
  \____|_| |_|\___|\___|_|\_\____/ \__,_|\___|_|\_\__,_|\___/ \___/|_|

'@
Write-Console $banner Cyan
Write-Console "  Versione $Version - analisi in sola lettura, nessun file viene modificato.`n"

$checks = @(
    @{ Id = 'Security'; Label = 'Difese di Windows (Defender, esclusioni, UAC, aggiornamenti)'; Run = { Invoke-CheckSecurity } }
    @{ Id = 'Persistence'; Label = 'Punti di avvio automatico (registro, cartelle Esecuzione automatica, IFEO, COM)'; Run = { Invoke-CheckPersistence } }
    @{ Id = 'ScheduledTasks'; Label = "Attivita' pianificate (anche quelle nascoste)"; Run = { Invoke-CheckScheduledTasks } }
    @{ Id = 'Services'; Label = "Servizi, driver e Modalita' provvisoria"; Run = { Invoke-CheckServices } }
    @{ Id = 'Wmi'; Label = 'Sottoscrizioni WMI permanenti'; Run = { Invoke-CheckWmi } }
    @{ Id = 'Processes'; Label = 'Processi in esecuzione e uso della CPU'; Run = { Invoke-CheckProcesses } }
    @{ Id = 'Network'; Label = 'Rete (porte, connessioni, hosts, proxy, firewall, controllo remoto)'; Run = { Invoke-CheckNetwork } }
    @{ Id = 'Browser'; Label = 'Browser (estensioni, criteri, collegamenti)'; Run = { Invoke-CheckBrowser } }
    @{ Id = 'Injections'; Label = 'Iniezioni nelle app (Discord, wallet di criptovalute)'; Run = { Invoke-CheckInjections } }
    @{ Id = 'Accounts'; Label = 'Account utente e accesso remoto'; Run = { Invoke-CheckAccounts } }
    @{ Id = 'Certificates'; Label = 'Certificati radice'; Run = { Invoke-CheckCertificates } }
    @{ Id = 'FileSystem'; Label = "File sospetti in AppData, Temp, ProgramData$(if ($Deep) { ' (approfondita)' })"; Run = { Invoke-CheckFileSystem -Deep:$Deep } }
    @{ Id = 'Timeline'; Label = 'Linea temporale (registri eventi e programmi avviati negli ultimi 30 giorni)'; Run = { Invoke-CheckTimeline } }
)
$toRun = @($checks | Where-Object { $Skip -notcontains $_.Id })
$mode = 'Scan'
if ($File) {
    $mode = 'File'
    $toRun = @(@{ Id = 'File'; Label = "Controllo di $(Split-Path -Leaf $File)"; Run = { Invoke-CheckFile -Path $File } })
}

# La lista bianca si applica mentre la scansione gira: allowlist.json e' l'esempio
# condiviso, allowlist.local.json la lista personale (ignorata da git)
# Non vale per il controllo di un file: chi lo chiede esplicitamente vuole il risultato
if ($mode -eq 'Scan') {
    Import-Allowlist -Path (Join-Path $PSScriptRoot 'allowlist.json'), (Join-Path $PSScriptRoot 'allowlist.local.json'), $AllowlistFile
}

$start = Get-Date
Write-ScanEvent 'scan.started' ([ordered]@{
    version = $Version; mode = $mode; target = $File; computer = $env:COMPUTERNAME; user = "$env:USERDOMAIN\$env:USERNAME"; admin = $script:IsAdmin
    deep = [bool]$Deep; skipped = $Skip; compareTo = $CompareTo; compareLast = [bool]$CompareLast; virusTotal = [bool]$VirusTotalApiKey
    outputDir = $OutputDir; checks = @($toRun | ForEach-Object { [ordered]@{ id = $_.Id; label = $_.Label } })
})
if (-not $script:IsAdmin -and $mode -eq 'Scan') { Write-ScanWarning 'Non sei amministratore: i risultati saranno incompleti.' }

# Esegue un passo della scansione con i suoi eventi di inizio e fine
function Invoke-ScanStep {
    param([string]$Id, [string]$Label, [scriptblock]$Run, [int]$Index, [int]$Total)
    $script:CurrentCheck = $Id
    Write-ScanEvent 'check.started' ([ordered]@{ id = $Id; label = $Label; index = $Index; total = $Total })
    if ($Total) { Write-Progress -Activity 'CheckBackdoor' -Status $Label -PercentComplete (100 * ($Index - 1) / $Total) }
    Write-Console ("[{0,2}/{1}] {2}" -f $Index, $Total, $Label) -NoNewline
    $before = $script:Findings.Count
    $t0 = Get-Date
    $status = 'ok'; $message = $null
    try {
        & $Run
    } catch {
        $status = 'error'; $message = $_.Exception.Message
        $script:ScanErrors += "$($Label): $message"
    }
    $ms = [int]((Get-Date) - $t0).TotalMilliseconds
    $n = $script:Findings.Count - $before
    if ($status -eq 'ok') { Write-Console (" ... ok ({0:N0}s, {1} segnalazioni)" -f ($ms / 1000), $n) DarkGray }
    else { Write-Console " ... errore: $message" Red }
    Write-ScanEvent 'check.completed' ([ordered]@{ id = $Id; status = $status; error = $message; durationMs = $ms; findings = $n })
    $script:CurrentCheck = $null
}

# Annullamento: chi segue gli eventi crea "<file eventi>.cancel". Un file e non un
# segnale al processo, perche' un'app normale non puo' fermare un processo amministratore.
# Si controlla tra un passo e l'altro.
function Stop-IfCancelRequested {
    if (-not $EventsFile) { return }
    $flag = "$EventsFile.cancel"
    if (Test-Path -LiteralPath $flag) {
        Remove-Item -LiteralPath $flag -Force -ErrorAction SilentlyContinue
        Write-ScanEvent 'scan.cancelled' ([ordered]@{ durationMs = [int]((Get-Date) - $start).TotalMilliseconds; message = 'Verifica annullata.' })
        Write-Console "`nVerifica annullata." Yellow
        exit 3
    }
}

$script:ScanErrors = @()
$i = 0
foreach ($c in $toRun) {
    $i++
    Stop-IfCancelRequested
    Invoke-ScanStep -Id $c.Id -Label $c.Label -Run $c.Run -Index $i -Total $toRun.Count
}
Stop-IfCancelRequested
Write-Progress -Activity 'CheckBackdoor' -Completed

if ($VirusTotalApiKey) {
    Write-Console 'Verifica degli hash su VirusTotal (viene inviato solo l''hash, non il file)...'
    # Nel controllo di un file si verifica anche il file "pulito": e' la domanda principale
    Invoke-ScanStep -Id 'VirusTotal' -Label 'Verifica degli hash su VirusTotal' -Run { Invoke-VirusTotalLookup -ApiKey $VirusTotalApiKey -Max $VirusTotalMax -IncludeInfo:($mode -eq 'File') }
}

# Confronto con una scansione precedente (non ha senso per il controllo di un file)
if ($mode -eq 'File') { $CompareLast = $false; $CompareTo = $null }
if ($CompareLast -and -not $CompareTo) {
    $last = Get-ChildItem -LiteralPath $OutputDir -Filter 'scansione_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($last) { $CompareTo = $last.FullName } else { Write-ScanWarning 'Nessuna scansione precedente trovata da confrontare.' }
}
if ($CompareTo) {
    Invoke-ScanStep -Id 'Compare' -Label 'Confronto con la scansione precedente' -Run { Compare-WithPrevious -PreviousJson $CompareTo }
}

$meta = @{
    Version = $Version; Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"
    Date = (Get-Date).ToString('dd/MM/yyyy HH:mm'); Duration = $(
        $span = (Get-Date) - $start
        if ($span.TotalMinutes -ge 1) { '{0} min {1} s' -f [int][Math]::Floor($span.TotalMinutes), $span.Seconds } else { '{0} s' -f [int]$span.TotalSeconds })
    Admin = $script:IsAdmin; Deep = [bool]$Deep; ComparedTo = $CompareTo; Ignored = $script:IgnoredCount; Errors = $script:ScanErrors
    Skipped = $Skip; VirusTotal = [bool]$VirusTotalApiKey; Mode = $mode; Target = $File
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
}
# "controllo_" per i singoli file: -CompareLast cerca solo le scansioni complete ("scansione_")
$report = Export-Results -OutputDir $OutputDir -Meta $meta -Prefix $(if ($mode -eq 'File') { 'controllo' } else { 'scansione' })

$counts = $script:Findings | Group-Object Severity -AsHashTable -AsString
$n = { param($s) if ($counts -and $counts[$s]) { $counts[$s].Count } else { 0 } }
$exitCode = if ((& $n 'Alto') -gt 0) { 2 } elseif ((& $n 'Medio') -gt 0) { 1 } else { 0 }
Write-ScanEvent 'scan.completed' ([ordered]@{
    exitCode = $exitCode; durationMs = [int]((Get-Date) - $start).TotalMilliseconds; ignored = $script:IgnoredCount
    counts = [ordered]@{ Alto = (& $n 'Alto'); Medio = (& $n 'Medio'); Basso = (& $n 'Basso'); Info = (& $n 'Info') }
    errors = $script:ScanErrors
    report = [ordered]@{ html = $report; json = [IO.Path]::ChangeExtension($report, '.json'); csv = [IO.Path]::ChangeExtension($report, '.csv') }
})

# --- Riepilogo in console -------------------------------------------------
Write-Console ''
Write-Console '================ RIEPILOGO ================'
Write-Console ("  Rischio alto   : {0}" -f (& $n 'Alto')) Red
Write-Console ("  Da verificare  : {0}" -f (& $n 'Medio')) Yellow
Write-Console ("  Rischio basso  : {0}" -f (& $n 'Basso')) Cyan
Write-Console ("  Informazioni   : {0}" -f (& $n 'Info')) DarkGray
foreach ($f in $script:Findings | Where-Object Severity -eq 'Alto' | Select-Object -First 15) {
    Write-Console "  [ALTO] $($f.Category): $($f.Title)" Red
}
Write-Console "`nReport: $report"

if (-not $NoOpen) { Invoke-Item -LiteralPath $report }
if ($PauseAtEnd) { Read-Host "`nPremi INVIO per chiudere" | Out-Null }

exit $exitCode
