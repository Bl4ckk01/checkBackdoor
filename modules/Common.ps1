# Funzioni condivise da tutti i moduli: raccolta dei risultati, analisi dei file,
# analisi delle righe di comando e punteggio di rischio.

$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:Inventory = New-Object System.Collections.Generic.List[object]
$script:FileCache = @{}
$script:ProcessTable = $null
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Eventi per chi segue la scansione dal vivo (l'app con interfaccia).
# Formato descritto in docs/EVENTI.md: una riga JSON per evento, in append.
# ---------------------------------------------------------------------------

$script:EventSchema = 'checkbackdoor.events/1'
$script:EventSink = $null      # percorso completo; $null = nessun evento
$script:EventSeq = 0
$script:CurrentCheck = $null    # controllo in corso, riportato in ogni segnalazione
$script:QuietMode = $false

function Write-ScanEvent {
    param([Parameter(Mandatory)][string]$Type, $Data = @{})
    if (-not $script:EventSink) { return }
    $script:EventSeq++
    $evt = [ordered]@{ schema = $script:EventSchema; seq = $script:EventSeq; time = (Get-Date).ToString('o'); pid = $PID; type = $Type; data = $Data }
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $evt -Depth 8 -Compress) + "`n")
    # Append con FileShare.ReadWrite: l'app legge il file mentre la scansione scrive
    for ($try = 0; $try -lt 5; $try++) {
        try {
            $fs = [IO.File]::Open($script:EventSink, 'Append', 'Write', 'ReadWrite')
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            return
        } catch { Start-Sleep -Milliseconds 50 }
    }
}

function Write-ScanWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-ScanEvent 'warning' ([ordered]@{ check = $script:CurrentCheck; message = $Message })
    if (-not $script:QuietMode) { Write-Warning $Message }
}

# ---------------------------------------------------------------------------
# Lista bianca: allowlist.json (condivisa) e allowlist.local.json (personale).
# Si applica mentre la scansione gira, cosi' chi segue gli eventi non vede mai
# comparire elementi che poi spariscono dal report.
# ---------------------------------------------------------------------------

$script:Allowlist = @{ Paths = @(); Hashes = @(); Titles = @(); Ids = @() }
$script:IgnoredCount = 0

function Import-Allowlist {
    param([string[]]$Path)
    $script:Allowlist = @{ Paths = @(); Hashes = @(); Titles = @(); Ids = @() }
    foreach ($p in $Path) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        try { $al = [IO.File]::ReadAllText($p) | ConvertFrom-Json } catch { Write-ScanWarning "$([IO.Path]::GetFileName($p)) non valido: $($_.Exception.Message)"; continue }
        $script:Allowlist.Paths += @($al.paths | Where-Object { $_ })
        $script:Allowlist.Hashes += @($al.sha256 | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
        $script:Allowlist.Titles += @($al.titles | Where-Object { $_ })
        # "ids": elementi ignorati dall'app, uno per uno (l'ID di Get-FindingId)
        $script:Allowlist.Ids += @($al.ids | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() })
    }
}

function Test-Allowlisted {
    param($Finding)
    foreach ($p in $script:Allowlist.Paths) {
        if (($Finding.Path -and $Finding.Path -like $p) -or ($Finding.Evidence -and $Finding.Evidence -like $p)) { return $true }
    }
    if ($Finding.Sha256 -and $script:Allowlist.Hashes -contains "$($Finding.Sha256)".ToUpperInvariant()) { return $true }
    foreach ($t in $script:Allowlist.Titles) { if ($Finding.Title -like $t) { return $true } }
    if ($Finding.Id -and $script:Allowlist.Ids -contains "$($Finding.Id)".ToLowerInvariant()) { return $true }
    return $false
}

# ID stabile di una segnalazione: lo stesso elemento ha lo stesso ID in ogni
# scansione, anche se VirusTotal ne cambia la gravita'. Serve all'app per
# "ignora" e per le azioni sul singolo elemento.
function Get-FindingId {
    param([string]$Category, [string]$Title, [string]$Path, [string]$Evidence)
    $key = ("$Category|$Title|$Path|$Evidence").ToLowerInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)) } finally { $sha.Dispose() }
    return (($hash[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------------------------------------------------------------------------
# Raccolta risultati
# ---------------------------------------------------------------------------

function ConvertTo-Severity {
    param([int]$Score)
    if ($Score -ge 60) { return 'Alto' }
    if ($Score -ge 35) { return 'Medio' }
    if ($Score -ge 15) { return 'Basso' }
    return 'Info'
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Alto', 'Medio', 'Basso', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [string]$Path,
        [string]$Evidence,
        [string]$Mitre,
        [string]$Recommendation,
        [string[]]$Reasons,
        [string]$Sha256,
        [string]$Signer,
        # Come disattivare l'elemento (Azioni.ps1): solo per i tipi che si possono annullare
        [hashtable]$Remedy
    )
    if ($Path -and [IO.Path]::IsPathRooted($Path)) {
        if (-not $Sha256) { $Sha256 = Get-FileSha256 $Path }
        if (-not $Signer) { $Signer = (Get-FileInfo $Path).Signer }
    }
    $finding = [pscustomobject]@{
        Id             = Get-FindingId $Category $Title $Path $Evidence
        Check          = $script:CurrentCheck
        Category       = $Category
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Path           = $Path
        Evidence       = $Evidence
        Mitre          = $Mitre
        Recommendation = $Recommendation
        Reasons        = @($Reasons | Where-Object { $_ })
        Sha256         = $Sha256
        Signer         = $Signer
        VirusTotal     = $null
        Remedy         = $Remedy
    }
    if (Test-Allowlisted $finding) { $script:IgnoredCount++; return }
    $script:Findings.Add($finding)
    Write-ScanEvent 'finding' ([ordered]@{ check = $script:CurrentCheck; finding = $finding })
}

# Ogni voce di avvio automatico finisce nell'inventario, anche se pulita:
# serve per confrontare due scansioni (-CompareTo) e vedere cosa e' cambiato.
function Add-InventoryItem {
    param([string]$Category, [string]$Key, [string]$Value)
    $script:Inventory.Add([pscustomobject]@{ Category = $Category; Key = $Key; Value = $Value })
}

# Registra una voce di persistenza: la mette in inventario e, se il punteggio e'
# abbastanza alto, la segnala come risultato.
function Register-AutorunEntry {
    param(
        [string]$Category,
        [string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Mitre,
        [int]$ExtraScore = 0,
        [string[]]$ExtraReasons,
        [hashtable]$Remedy,
        [string]$Recommendation = 'Se non riconosci questo programma, cerca il nome del file online, caricalo su virustotal.com e poi rimuovi la voce di avvio.'
    )
    Add-InventoryItem -Category $Category -Key "$Location | $Name" -Value $Command
    $risk = Get-CommandRisk -CommandLine $Command
    $score = $risk.Score + $ExtraScore
    $reasons = @($ExtraReasons) + @($risk.Reasons) | Where-Object { $_ }
    $severity = ConvertTo-Severity $score
    if ($severity -ne 'Info') {
        Add-Finding -Category $Category -Severity $severity -Title "$Name" `
            -Detail $Location -Path $risk.Target -Evidence $Command -Mitre $Mitre `
            -Reasons $reasons -Sha256 $risk.Sha256 -Signer $risk.Signer -Recommendation $Recommendation -Remedy $Remedy
    }
}

# ---------------------------------------------------------------------------
# Analisi dei file
# ---------------------------------------------------------------------------

$script:UserWritablePattern = '(?i)(\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents|Music|Videos|Pictures|Saved Games)\\|\\Users\\Public\\|^[A-Z]:\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\\$Recycle\.Bin\\|^[A-Z]:\\PerfLogs\\|\\Windows\\Tasks\\|\\Windows\\Debug\\|\\Windows\\Fonts\\|\\Windows\\Help\\|\\Windows\\addins\\|\\System32\\Tasks\\)'

function Test-UserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    # ProgramData\Microsoft\Windows Defender ospita file legittimi firmati Microsoft
    return ($Path -match $script:UserWritablePattern)
}

function Test-MicrosoftSigner {
    param([string]$Signer)
    return ($Signer -match '^Microsoft (Windows|Corporation)|^Microsoft Windows (Publisher|Production PCA)')
}

function Get-FileInfo {
    param([string]$Path)
    if (-not $Path) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:FileCache.ContainsKey($key)) { return $script:FileCache[$key] }

    $info = [pscustomobject]@{
        Path = $Path; Exists = $false; Size = 0; Created = $null; Modified = $null
        SignatureStatus = 'Unknown'; Signer = $null; IsMicrosoft = $false
        Sha256 = $null; Company = $null; Description = $null; OriginalName = $null; Hidden = $false
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and -not $item.PSIsContainer) {
        $info.Exists = $true
        $info.Size = $item.Length
        $info.Created = $item.CreationTime
        $info.Modified = $item.LastWriteTime
        $info.Hidden = [bool]($item.Attributes -band ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
        try {
            $vi = $item.VersionInfo
            $info.Company = $vi.CompanyName
            $info.Description = $vi.FileDescription
            $info.OriginalName = $vi.OriginalFilename
        } catch { }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $info.SignatureStatus = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $info.Signer = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            }
            $info.IsMicrosoft = ($info.SignatureStatus -eq 'Valid' -and (Test-MicrosoftSigner $info.Signer))
        } catch { }
        # Le app del Microsoft Store non hanno una firma nel singolo file: e' firmato il
        # pacchetto, verificato da Windows all'installazione. La cartella WindowsApps
        # e' modificabile solo dal sistema. 8wekyb3d8bbwe e' l'ID editore di Microsoft.
        if ($info.SignatureStatus -eq 'NotSigned' -and $Path -match '(?i)^[A-Z]:\\Program Files\\WindowsApps\\([^\\]+)\\') {
            $info.SignatureStatus = 'Valid'
            $info.Signer = "Pacchetto Microsoft Store ($($Matches[1]))"
            $info.IsMicrosoft = $Matches[1] -match '_8wekyb3d8bbwe$'
        }
    }
    $script:FileCache[$key] = $info
    return $info
}

# L'hash si calcola solo per i file che finiscono nel report (calcolarlo per ogni
# eseguibile esaminato rallenterebbe molto la scansione).
function Get-FileSha256 {
    param([string]$Path)
    $info = Get-FileInfo $Path
    if (-not $info -or -not $info.Exists) { return $null }
    if (-not $info.Sha256 -and $info.Size -lt 300MB) {
        try { $info.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    }
    return $info.Sha256
}

# Nomi di file casuali (es. "xkqzvbte.exe", "a8f3c1d9e2.exe") sono tipici dei dropper.
function Test-RandomLookingName {
    param([string]$Path)
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    if (-not $name -or $name.Length -lt 7) { return $false }
    if ($name -match '^[0-9a-f]{8,}$' -or $name -match '^\{?[0-9a-f\-]{32,}\}?$') { return $true }
    # Nomi con separatori o numeri di versione (pngcrush_1_8_w64, setup-x64) sono "umani"
    if ($name -match '[\s_\-\.]') { return $false }
    $letters = ($name -replace '[^a-zA-Z]', '')
    if ($letters.Length -lt 7) { return $false }
    $vowels = ($letters -replace '[^aeiouyAEIOUY]', '').Length
    return (($vowels / $letters.Length) -lt 0.15)
}

# ---------------------------------------------------------------------------
# Analisi delle righe di comando
# ---------------------------------------------------------------------------

$script:ExecExtensions = 'exe|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|dll|scr|cpl|msc|hta|lnk|sys|jar|pif|ocx'

function Resolve-CommandPath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $cmd = $cmd -replace '^\\\?\?\\', ''
    $cmd = $cmd -replace '^(?i)\\SystemRoot\\', "$env:SystemRoot\"
    if ($cmd -match '^(?i)system32\\') { $cmd = Join-Path $env:SystemRoot $cmd }

    $candidate = $null
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { $candidate = $cmd.Substring(1, $end - 1) } else { $candidate = $cmd.Trim('"') }
    } else {
        $m = [regex]::Match($cmd, "^(?i)(.+?\.($script:ExecExtensions))(?=\s|,|`"|$)")
        if ($m.Success) { $candidate = $m.Groups[1].Value } else { $candidate = ($cmd -split '\s+')[0] }
    }
    if (-not $candidate) { return $null }

    if (-not [IO.Path]::IsPathRooted($candidate)) {
        foreach ($dir in @("$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\System32\wbem", "$env:SystemRoot\System32\WindowsPowerShell\v1.0")) {
            $p = Join-Path $dir $candidate
            if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
            if (-not [IO.Path]::HasExtension($candidate) -and (Test-Path -LiteralPath "$p.exe" -PathType Leaf)) { return "$p.exe" }
        }
        $c = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    return $candidate
}

# Restituisce i file citati negli argomenti (es. la DLL passata a rundll32 o lo
# script passato a wscript), che sono il vero "carico" da analizzare.
function Get-EmbeddedPaths {
    param([string]$CommandLine)
    if (-not $CommandLine) { return @() }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine)
    $found = New-Object System.Collections.Generic.List[string]
    $rx = "(?i)([A-Z]:\\[^`"*?<>|,]+?\.($script:ExecExtensions))(?=[\s,`"']|$)"
    foreach ($m in [regex]::Matches($cmd, $rx)) { $found.Add($m.Groups[1].Value) }
    return $found
}

$script:SuspiciousPatterns = @(
    @{ Rx = '(?i)\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}'; S = 45; R = 'PowerShell con comando nascosto in Base64 (-EncodedCommand)' }
    @{ Rx = '(?i)-w(indowstyle)?\s+h(idden)?\b'; S = 20; R = 'Esegue in una finestra nascosta' }
    @{ Rx = '(?i)\b(iex|invoke-expression)\b'; S = 30; R = 'Esegue codice generato al volo (Invoke-Expression)' }
    @{ Rx = '(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b)'; S = 35; R = 'Scarica contenuti da internet' }
    @{ Rx = '(?i)frombase64string'; S = 25; R = 'Decodifica dati in Base64' }
    @{ Rx = '(?i)-(nop|noprofile)\b.*-(ep|executionpolicy)\s+bypass|-(ep|executionpolicy)\s+bypass'; S = 15; R = 'Aggira la policy di esecuzione di PowerShell' }
    @{ Rx = '(?i)mshta(\.exe)?["'']?\s+["'']?(https?|javascript|vbscript|about):'; S = 50; R = 'mshta esegue script remoti o inline (tecnica LOLBin)' }
    @{ Rx = '(?i)regsvr32(\.exe)?.*/i:\s*["'']?https?'; S = 50; R = 'regsvr32 carica uno scriptlet remoto (tecnica "Squiblydoo")' }
    @{ Rx = '(?i)rundll32(\.exe)?["'']?\s+.*(javascript:|vbscript:|mshtml,RunHTMLApplication)'; S = 50; R = 'rundll32 usato per eseguire script (tecnica LOLBin)' }
    @{ Rx = '(?i)certutil(\.exe)?.*\s[-/](urlcache|decode|decodehex)'; S = 45; R = 'certutil usato per scaricare o decodificare file' }
    @{ Rx = '(?i)bitsadmin(\.exe)?.*/(transfer|addfile|SetNotifyCmdLine)'; S = 35; R = 'bitsadmin usato per scaricare file o eseguire comandi' }
    @{ Rx = '(?i)https?://\d{1,3}(\.\d{1,3}){3}'; S = 30; R = 'Contatta un indirizzo IP diretto invece di un dominio' }
    @{ Rx = '(?i)(pastebin\.com|paste\.ee|transfer\.sh|discord(app)?\.com/api/webhooks|cdn\.discordapp\.com/attachments|api\.telegram\.org/bot|ngrok\.(io|app)|trycloudflare\.com|anonfiles|gofile\.io|temp\.sh|file\.io)'; S = 30; R = 'Usa un servizio spesso abusato dai malware per scaricare payload o inviare dati' }
    @{ Rx = '(?i)(stratum\+(tcp|ssl)|--donate-level|xmrig|nicehash|nanopool|moneroocean|--cpu-max-threads-hint|\s-o\s+\S+:\d{3,5}\s.*-u\s)'; S = 60; R = 'Parametri tipici di un cryptominer (XMRig e simili)' }
    @{ Rx = '(?i)(wscript|cscript)(\.exe)?["'']?\s+.*\\(appdata|temp|programdata|users\\public)\\'; S = 25; R = 'Script VBS/JS eseguito da una cartella utente' }
    @{ Rx = '(?i)(add-mppreference|set-mppreference|DisableRealtimeMonitoring|ExclusionPath)'; S = 55; R = 'Modifica le impostazioni di Microsoft Defender' }
    @{ Rx = '(?i)schtasks(\.exe)?.*/create'; S = 20; R = 'Crea a sua volta un''attivita'' pianificata' }
    @{ Rx = '(?i)(vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*(recoveryenabled|safeboot))'; S = 55; R = 'Cancella i backup o modifica l''avvio di Windows' }
    @{ Rx = '(?i)\\(appdata|temp)\\[^\\]+\.(vbs|vbe|js|jse|wsf|hta)\b'; S = 20; R = 'Script direttamente in AppData/Temp' }
    @{ Rx = '(?i)(netsh.*firewall.*(add|set).*allow|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)'; S = 40; R = 'Modifica il firewall di Windows' }
)

function Get-CommandRisk {
    param([string]$CommandLine)
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $target = Resolve-CommandPath $CommandLine
    $sha = $null; $signer = $null

    # Programma lanciato per primo, poi i file citati negli argomenti (senza doppioni)
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($target) + @(Get-EmbeddedPaths $CommandLine)) {
        if ($f -and -not ($files -contains $f)) { $files.Add($f) }
    }

    # Se il programma lanciato e' un "host" di sistema (rundll32, wscript...)
    # il carico vero e' il file passato come argomento.
    $hostNames = 'rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|mshta\.exe|powershell\.exe|pwsh\.exe|cmd\.exe|conhost\.exe|javaw?\.exe|msiexec\.exe'
    $payloadFound = $false

    $fileScoreMax = 0
    foreach ($f in $files) {
        $fs = 0
        if (-not [IO.Path]::IsPathRooted($f)) { continue }
        $info = Get-FileInfo $f
        if (-not $info.Exists) {
            $fs += 10
            $reasons.Add("Il file non esiste piu': $f (voce orfana o file cancellato dopo l'avvio)")
        } else {
            $isHost = [IO.Path]::GetFileName($f) -match "^($hostNames)$"
            if (-not $isHost -and -not $payloadFound) {
                $payloadFound = $true
                $target = $f; $sha = $info.Sha256; $signer = $info.Signer
            } elseif (-not $sha) {
                $sha = $info.Sha256; $signer = $info.Signer
            }
            if ($info.IsMicrosoft) { continue }
            $isScript = $f -match '(?i)\.(vbs|vbe|js|jse|wsf|wsh|ps1|bat|cmd|hta)$'
            $userWritable = Test-UserWritablePath $f
            # Uno script in Program Files/Windows e' modificabile solo da un amministratore
            if ($isScript -and -not $userWritable) { continue }
            switch ($info.SignatureStatus) {
                'Valid' { }
                'NotSigned' { $fs += 25; $reasons.Add("Non firmato digitalmente: $f") }
                'HashMismatch' { $fs += 50; $reasons.Add("Firma digitale manomessa (il file e' stato modificato dopo la firma): $f") }
                default { $fs += 30; $reasons.Add("Firma digitale non valida ($($info.SignatureStatus)): $f") }
            }
            if ($isScript) { $fs += 10; $reasons.Add("E' uno script, non un programma firmabile: $f") }
            if ($userWritable) {
                if ($info.SignatureStatus -eq 'Valid') { $fs += 5 }
                else { $fs += 20; $reasons.Add("Si trova in una cartella utente/temporanea (AppData, Temp, ProgramData...): $f") }
            }
            if ($info.Hidden) { $fs += 15; $reasons.Add("Il file ha l'attributo nascosto/di sistema: $f") }
            if ($info.SignatureStatus -ne 'Valid' -and (Test-RandomLookingName $f)) { $fs += 15; $reasons.Add("Nome del file dall'aspetto casuale: $f") }
            if ($info.SignatureStatus -ne 'Valid' -and $info.Created -and $info.Created -gt (Get-Date).AddDays(-30)) {
                $fs += 5; $reasons.Add("Creato negli ultimi 30 giorni ($($info.Created.ToString('dd/MM/yyyy')))")
            }
            if ($info.SignatureStatus -ne 'Valid' -and -not $info.Company -and -not $isScript) {
                $fs += 5; $reasons.Add('Nessun produttore indicato nelle proprieta'' del file')
            }
        }
        if ($fs -gt $fileScoreMax) { $fileScoreMax = $fs }
    }
    $score += $fileScoreMax

    foreach ($p in $script:SuspiciousPatterns) {
        if ($CommandLine -match $p.Rx) { $score += $p.S; $reasons.Add($p.R) }
    }

    return [pscustomobject]@{
        Score = $score; Reasons = $reasons.ToArray(); Target = $target; Sha256 = $sha; Signer = $signer
    }
}

# ---------------------------------------------------------------------------
# Utilita'
# ---------------------------------------------------------------------------

function Get-RegValues {
    param([string]$Path)
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $key) { return @() }
    foreach ($n in $key.GetValueNames()) {
        [pscustomobject]@{ Name = $(if ($n) { $n } else { '(Predefinito)' }); Value = $key.GetValue($n) }
    }
}

# Apre una chiave con l'API .NET partendo da un percorso stile PowerShell
# (HKLM:\..., HKCU:\..., HKU:\SID\...). Molto piu' veloce dei cmdlet su grandi rami.
function Open-RegistryKey {
    param([string]$Path)
    $m = [regex]::Match($Path, '^(HKLM|HKCU|HKU):\\?(.*)$')
    if (-not $m.Success) { return $null }
    $hive = switch ($m.Groups[1].Value) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
        'HKU' { [Microsoft.Win32.Registry]::Users }
    }
    try { return $hive.OpenSubKey($m.Groups[2].Value) } catch { return $null }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# Hive di tutti gli utenti caricati (non solo quello corrente: se avvii come
# amministratore con un altro account, HKCU non e' piu' il tuo).
function Get-UserHives {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
    }
    $hives = @()
    foreach ($k in Get-ChildItem -LiteralPath 'HKU:\' -ErrorAction SilentlyContinue) {
        if ($k.PSChildName -match '^S-1-5-21-[\d\-]+$') {
            $user = $k.PSChildName
            try { $user = (New-Object Security.Principal.SecurityIdentifier($k.PSChildName)).Translate([Security.Principal.NTAccount]).Value } catch { }
            $hives += [pscustomobject]@{ Root = "HKU:\$($k.PSChildName)"; User = $user }
        }
    }
    if (-not $hives) { $hives += [pscustomobject]@{ Root = 'HKCU:'; User = $env:USERNAME } }
    return $hives
}

function Get-ProcessTable {
    if (-not $script:ProcessTable) {
        $script:ProcessTable = @{}
        foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
            # Alcuni processi riportano il percorso nel formato \\?\C:\...
            $exe = $p.ExecutablePath
            if ($exe -like '\\?\*') { $exe = $exe.Substring(4) }
            $script:ProcessTable[[int]$p.ProcessId] = [pscustomobject]@{
                ProcessId = $p.ProcessId; ParentProcessId = $p.ParentProcessId; Name = $p.Name
                ExecutablePath = $exe; CommandLine = $p.CommandLine; CreationDate = $p.CreationDate
            }
        }
    }
    return $script:ProcessTable
}

function Get-EditDistance {
    param([string]$A, [string]$B)
    $A = $A.ToLowerInvariant(); $B = $B.ToLowerInvariant()
    $d = New-Object 'int[,]' ($A.Length + 1), ($B.Length + 1)
    for ($i = 0; $i -le $A.Length; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $B.Length; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $A.Length; $i++) {
        for ($j = 1; $j -le $B.Length; $j++) {
            $cost = 1
            if ($A[$i - 1] -eq $B[$j - 1]) { $cost = 0 }
            $del = $d[($i - 1), $j] + 1
            $ins = $d[$i, ($j - 1)] + 1
            $sub = $d[($i - 1), ($j - 1)] + $cost
            $d[$i, $j] = [Math]::Min([Math]::Min($del, $ins), $sub)
        }
    }
    return $d[$A.Length, $B.Length]
}

function Resolve-Shortcut {
    param([string]$Path)
    try {
        if (-not $script:WshShell) { $script:WshShell = New-Object -ComObject WScript.Shell }
        $lnk = $script:WshShell.CreateShortcut($Path)
        return [pscustomobject]@{ Target = $lnk.TargetPath; Arguments = $lnk.Arguments }
    } catch { return $null }
}

# Come disattivare una voce del registro: serve l'amministratore se non e' nel ramo
# dell'utente che usa l'app (HKCU o HKU\<il suo SID>).
function New-RegistryRemedy {
    param([string]$Key, [string]$Name)
    if (-not $Name -or $Name -eq '(Predefinito)') { return $null }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $own = $Key -like 'HKCU:*' -or $Key -like "HKU:\$sid\*"
    return @{ Kind = 'RegistryValue'; Key = $Key; Name = $Name; Admin = -not $own }
}

# Vero se il comando lancia proprio questo CheckBackdoor.ps1 (stesso contenuto), per
# esempio la verifica programmata dall'app. Un'attivita' che si chiama CheckBackdoor
# ma esegue altro resta segnalata normalmente.
function Test-OwnEngineCommand {
    param([string]$CommandLine)
    if (-not $script:EngineRoot) { return $false }
    $own = Join-Path $script:EngineRoot 'CheckBackdoor.ps1'
    $ownHash = Get-FileSha256 $own
    if (-not $ownHash) { return $false }
    foreach ($p in Get-EmbeddedPaths $CommandLine) {
        if ([IO.Path]::GetFileName($p) -eq 'CheckBackdoor.ps1' -and (Get-FileSha256 $p) -eq $ownHash) { return $true }
    }
    return $false
}

# Segreto cifrato con DPAPI per l'utente corrente (la chiave di VirusTotal salvata dall'app).
# Solo lo stesso utente Windows, sullo stesso PC, puo' decifrarlo.
$script:SecretEntropy = [Text.Encoding]::UTF8.GetBytes('CheckBackdoor.VirusTotal/1')
function Read-ProtectedSecret {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Add-Type -AssemblyName System.Security
        $blob = [Convert]::FromBase64String([IO.File]::ReadAllText($Path).Trim())
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $script:SecretEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plain)
    } catch {
        Write-ScanWarning "Chiave di VirusTotal non leggibile: salvala di nuovo dalle impostazioni dell'app."
        return $null
    }
}
