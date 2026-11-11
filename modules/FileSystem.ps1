# File sospetti nelle cartelle dove i malware si installano senza bisogno di
# privilegi: AppData, Temp, ProgramData, Pubblica. Cerca eseguibili non firmati,
# script, file nascosti e flussi di dati alternativi (ADS).

function Invoke-CheckFileSystem {
    param([switch]$Deep)
    $cat = 'File sospetti'

    $roots = New-Object System.Collections.Generic.List[object]
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        if ($prof.Name -in 'Default', 'Default User', 'All Users') { continue }
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Roaming'; D = 3 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Local'; D = 2 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Local\Temp'; D = 3 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\LocalLow'; D = 3 })
    }
    $roots.Add(@{ P = $env:ProgramData; D = 2 })
    $roots.Add(@{ P = "$env:SystemDrive\Users\Public"; D = 3 })
    $roots.Add(@{ P = "$env:SystemRoot\Temp"; D = 3 })
    $roots.Add(@{ P = "$env:SystemDrive\PerfLogs"; D = 3 })
    $roots.Add(@{ P = "$env:SystemRoot\Tasks"; D = 1 })
    $roots.Add(@{ P = "$env:SystemDrive\Intel"; D = 2 })
    $roots.Add(@{ P = "$env:SystemDrive\`$Recycle.Bin"; D = 3 })

    # Cache, librerie e risorse di app: contengono decine di migliaia di file .js/.exe legittimi
    $skipDirs = '(?i)\\(Packages|Microsoft\\(Edge|WindowsApps|Teams|OneDrive|Windows\\(INetCache|WebCache|Explorer|Caches|WER))|Google\\Chrome|BraveSoftware|Mozilla\\Firefox\\Profiles|Opera Software|npm-cache|npm|pip|pnpm|yarn|NuGet|\.vscode|\.git|Code\\(Cache|CachedData)|htmlcache|CrashDumps|D3DSCache|DXCache|GLCache|Package Cache|assembly|Docker|JetBrains|Python\d*|node_modules|site-packages|resources\\app|Windows Defender|Windows\\Recent|Office\\Recent|cache|Cache|Code Cache|GPUCache|Service Worker|IndexedDB|Local Storage|dist|lib)$'
    $binExt = '(?i)\.(exe|scr|cpl|jar|lnk)$'
    $scriptExt = '(?i)\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)$'
    $scriptMaxDepth = 1
    if ($Deep) {
        $binExt = '(?i)\.(exe|dll|sys|scr|pif|com|cpl|ocx|jar|lnk)$'
        $scriptMaxDepth = 3
        foreach ($r in $roots) { $r.D = 8 }
    }

    $count = 0
    foreach ($r in $roots) {
        if (-not [IO.Directory]::Exists($r.P)) { continue }
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([pscustomobject]@{ Dir = $r.P; Depth = 0 })
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()
            if ($item.Dir -match $skipDirs) { continue }
            $entries = $null
            try { $entries = ([IO.DirectoryInfo]$item.Dir).GetFileSystemInfos() } catch { continue }
            foreach ($e in $entries) {
                if ($e -is [IO.DirectoryInfo]) {
                    if ($item.Depth -lt $r.D -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        $queue.Enqueue([pscustomobject]@{ Dir = $e.FullName; Depth = $item.Depth + 1 })
                    }
                    continue
                }
                $isBin = $e.Name -match $binExt
                $isScript = $item.Depth -le $scriptMaxDepth -and $e.Name -match $scriptExt
                if (-not ($isBin -or $isScript)) { continue }
                $count++
                Test-SuspiciousFile -File $e -Depth $item.Depth -Category $cat
            }
        }
    }
    Add-InventoryItem $cat 'File eseguibili esaminati' "$count"
}

function Test-SuspiciousFile {
    param($File, [int]$Depth, [string]$Category)
    $path = $File.FullName
    $ext = $File.Extension.ToLower()
    $score = 0; $why = @()

    if ($ext -eq '.lnk') {
        # Collegamenti in cartelle di sistema che lanciano interpreti di comandi
        $lnk = Resolve-Shortcut $path
        if ($lnk -and $lnk.Target) {
            $risk = Get-CommandRisk "`"$($lnk.Target)`" $($lnk.Arguments)"
            if ($risk.Score -ge 35 -and $risk.Reasons -match 'PowerShell|mshta|rundll32|regsvr32|Base64|internet|script') {
                Add-Finding -Category $Category -Severity (ConvertTo-Severity $risk.Score) -Title "Collegamento sospetto: $($File.Name)" -Path $path `
                    -Evidence "$($lnk.Target) $($lnk.Arguments)" -Mitre 'T1547.009' -Reasons $risk.Reasons
            }
        }
        return
    }

    $hidden = [bool]($File.Attributes -band ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
    $isScript = $ext -match '^\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)$'
    $recent = $File.CreationTime -gt (Get-Date).AddDays(-30)

    if ($isScript) {
        # Gli script in AppData/ProgramData sono rari; nei Temp sono spesso residui di installer
        $score += 15; $why += 'Script in una cartella utente'
        if ($ext -match '^\.(vbs|vbe|js|jse|wsf|hta)$') { $score += 15; $why += 'VBScript/JScript/HTA: formati usati quasi solo da malware al giorno d''oggi' }
        if ($File.Length -lt 2MB) {
            $text = $null
            try { $text = [IO.File]::ReadAllText($path) } catch { }
            if ($text) {
                foreach ($p in $script:SuspiciousPatterns) {
                    if ($text -match $p.Rx) { $score += [int]($p.S / 2); $why += "Contenuto: $($p.R)" }
                }
                if ($text -match '(?i)(chr\(\d+\)\s*&\s*){10,}|(\[char\]\d+\s*\+\s*){10,}|[A-Za-z0-9+/]{400,}={0,2}') {
                    $score += 25; $why += 'Contenuto offuscato (lunghe stringhe Base64 o catene di caratteri)'
                }
            }
        }
    } else {
        $info = Get-FileInfo $path
        if ($info.IsMicrosoft -or $info.SignatureStatus -eq 'Valid') {
            # Firmato: segnaliamo solo se nascosto in una posizione strana
            if ($hidden -and $Depth -eq 0) {
                $score += 15; $why += 'Eseguibile firmato ma nascosto in una cartella utente'
            }
        } else {
            $score += 15; $why += "Eseguibile non firmato ($($info.SignatureStatus))"
            if ($info.SignatureStatus -eq 'HashMismatch') { $score += 40; $why += 'Firma manomessa' }
            if ($Depth -eq 0) { $score += 15; $why += 'Si trova direttamente nella radice di AppData/ProgramData/Temp invece che nella cartella di un programma' }
            if (-not $info.Company -and -not $info.Description) { $score += 5; $why += 'Nessuna informazione sul produttore' }
            if (Test-RandomLookingName $path) { $score += 15; $why += 'Nome casuale' }
            if ($path -match '(?i)\\(Microsoft|Windows|Intel|NVIDIA|Google|Adobe)\\[^\\]+$' -and $Depth -le 2) {
                $score += 10; $why += 'Non firmato ma in una cartella che imita un produttore noto'
            }
            if ($File.Name -match '^(?i)(svchost|csrss|lsass|winlogon|services|smss|explorer|dllhost|conhost|taskhostw|runtimebroker|spoolsv|wininit|ctfmon|dwm)\.exe$') {
                $score += 50; $why += 'Usa il nome di un processo di sistema fuori da System32'
            }
            if ($path -match '(?i)\\\$Recycle\.Bin\\') { $score += 20; $why += 'Eseguibile nel Cestino (posizione usata per nascondersi)' }
            if ($path -match '(?i)\\AppData\\Local\\Temp\\' -and $Depth -ge 1) { $score -= 10 }   # residui di installer
        }
    }
    if ($hidden) { $score += 15; $why += 'Attributo nascosto/di sistema' }
    if ($recent -and $score -gt 0) { $score += 5; $why += "Creato il $($File.CreationTime.ToString('dd/MM/yyyy'))" }

    # Flussi di dati alternativi: dati nascosti "dentro" un file, invisibili in Esplora risorse.
    # Controllo costoso: solo per i file nella radice o gia' sospetti.
    if ($Depth -eq 0 -or $score -gt 0) { try {
        $streams = Get-Item -LiteralPath $path -Stream * -ErrorAction Stop |
            Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen', 'com.dropbox.attrs', 'Afp_AfpInfo', 'OECustomProperty' -and $_.Length -gt 0 }
        foreach ($s in $streams) { $score += 30; $why += "Contiene un flusso di dati nascosto (ADS) '$($s.Stream)' di $($s.Length) byte" }
    } catch { } }

    $sev = ConvertTo-Severity $score
    if ($sev -in 'Alto', 'Medio') {
        $info = Get-FileInfo $path
        Add-Finding -Category $Category -Severity $sev -Title $File.Name -Path $path -Mitre 'T1036 / T1564' -Reasons $why `
            -Evidence "Dimensione $([math]::Round($File.Length / 1KB)) KB; creato $($File.CreationTime.ToString('dd/MM/yyyy HH:mm')); modificato $($File.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))" `
            -Sha256 $info.Sha256 -Signer $info.Signer `
            -Recommendation 'Carica il file su virustotal.com. Se e'' malevolo, prima rimuovi le voci di avvio che lo lanciano, poi elimina il file.'
    }
}
