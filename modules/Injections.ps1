# Iniezioni degli stealer nelle app Electron (T1554): invece di installarsi come
# programma, molti stealer modificano il codice di Discord o dei wallet di
# criptovalute, che lo eseguono da soli a ogni avvio rubando token e frasi di
# recupero. Sopravvivono alla rimozione del malware originale.
# Usa Get-ProfileRoots dal modulo Browser.

$script:InjectionCategory = 'Iniezioni nelle app'
$script:DiscordFlavors = 'Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment', 'Lightcord'
# Contenuto originale di discord_desktop_core\index.js
$script:DiscordCleanIndex = '^\s*module\.exports\s*=\s*require\(\s*[''"]\./core\.asar[''"]\s*\)\s*;?\s*$'
# Canali con cui gli stealer inviano i dati rubati
$script:ExfilPattern = '(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|paste\.ee|ngrok\.(io|app)|trycloudflare\.com|transfer\.sh|gofile\.io|file\.io)'

function Test-DiscordClients {
    param([Parameter(Mandatory)][string]$LocalAppData, [string]$User)
    foreach ($flavor in $script:DiscordFlavors) {
        $base = Join-Path $LocalAppData $flavor
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $indexes = Get-ChildItem -LiteralPath $base -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem -LiteralPath (Join-Path $_.FullName 'modules') -Directory -Filter 'discord_desktop_core*' -ErrorAction SilentlyContinue
        } | ForEach-Object { Join-Path $_.FullName 'discord_desktop_core\index.js' } | Where-Object { Test-Path -LiteralPath $_ }
        foreach ($index in $indexes) {
            $text = ''
            try { $text = [IO.File]::ReadAllText($index) } catch { continue }
            $sha = Get-FileSha256 $index
            Add-InventoryItem $script:InjectionCategory "$flavor | $User | $index" $sha
            if ($text -match $script:DiscordCleanIndex) { continue }

            $extra = ($text -replace "module\.exports\s*=\s*require\(\s*['""]\./core\.asar['""]\s*\)\s*;?", '').Trim()
            $sample = if ($extra.Length -gt 300) { $extra.Substring(0, 300) + '...' } else { $extra }
            $why = @("Il file originale di $flavor contiene una sola riga; questo contiene altro codice ($($extra.Length) caratteri) che viene eseguito a ogni avvio dell'app")
            $sev = 'Alto'
            if ($text -match $script:ExfilPattern) { $why += "Contiene un canale per inviare dati all'esterno: $($Matches[0])" }
            if ($text -match '(?i)(token|localStorage|webhook|billing|password|2fa|mfa|backup_codes)') { $why += 'Fa riferimento a token, password o codici di accesso dell''account' }
            if ($text -match '(?i)betterdiscord\.asar' -and $extra -notmatch $script:ExfilPattern -and ($extra -split "`n").Count -le 3) {
                $sev = 'Medio'
                $why = @('E'' la modifica fatta da BetterDiscord, una mod diffusa: va bene solo se l''hai installata tu', 'Le mod di Discord violano i suoi termini di servizio e possono caricare plugin di terzi')
            }
            Add-Finding -Category $script:InjectionCategory -Severity $sev -Title "$flavor modificato (discord_desktop_core)" -Path $index -Detail "Utente $User" `
                -Evidence $sample -Mitre 'T1554' -Reasons $why `
                -Recommendation "Chiudi $flavor (anche dall'area di notifica), disinstallalo, elimina la cartella $base e reinstallalo dal sito ufficiale. Poi da un altro dispositivo cambia la password di Discord: il cambio invalida il token rubato. Attiva l'autenticazione a due fattori."
        }
    }
}

# Cerca canali di esfiltrazione dentro un file grande, a blocchi
function Find-ExfilIndicator {
    param([string]$Path)
    $fs = $null
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $buf = New-Object byte[] (8MB)
        $tail = ''
        $latin = [Text.Encoding]::GetEncoding(28591)
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
            $chunk = $tail + $latin.GetString($buf, 0, $n)
            $m = [regex]::Match($chunk, $script:ExfilPattern)
            if ($m.Success) { return $m.Value }
            $tail = $chunk.Substring([Math]::Max(0, $chunk.Length - 64))   # sovrapposizione tra blocchi
        }
    } catch { } finally { if ($fs) { $fs.Dispose() } }
    return $null
}

function Test-WalletApps {
    param([Parameter(Mandatory)][string]$LocalAppData, [string]$User)
    $wallets = @(
        @{ Name = 'Exodus'; Dirs = @(Get-ChildItem -LiteralPath (Join-Path $LocalAppData 'exodus') -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | ForEach-Object FullName); Exe = 'Exodus.exe' }
        @{ Name = 'Atomic Wallet'; Dirs = @((Join-Path $LocalAppData 'Programs\atomic')); Exe = 'Atomic Wallet.exe' }
    )
    foreach ($w in $wallets) {
        foreach ($dir in $w.Dirs) {
            $asar = Join-Path $dir 'resources\app.asar'
            if (-not (Test-Path -LiteralPath $asar)) { continue }
            $asarItem = Get-Item -LiteralPath $asar -Force
            Add-InventoryItem $script:InjectionCategory "$($w.Name) | $User | $asar" "$($asarItem.Length) byte, $($asarItem.LastWriteTimeUtc.ToString('s'))"
            $why = @(); $score = 0
            $exe = Join-Path $dir $w.Exe
            if (Test-Path -LiteralPath $exe) {
                $gap = ($asarItem.LastWriteTime - (Get-Item -LiteralPath $exe -Force).LastWriteTime).TotalHours
                if ($gap -gt 24) {
                    $score += 40; $why += "Il codice dell'app (app.asar) e' stato modificato $([Math]::Round($gap / 24)) giorni dopo l'installazione: gli aggiornamenti cambiano tutti i file insieme"
                }
            }
            $hit = Find-ExfilIndicator $asar
            if ($hit) { $score += 60; $why += "Contiene un canale per inviare dati all'esterno ($hit): un wallet non ne ha bisogno" }
            if ($score -eq 0) { continue }
            Add-Finding -Category $script:InjectionCategory -Severity (ConvertTo-Severity $score) -Title "$($w.Name) potrebbe essere stato modificato" -Path $asar -Detail "Utente $User" `
                -Mitre 'T1554' -Reasons (@('Gli stealer sostituiscono il codice dei wallet per rubare la frase di recupero quando la digiti.') + $why) `
                -Recommendation "Non aprire $($w.Name) e non digitare la frase di recupero. Da un dispositivo sicuro, crea un nuovo wallet e trasferisci i fondi; poi disinstalla $($w.Name), elimina la sua cartella e reinstallalo dal sito ufficiale."
        }
    }
}

function Invoke-CheckInjections {
    foreach ($u in Get-ProfileRoots) {
        Test-DiscordClients -LocalAppData $u.Local -User $u.User
        Test-WalletApps -LocalAppData $u.Local -User $u.User
    }
}
