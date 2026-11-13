# Stealer injections into Electron apps (T1554): instead of installing themselves as a
# program, many stealers modify the code of Discord or of crypto wallets, which then run
# it on their own at every start, stealing tokens and recovery phrases. They survive the
# removal of the original malware.
# Uses Get-ProfileRoots from the Browser module.

$script:InjectionCategory = 'App injections'
$script:DiscordFlavors = 'Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment', 'Lightcord'
# Original content of discord_desktop_core\index.js
$script:DiscordCleanIndex = '^\s*module\.exports\s*=\s*require\(\s*[''"]\./core\.asar[''"]\s*\)\s*;?\s*$'
# Channels stealers use to send the stolen data
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
            $why = @("The original $flavor file has a single line; this one has more code ($($extra.Length) characters) that runs every time the app starts")
            $sev = 'High'
            if ($text -match $script:ExfilPattern) { $why += "It contains a channel to send data out: $($Matches[0])" }
            if ($text -match '(?i)(token|localStorage|webhook|billing|password|2fa|mfa|backup_codes)') { $why += 'It refers to account tokens, passwords or sign-in codes' }
            if ($text -match '(?i)betterdiscord\.asar' -and $extra -notmatch $script:ExfilPattern -and ($extra -split "`n").Count -le 3) {
                $sev = 'Medium'
                $why = @('It is the change made by BetterDiscord, a popular mod: fine only if you installed it yourself', 'Discord mods break its terms of service and can load third-party plugins')
            }
            Add-Finding -Category $script:InjectionCategory -Severity $sev -Title "$flavor modified (discord_desktop_core)" -Path $index -Detail "User $User" `
                -Evidence $sample -Mitre 'T1554' -Reasons $why `
                -Recommendation "Quit $flavor (from the notification area too), uninstall it, delete the folder $base and reinstall it from the official website. Then, from another device, change your Discord password: changing it invalidates the stolen token. Turn on two-factor authentication."
        }
    }
}

# Looks for exfiltration channels inside a large file, in chunks
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
            $tail = $chunk.Substring([Math]::Max(0, $chunk.Length - 64))   # overlap between chunks
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
            Add-InventoryItem $script:InjectionCategory "$($w.Name) | $User | $asar" "$($asarItem.Length) bytes, $($asarItem.LastWriteTimeUtc.ToString('s'))"
            $why = @(); $score = 0
            $exe = Join-Path $dir $w.Exe
            if (Test-Path -LiteralPath $exe) {
                $gap = ($asarItem.LastWriteTime - (Get-Item -LiteralPath $exe -Force).LastWriteTime).TotalHours
                if ($gap -gt 24) {
                    $score += 40; $why += "The app code (app.asar) was changed $([Math]::Round($gap / 24)) days after installation: updates change all files together"
                }
            }
            $hit = Find-ExfilIndicator $asar
            if ($hit) { $score += 60; $why += "It contains a channel to send data out ($hit): a wallet has no need for one" }
            if ($score -eq 0) { continue }
            Add-Finding -Category $script:InjectionCategory -Severity (ConvertTo-Severity $score) -Title "$($w.Name) may have been modified" -Path $asar -Detail "User $User" `
                -Mitre 'T1554' -Reasons (@('Stealers replace wallet code to steal the recovery phrase when you type it.') + $why) `
                -Recommendation "Do not open $($w.Name) and do not type your recovery phrase. From a safe device, create a new wallet and move the funds; then uninstall $($w.Name), delete its folder and reinstall it from the official website."
        }
    }
}

function Invoke-CheckInjections {
    foreach ($u in Get-ProfileRoots) {
        Test-DiscordClients -LocalAppData $u.Local -User $u.User
        Test-WalletApps -LocalAppData $u.Local -User $u.User
    }
}
