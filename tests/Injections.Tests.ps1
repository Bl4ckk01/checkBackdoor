# Iniezioni in Discord e nei wallet, su una cartella AppData\Local finta.
# I canali di esfiltrazione sono composti a runtime: scritti per intero potrebbero
# far bloccare il file da AMSI.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript Injections)

    $local = Join-Path $TestDrive 'Local'
    $clean = "module.exports = require('./core.asar');"
    function New-DiscordIndex([string]$Flavor, [string]$Content) {
        $dir = Join-Path $local "$Flavor\app-1.0.9001\modules\discord_desktop_core-1\discord_desktop_core"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'index.js') -Value $Content
    }
    $hook = 'https://' + 'disc' + 'ord.com/api/web' + 'hooks/123/abc'
    New-DiscordIndex 'Discord' $clean
    New-DiscordIndex 'DiscordCanary' ("const u = '$hook';`nfunction send(t) { /* token */ }`n" + $clean)
    New-DiscordIndex 'DiscordPTB' ("require(`"C:\\Utente\\BetterDiscord\\data\\betterdiscord.asar`");`n" + $clean)

    # Exodus manomesso: app.asar modificato mesi dopo l'eseguibile e con un bot Telegram
    $exodus = Join-Path $local 'exodus\app-24.1.1'
    New-Item -ItemType Directory -Path (Join-Path $exodus 'resources') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $exodus 'Exodus.exe') -Value 'finto'
    (Get-Item -LiteralPath (Join-Path $exodus 'Exodus.exe')).LastWriteTime = (Get-Date).AddDays(-90)
    Set-Content -LiteralPath (Join-Path $exodus 'resources\app.asar') -Value ('codice ' * 1000 + 'https://' + 'api.tele' + 'gram.org/bot' + '123:abc/sendMessage')

    # Atomic Wallet integro: stessi tempi, nessun canale
    $atomic = Join-Path $local 'Programs\atomic'
    New-Item -ItemType Directory -Path (Join-Path $atomic 'resources') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $atomic 'Atomic Wallet.exe') -Value 'finto'
    Set-Content -LiteralPath (Join-Path $atomic 'resources\app.asar') -Value ('codice ' * 1000)

    $script:Findings.Clear(); $script:Inventory.Clear()
    Test-DiscordClients -LocalAppData $local -User 'test'
    Test-WalletApps -LocalAppData $local -User 'test'
}

Describe 'Discord' {
    It 'mette in inventario ogni client trovato' {
        @($script:Inventory | Where-Object Key -like 'Discord*') | Should -HaveCount 3
    }
    It 'non segnala il client con il file originale' {
        $script:Findings | Where-Object Title -like 'Discord modificato*' | Should -BeNullOrEmpty
    }
    It 'segna come Alto il client con codice iniettato e il canale di invio' {
        $f = $script:Findings | Where-Object Title -like 'DiscordCanary*'
        $f.Severity | Should -Be 'Alto'
        $f.Reasons -join ' ' | Should -Match 'webhooks'
    }
    It 'riconosce BetterDiscord come da verificare' {
        $f = $script:Findings | Where-Object Title -like 'DiscordPTB*'
        $f.Severity | Should -Be 'Medio'
        $f.Reasons -join ' ' | Should -Match 'BetterDiscord'
    }
}

Describe 'Wallet' {
    It 'segna come Alto Exodus modificato dopo l''installazione e con un canale di invio' {
        $f = $script:Findings | Where-Object Title -like 'Exodus*'
        $f.Severity | Should -Be 'Alto'
        $f.Reasons -join ' ' | Should -Match 'giorni dopo'
        $f.Reasons -join ' ' | Should -Match 'telegram'
    }
    It 'non segnala Atomic Wallet integro' {
        $script:Findings | Where-Object Title -like 'Atomic*' | Should -BeNullOrEmpty
    }
}
