# Injections into Discord and wallets, on a fake AppData\Local folder.
# Exfiltration channels are assembled at runtime: written out in full they could
# get the file blocked by AMSI.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
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
    New-DiscordIndex 'DiscordPTB' ("require(`"C:\\User\\BetterDiscord\\data\\betterdiscord.asar`");`n" + $clean)

    # Tampered Exodus: app.asar changed months after the executable and with a Telegram bot
    $exodus = Join-Path $local 'exodus\app-24.1.1'
    New-Item -ItemType Directory -Path (Join-Path $exodus 'resources') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $exodus 'Exodus.exe') -Value 'fake'
    (Get-Item -LiteralPath (Join-Path $exodus 'Exodus.exe')).LastWriteTime = (Get-Date).AddDays(-90)
    Set-Content -LiteralPath (Join-Path $exodus 'resources\app.asar') -Value ('code ' * 1000 + 'https://' + 'api.tele' + 'gram.org/bot' + '123:abc/sendMessage')

    # Intact Atomic Wallet: same times, no channel
    $atomic = Join-Path $local 'Programs\atomic'
    New-Item -ItemType Directory -Path (Join-Path $atomic 'resources') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $atomic 'Atomic Wallet.exe') -Value 'fake'
    Set-Content -LiteralPath (Join-Path $atomic 'resources\app.asar') -Value ('code ' * 1000)

    $script:Findings.Clear(); $script:Inventory.Clear()
    Test-DiscordClients -LocalAppData $local -User 'test'
    Test-WalletApps -LocalAppData $local -User 'test'
}

Describe 'Discord' {
    It 'inventories every client found' {
        @($script:Inventory | Where-Object Key -like 'Discord*') | Should -HaveCount 3
    }
    It 'does not flag the client with the original file' {
        $script:Findings | Where-Object Title -like 'Discord modified*' | Should -BeNullOrEmpty
    }
    It 'rates as High the client with injected code and the exfiltration channel' {
        $f = $script:Findings | Where-Object Title -like 'DiscordCanary*'
        $f.Severity | Should -Be 'High'
        $f.Reasons -join ' ' | Should -Match 'webhooks'
    }
    It 'treats BetterDiscord as to review' {
        $f = $script:Findings | Where-Object Title -like 'DiscordPTB*'
        $f.Severity | Should -Be 'Medium'
        $f.Reasons -join ' ' | Should -Match 'BetterDiscord'
    }
}

Describe 'Wallets' {
    It 'rates as High an Exodus changed after installation and with an exfiltration channel' {
        $f = $script:Findings | Where-Object Title -like 'Exodus*'
        $f.Severity | Should -Be 'High'
        $f.Reasons -join ' ' | Should -Match 'days after'
        $f.Reasons -join ' ' | Should -Match 'telegram'
    }
    It 'does not flag an intact Atomic Wallet' {
        $script:Findings | Where-Object Title -like 'Atomic*' | Should -BeNullOrEmpty
    }
}
