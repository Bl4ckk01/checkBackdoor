# Estensioni dei browser su un profilo Chromium finto, parametri dei collegamenti.
# Non tocca i browser ne' il registro del PC: tutto avviene nella cartella TestDrive.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript Browser)

    $profileDir = Join-Path $TestDrive 'Chrome\Default'
    $unpacked = Join-Path $TestDrive 'Desktop\estensione-locale'
    function New-Ext {
        param([string]$Id, [string]$Manifest)
        $dir = Join-Path $profileDir "Extensions\$Id\1.0_0"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Value $Manifest
    }
    New-Item -ItemType Directory -Force -Path $unpacked | Out-Null
    Set-Content -LiteralPath (Join-Path $unpacked 'manifest.json') -Value '{"name":"Estensione locale","version":"9.9"}'
    New-Ext 'store' '{"name":"Dark Reader","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Ext 'sideload' '{"name":"PDF Converter","version":"2.0","update_url":"https://updates.example.invalid/x.xml"}'
    New-Ext 'disabled' '{"name":"__MSG_appName__","default_locale":"en","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Item -ItemType Directory -Force -Path (Join-Path $profileDir 'Extensions\disabled\1.0_0\_locales\en') | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'Extensions\disabled\1.0_0\_locales\en\messages.json') -Value '{"appName":{"message":"Coupon Finder"}}'
    New-Ext 'flagged' '{"name":"Netflix Plus","version":"1.2","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Ext 'edgestore' '{"name":"Traduttore","version":"3.0","update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"}'

    $allSites = '"explicit_host":["<all_urls>"]'
    $prefs = @"
{"extensions":{"settings":{
 "store":{"location":1,"from_webstore":true,"path":"store\\1.0_0","active_permissions":{"api":["cookies"],$allSites}},
 "unpacked":{"location":4,"path":"$($unpacked.Replace('\','\\'))","active_permissions":{"api":["cookies","nativeMessaging"],$allSites}},
 "sideload":{"location":1,"from_webstore":false,"path":"sideload\\1.0_0","active_permissions":{"api":["tabs"],$allSites}},
 "disabled":{"location":1,"from_webstore":true,"path":"disabled\\1.0_0","state":0,"disable_reasons":[1]},
 "flagged":{"location":1,"from_webstore":true,"path":"flagged\\1.0_0","blacklist_state":1,"disable_reasons":[256]},
 "edgestore":{"location":1,"from_webstore":false,"path":"edgestore\\1.0_0","active_permissions":{"api":["cookies"],$allSites}},
 "residuo":{"active_bit":false},
 "componente":{"location":5,"path":"C:\\Program Files\\Browser\\component"}
}}}
"@
    Set-Content -LiteralPath (Join-Path $profileDir 'Secure Preferences') -Value $prefs

    $script:Findings.Clear(); $script:Inventory.Clear()
    Test-ChromiumProfile -Browser 'Google Chrome' -Page 'chrome://extensions' -ProfileDir $profileDir -User 'test'
    function Get-ExtFinding([string]$Name) { $script:Findings | Where-Object Title -like "*: $Name" }
}

Describe 'Test-ChromiumProfile' {
    It 'mette in inventario le estensioni installate, non i residui ne'' i componenti' {
        $script:Inventory | Should -HaveCount 6
        $script:Inventory.Key -join ' ' | Should -Not -Match 'residuo|componente'
    }
    It 'legge il nome tradotto dal manifest (__MSG_...__)' {
        ($script:Inventory | Where-Object Key -like '*| disabled').Value | Should -Match '^Coupon Finder'
    }
    It 'segna come Alto un''estensione caricata da cartella con accesso ai cookie' {
        (Get-ExtFinding 'Estensione locale').Severity | Should -Be 'Alto'
    }
    It 'segna come Alto un''estensione non da store con server di aggiornamento privato' {
        $f = Get-ExtFinding 'PDF Converter'
        $f.Severity | Should -Be 'Alto'
        $f.Reasons -join ' ' | Should -Match 'updates\.example\.invalid'
    }
    It 'segna come Alto un''estensione che il browser ha marcato come malware, anche se disattivata' {
        $f = Get-ExtFinding 'Netflix Plus'
        $f.Severity | Should -Be 'Alto'
        $f.Reasons -join ' ' | Should -Match 'malware'
    }
    It 'non segnala <Name>' -ForEach @(@{ Name = 'Dark Reader' }, @{ Name = 'Coupon Finder' }, @{ Name = 'Traduttore' }) {
        Get-ExtFinding $Name | Should -BeNullOrEmpty
    }
}

Describe 'Get-PermissionRisk' {
    It 'non da'' punti a permessi ordinari' {
        (Get-PermissionRisk @('storage', 'tabs')).Score | Should -Be 0
    }
    It 'pesa l''accesso a tutti i siti insieme ai cookie' {
        (Get-PermissionRisk @('<all_urls>', 'cookies')).Score | Should -Be 20
    }
    It 'pesa il permesso debugger' {
        (Get-PermissionRisk @('debugger')).Score | Should -Be 20
    }
}

Describe 'Parametri del browser nei collegamenti' {
    It 'segnala <Line>' -ForEach @(
        @{ Line = '--load-extension="C:\Users\x\AppData\Local\ext"' }
        @{ Line = '--remote-debugging-port=9222' }
        @{ Line = 'https://ricerca.example.invalid' }
    ) {
        @($script:BrowserArgs | Where-Object { $Line -match $_.Rx }) | Should -Not -BeNullOrEmpty
    }
    It 'non segnala <Line>' -ForEach @(
        @{ Line = '--profile-directory=Default' }
        @{ Line = '--profile-directory=Default --app-id=abcdef' }
        @{ Line = '--app=https://music.youtube.com' }
    ) {
        @($script:BrowserArgs | Where-Object { $Line -match $_.Rx }) | Should -BeNullOrEmpty
    }
}
