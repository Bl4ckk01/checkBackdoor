# Browser extensions on a fake Chromium profile, shortcut parameters.
# It touches neither the browsers nor the registry of the PC: everything happens in TestDrive.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript Browser)

    $profileDir = Join-Path $TestDrive 'Chrome\Default'
    $unpacked = Join-Path $TestDrive 'Desktop\local-extension'
    function New-Ext {
        param([string]$Id, [string]$Manifest)
        $dir = Join-Path $profileDir "Extensions\$Id\1.0_0"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'manifest.json') -Value $Manifest
    }
    New-Item -ItemType Directory -Force -Path $unpacked | Out-Null
    Set-Content -LiteralPath (Join-Path $unpacked 'manifest.json') -Value '{"name":"Local extension","version":"9.9"}'
    New-Ext 'store' '{"name":"Dark Reader","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Ext 'sideload' '{"name":"PDF Converter","version":"2.0","update_url":"https://updates.example.invalid/x.xml"}'
    New-Ext 'disabled' '{"name":"__MSG_appName__","default_locale":"en","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Item -ItemType Directory -Force -Path (Join-Path $profileDir 'Extensions\disabled\1.0_0\_locales\en') | Out-Null
    Set-Content -LiteralPath (Join-Path $profileDir 'Extensions\disabled\1.0_0\_locales\en\messages.json') -Value '{"appName":{"message":"Coupon Finder"}}'
    New-Ext 'flagged' '{"name":"Netflix Plus","version":"1.2","update_url":"https://clients2.google.com/service/update2/crx"}'
    New-Ext 'edgestore' '{"name":"Translator","version":"3.0","update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"}'

    $allSites = '"explicit_host":["<all_urls>"]'
    $prefs = @"
{"extensions":{"settings":{
 "store":{"location":1,"from_webstore":true,"path":"store\\1.0_0","active_permissions":{"api":["cookies"],$allSites}},
 "unpacked":{"location":4,"path":"$($unpacked.Replace('\','\\'))","active_permissions":{"api":["cookies","nativeMessaging"],$allSites}},
 "sideload":{"location":1,"from_webstore":false,"path":"sideload\\1.0_0","active_permissions":{"api":["tabs"],$allSites}},
 "disabled":{"location":1,"from_webstore":true,"path":"disabled\\1.0_0","state":0,"disable_reasons":[1]},
 "flagged":{"location":1,"from_webstore":true,"path":"flagged\\1.0_0","blacklist_state":1,"disable_reasons":[256]},
 "edgestore":{"location":1,"from_webstore":false,"path":"edgestore\\1.0_0","active_permissions":{"api":["cookies"],$allSites}},
 "leftover":{"active_bit":false},
 "component":{"location":5,"path":"C:\\Program Files\\Browser\\component"}
}}}
"@
    Set-Content -LiteralPath (Join-Path $profileDir 'Secure Preferences') -Value $prefs

    $script:Findings.Clear(); $script:Inventory.Clear()
    Test-ChromiumProfile -Browser 'Google Chrome' -Page 'chrome://extensions' -ProfileDir $profileDir -User 'test'
    function Get-ExtFinding([string]$Name) { $script:Findings | Where-Object Title -like "*: $Name" }
}

Describe 'Test-ChromiumProfile' {
    It 'inventories the installed extensions, not leftovers or components' {
        $script:Inventory | Should -HaveCount 6
        $script:Inventory.Key -join ' ' | Should -Not -Match 'leftover|component'
    }
    It 'reads the localized name from the manifest (__MSG_...__)' {
        ($script:Inventory | Where-Object Key -like '*| disabled').Value | Should -Match '^Coupon Finder'
    }
    It 'rates as High an extension loaded from a folder with access to cookies' {
        (Get-ExtFinding 'Local extension').Severity | Should -Be 'High'
    }
    It 'rates as High a non-store extension with a private update server' {
        $f = Get-ExtFinding 'PDF Converter'
        $f.Severity | Should -Be 'High'
        $f.Reasons -join ' ' | Should -Match 'updates\.example\.invalid'
    }
    It 'rates as High an extension the browser marked as malware, even if disabled' {
        $f = Get-ExtFinding 'Netflix Plus'
        $f.Severity | Should -Be 'High'
        $f.Reasons -join ' ' | Should -Match 'malware'
    }
    It 'does not flag <Name>' -ForEach @(@{ Name = 'Dark Reader' }, @{ Name = 'Coupon Finder' }, @{ Name = 'Translator' }) {
        Get-ExtFinding $Name | Should -BeNullOrEmpty
    }
}

Describe 'Get-PermissionRisk' {
    It 'gives no points to ordinary permissions' {
        (Get-PermissionRisk @('storage', 'tabs')).Score | Should -Be 0
    }
    It 'weighs access to all sites together with cookies' {
        (Get-PermissionRisk @('<all_urls>', 'cookies')).Score | Should -Be 20
    }
    It 'weighs the debugger permission' {
        (Get-PermissionRisk @('debugger')).Score | Should -Be 20
    }
}

Describe 'Browser parameters in shortcuts' {
    It 'flags <Line>' -ForEach @(
        @{ Line = '--load-extension="C:\Users\x\AppData\Local\ext"' }
        @{ Line = '--remote-debugging-port=9222' }
        @{ Line = 'https://search.example.invalid' }
    ) {
        @($script:BrowserArgs | Where-Object { $Line -match $_.Rx }) | Should -Not -BeNullOrEmpty
    }
    It 'does not flag <Line>' -ForEach @(
        @{ Line = '--profile-directory=Default' }
        @{ Line = '--profile-directory=Default --app-id=abcdef' }
        @{ Line = '--app=https://music.youtube.com' }
    ) {
        @($script:BrowserArgs | Where-Object { $Line -match $_.Rx }) | Should -BeNullOrEmpty
    }
}
