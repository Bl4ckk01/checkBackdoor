# Report: testo italiano, HTML sicuro e offline, lista bianca, confronto tra scansioni.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript Report)

    function New-TestMeta {
        param([bool]$Admin = $true, [string[]]$Skipped = @())
        @{
            Version = 'test'; Computer = 'PC-TEST'; User = 'PC-TEST\utente'; Date = '01/01/2026 10:00'; Duration = '1 min 2 s'
            Admin = $Admin; Skipped = $Skipped; Errors = @(); Ignored = 0
            Examined = @{ 'Avvio automatico' = 10; 'Servizi' = 5 }; Files = @{ Json = 'a.json'; Csv = 'a.csv' }
        }
    }
}

Describe 'ConvertTo-ItalianProse' {
    It 'mette gli accenti in <In>' -ForEach @(
        @{ In = "E' uno script"; Out = "{EUpper} uno script" }
        @{ In = "c'e' un file"; Out = "c'{e} un file" }
        @{ In = "non esiste piu'."; Out = "non esiste pi{u}." }
        @{ In = "perche' puo'"; Out = "perch{eAcute} pu{o}" }
        @{ In = "Attivita' pianificate"; Out = "Attivit{a} pianificate" }
        @{ In = "e' cosi'"; Out = "{e} cos{i}" }
    ) {
        $expected = $Out
        foreach ($k in $script:Chr.Keys) { $expected = $expected.Replace("{$k}", $script:Chr[$k]) }
        ConvertTo-ItalianProse $In | Should -BeExactly $expected
    }
    It 'non tocca gli apostrofi normali e i percorsi' {
        ConvertTo-ItalianProse "l'utente apre C:\a\b.exe" | Should -BeExactly "l'utente apre C:\a\b.exe"
    }
}

Describe 'New-HtmlReport' {
    BeforeAll {
        $findings = @(
            New-TestFinding -Severity 'Alto' -Title '<img src=x onerror=alert(1)>' -Evidence '<script>alert(2)</script>'
            New-TestFinding -Severity 'Medio' -Category 'Servizi' -Title 'Servizio di prova'
            New-TestFinding -Severity 'Info' -Category 'Servizi' -Title 'Solo informazione'
        )
        $html = New-HtmlReport -Findings $findings -Meta (New-TestMeta -Skipped 'Wmi')
    }
    It 'trasforma in testo i nomi scelti da un attaccante' {
        $html | Should -Not -Match '<img src=x'
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
    }
    It 'non carica nulla da internet all''apertura' {
        $html | Should -Not -Match '<script[^>]+src='
        $html | Should -Not -Match '<link[^>]+href='
        $html | Should -Not -Match '<img\s'
        $html | Should -Not -Match '@import|url\(\s*["'']?https?:'
    }
    It 'mostra il verdetto per un indizio ad alto rischio' {
        $html | Should -Match 'Un indizio ad alto rischio'
    }
    It 'conta come segnalazioni visibili solo quelle non informative' {
        $html | Should -Match '<span data-all-count>2</span>'
        $html | Should -Match 'data-count>2<'
    }
    It 'segna come non eseguita l''area di un controllo saltato' {
        $html | Should -Match 'data-area="WMI"[^>]*><span class="a-name">WMI</span><span class="a-meta">[^<]*</span><span class="a-state s-off">Non eseguito'
    }
    It 'collega i file JSON e CSV della stessa scansione' {
        $html | Should -Match 'href="a\.json"'
        $html | Should -Match 'href="a\.csv"'
    }
    It 'avvisa quando la scansione non e'' da amministratore' {
        New-HtmlReport -Findings $findings -Meta (New-TestMeta -Admin $false) | Should -Match 'Controlli incompleti'
    }
    It 'dice che non ci sono indizi quando la lista e'' vuota' {
        $empty = New-HtmlReport -Findings @() -Meta (New-TestMeta)
        $empty | Should -Match 'Nessun indizio di backdoor'
        $empty | Should -Match 'Nessuna segnalazione: tutte le aree'
    }
}

Describe 'Elementi nascosti dalla lista bianca nel report' {
    It 'li elenca con la regola, come testo' {
        $hidden = @([pscustomobject]@{ Id = 'a1'; Category = 'Avvio automatico'; Severity = 'Medio'; Title = '<b>Nascosto</b>'; Path = 'C:\Sicuro\x.exe'; Rule = 'percorso C:\Sicuro\*' })
        $html = New-HtmlReport -Findings @() -Meta (New-TestMeta) -Ignored $hidden
        $html | Should -Match 'id="ig-h"'
        $html | Should -Match '&lt;b&gt;Nascosto&lt;/b&gt;'
        $html | Should -Match ([regex]::Escape('percorso C:\Sicuro\*'))
    }
    It 'non mostra la sezione se non e'' stato nascosto nulla' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) | Should -Not -Match 'id="ig-h"'
    }
}

Describe 'Azioni nel report' {
    It 'offre Disattiva solo agli elementi che si possono annullare, e Ignora mai agli Info' {
        $con = New-TestFinding -Title 'Con azione' -Path 'C:\Users\x\AppData\a.exe'
        $con | Add-Member -NotePropertyName Remedy -NotePropertyValue @{ Kind = 'RegistryValue' }
        $senza = New-TestFinding -Title 'Senza azione'
        $info = New-TestFinding -Title 'Solo informazione' -Severity 'Info'
        $html = New-HtmlReport -Findings @($con, $senza, $info) -Meta (New-TestMeta)
        ([regex]::Matches($html, 'data-act="disable"')).Count | Should -Be 1
        ([regex]::Matches($html, 'data-act="ignore"')).Count | Should -Be 2
        $html | Should -Match ('class="acts" data-id="' + $con.Id + '"')
    }
    It 'nasconde le azioni fuori dall''app' {
        New-HtmlReport -Findings @(New-TestFinding) -Meta (New-TestMeta) | Should -Match '\.acts\{display:none\}'
    }
}

Describe 'Linea temporale nel report' {
    BeforeAll {
        $finding = New-TestFinding -Category 'Linea temporale' -Title 'Account creato: supporto' -Evidence 'Creato da bob'
        function New-Entry([int]$Minutes, [string]$Text = 'Avviato tool.exe', [string]$FindingId) {
            [pscustomobject]@{ Time = (Get-Date '2026-03-01 10:00').AddMinutes($Minutes).ToString('s'); Source = 'Programmi'; Text = $Text; Path = 'C:\Users\x\Downloads\tool.exe'; Severity = 'Info'; FindingId = $FindingId }
        }
    }
    It 'non mostra la sezione se il controllo non e'' stato eseguito' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) | Should -Not -Match 'id="tl-h"'
    }
    It 'dice che non ci sono eventi quando la linea temporale e'' vuota' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline @() | Should -Match 'Nessun evento rilevante'
    }
    It 'mette gli eventi dal piu'' recente e collega la segnalazione' {
        $html = New-HtmlReport -Findings @($finding) -Meta (New-TestMeta) -Timeline @((New-Entry 0 'primo'), (New-Entry 5 'secondo' $finding.Id))
        $html.IndexOf('secondo') | Should -BeLessThan $html.IndexOf('primo')
        $html | Should -Match ([regex]::Escape("href=""#f-$($finding.Id)"""))
        $html | Should -Match '01/03/2026 10:05'
    }
    It 'trasforma in testo i nomi dei programmi' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline @(New-Entry 0 'Avviato <img src=x>') | Should -Match '&lt;img src=x&gt;'
    }
    It 'mostra al massimo 60 eventi e rimanda al JSON' {
        $many = foreach ($i in 1..65) { New-Entry $i }
        $html = New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline $many
        ([regex]::Matches($html, 'class="tl-row"')).Count | Should -Be 60
        $html | Should -Match 'Altri 5 eventi'
    }
}

Describe 'Invoke-Allowlist' {
    BeforeEach {
        $script:Findings = New-Object System.Collections.Generic.List[object]
        $script:Findings.Add((New-TestFinding -Title 'Da tenere' -Path 'C:\Altro\x.exe'))
        $script:Findings.Add((New-TestFinding -Title 'Per percorso' -Path 'C:\Sicuro\app\x.exe'))
        $script:Findings.Add((New-TestFinding -Title 'Ignorami pure'))
        $script:Findings.Add((New-TestFinding -Title 'Per hash' -Sha256 'abcdef'))
        $shared = Join-Path $TestDrive 'allowlist.json'
        $local = Join-Path $TestDrive 'allowlist.local.json'
        Set-Content -LiteralPath $shared -Value '{ "paths": ["C:\\Sicuro\\*"], "sha256": [], "titles": [] }'
        Set-Content -LiteralPath $local -Value '{ "paths": [], "sha256": ["ABCDEF"], "titles": ["*Ignorami*"] }'
    }
    It 'unisce la lista condivisa e quella locale' {
        Invoke-Allowlist -Path $shared, $local | Should -Be 3
        $script:Findings | Should -HaveCount 1
        $script:Findings[0].Title | Should -Be 'Da tenere'
    }
    It 'ignora un file che non esiste' {
        Invoke-Allowlist -Path (Join-Path $TestDrive 'manca.json') | Should -Be 0
        $script:Findings | Should -HaveCount 4
    }
}

Describe 'Compare-WithPrevious' {
    BeforeEach {
        $script:Findings.Clear(); $script:Inventory.Clear()
        $prev = [ordered]@{
            Meta = @{ Date = '01/01/2026 09:00' }
            Inventory = @(
                @{ Category = 'Avvio automatico'; Key = 'Run | Uno'; Value = 'uno.exe' }
                @{ Category = 'Avvio automatico'; Key = 'Run | Tolto'; Value = 'tolto.exe' }
                @{ Category = 'Rete'; Key = 'Established | app.exe | 50000'; Value = '1.2.3.4:443' }
                @{ Category = 'Certificati'; Key = 'Root macchina'; Value = 'ABC' }
            )
        }
        $json = Join-Path $TestDrive 'prev.json'
        Set-Content -LiteralPath $json -Value ($prev | ConvertTo-Json -Depth 4)
        Add-InventoryItem 'Avvio automatico' 'Run | Uno' 'uno.exe'
        Add-InventoryItem 'Avvio automatico' 'Run | Nuovo' 'nuovo.exe'
        Add-InventoryItem 'Rete' 'Established | app.exe | 50123' '5.6.7.8:443'
        Compare-WithPrevious -PreviousJson $json
    }
    It 'segnala la voce di avvio comparsa dopo la scansione precedente' {
        $new = @($script:Findings | Where-Object Title -like 'Nuovo*')
        $new | Should -HaveCount 1
        $new[0].Title | Should -Match 'Run \| Nuovo'
        $new[0].Severity | Should -Be 'Medio'
    }
    It 'ignora le connessioni di rete, che cambiano di continuo' {
        $script:Findings | Where-Object Title -match 'Established' | Should -BeNullOrEmpty
    }
    It 'riporta come informazione la voce rimossa' {
        $gone = @($script:Findings | Where-Object Title -like 'Rimosso*')
        $gone | Should -HaveCount 1
        $gone[0].Severity | Should -Be 'Info'
    }
    It 'non considera rimossi gli elementi di un controllo saltato' {
        $script:Findings | Where-Object Title -match 'Certificati' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ExaminedCounts' {
    It 'somma le voci per area e usa i conteggi dei file' {
        $script:Inventory.Clear(); $script:ProcessTable = $null
        Add-InventoryItem 'Servizi' 'Servizio: a' 'a'
        Add-InventoryItem 'Modalita provvisoria' 'Minimal | a' 'a'
        Add-InventoryItem 'File sospetti' 'File eseguibili esaminati' '363'
        $c = Get-ExaminedCounts
        $c['Servizi'] | Should -Be 2
        $c['File sospetti'] | Should -Be 363
        $c.ContainsKey('Processi') | Should -BeFalse
    }
}
