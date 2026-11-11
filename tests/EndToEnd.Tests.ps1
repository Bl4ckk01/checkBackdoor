# Scansione vera con powershell.exe, come la lancia un utente. Salta i controlli piu'
# lenti (file, processi, servizi, rete, browser) per restare sotto il minuto.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    $script:Out = Join-Path $TestDrive 'report'
    $script:Main = Join-Path $script:ProjectRoot 'CheckBackdoor.ps1'
    $script:Skip = 'FileSystem,Processes,Services,Network,Browser,Injections'
    function Invoke-Scan {
        param([string[]]$Extra = @())
        $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Main, '-NoElevate', '-NoOpen', '-Skip', $script:Skip, '-OutputDir', $script:Out) + $Extra
        $ErrorActionPreference = 'Continue'
        $output = & powershell.exe @psArgs 2>&1 | ForEach-Object { "$_" } | Out-String
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
    # La prima scansione gira come la lancera' l'app: in silenzio, con il file di eventi
    $script:EventsPath = Join-Path $TestDrive 'eventi.jsonl'
    $script:First = Invoke-Scan -Extra '-Quiet', '-EventsFile', $script:EventsPath
    $script:Events = @(Get-Content -LiteralPath $script:EventsPath -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
}

Describe 'Eventi della scansione' -Tag 'E2E' {
    It 'non scrive nulla in console con -Quiet' {
        $script:First.Output.Trim() | Should -BeNullOrEmpty
    }
    It 'si apre con scan.started e si chiude con scan.completed' {
        $script:Events[0].type | Should -Be 'scan.started'
        $script:Events[-1].type | Should -Be 'scan.completed'
        $script:Events[-1].data.exitCode | Should -Be $script:First.ExitCode
    }
    It 'usa lo stesso schema e una numerazione continua' {
        $script:Events.schema | Sort-Object -Unique | Should -Be 'checkbackdoor.events/1'
        $script:Events.seq | Should -Be (1..$script:Events.Count)
    }
    It 'apre e chiude ogni controllo annunciato' {
        $announced = $script:Events[0].data.checks.id
        $announced | Should -Not -Contain 'FileSystem'
        ($script:Events | Where-Object type -eq 'check.started').data.id | Should -Be $announced
        ($script:Events | Where-Object type -eq 'check.completed').data.id | Should -Be $announced
    }
    It 'riporta le stesse segnalazioni del report, con gli stessi ID' {
        $done = $script:Events[-1].data
        $report = [IO.File]::ReadAllText($done.report.json) | ConvertFrom-Json
        $fromEvents = @($script:Events | Where-Object type -eq 'finding' | ForEach-Object { $_.data.finding.Id }) | Sort-Object
        $fromReport = @($report.Findings.Id) | Sort-Object
        $fromEvents | Should -Be $fromReport
        $done.report.html | Should -Exist
    }
}

Describe 'Annullamento' -Tag 'E2E' {
    It 'si ferma con scan.cancelled e codice 3 quando trova il file .cancel' {
        $dir = Join-Path $TestDrive 'annullata'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $events = Join-Path $dir 'eventi.jsonl'
        Set-Content -LiteralPath "$events.cancel" -Value ''
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -NoElevate -NoOpen -Quiet -OutputDir $dir -EventsFile $events 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 3
        $ev = @(Get-Content -LiteralPath $events | ForEach-Object { $_ | ConvertFrom-Json })
        $ev[0].type | Should -Be 'scan.started'
        $ev[-1].type | Should -Be 'scan.cancelled'
        Test-Path -LiteralPath "$events.cancel" | Should -BeFalse
        Get-ChildItem -LiteralPath $dir -Filter 'scansione_*' | Should -BeNullOrEmpty
    }
}

Describe 'Motore incompleto' -Tag 'E2E' {
    It 'spiega che manca un modulo (es. in quarantena) ed esce con codice 4' {
        # Copia del motore senza un modulo, come dopo l'intervento di un antivirus
        $eng = Join-Path $TestDrive 'motore-incompleto'
        New-Item -ItemType Directory -Path (Join-Path $eng 'modules') -Force | Out-Null
        Copy-Item -LiteralPath $script:Main -Destination $eng
        Get-ChildItem -LiteralPath (Join-Path $script:ProjectRoot 'modules') -Filter '*.ps1' |
            Where-Object Name -ne 'Browser.ps1' | Copy-Item -Destination (Join-Path $eng 'modules')
        $events = Join-Path $eng 'eventi.jsonl'
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $eng 'CheckBackdoor.ps1') -NoElevate -NoOpen -Quiet -OutputDir $eng -EventsFile $events 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 4
        $ev = @(Get-Content -LiteralPath $events | ForEach-Object { $_ | ConvertFrom-Json })
        $ev[-1].type | Should -Be 'scan.failed'
        $ev[-1].data.message | Should -Match 'modules\\Browser\.ps1.*antivirus'
    }
}

Describe 'Controllo di un file' -Tag 'E2E' {
    BeforeAll {
        # Un eseguibile non firmato "scaricato da internet", nella stessa cartella dei report:
        # il confronto successivo deve ignorare il suo controllo_*.json
        $exe = Join-Path $TestDrive 'scaricato.exe'
        $ns = 'CbE2E' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        Add-Type -TypeDefinition "namespace $ns { public static class P { public static void Main() { } } }" -OutputAssembly $exe -OutputType ConsoleApplication
        Set-Content -LiteralPath $exe -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://download.example.invalid/scaricato.exe"
        $ErrorActionPreference = 'Continue'
        $script:FileRun = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -File $exe -NoOpen -Quiet -OutputDir $script:Out 2>&1 | ForEach-Object { "$_" } | Out-String
        $script:FileExit = $LASTEXITCODE
        $script:FileJson = Get-ChildItem -LiteralPath $script:Out -Filter 'controllo_*.json' | Select-Object -First 1
    }
    It 'scrive un report controllo_* invece di scansione_*' {
        $script:FileJson | Should -Not -BeNullOrEmpty -Because $script:FileRun
        Get-ChildItem -LiteralPath $script:Out -Filter 'controllo_*.html' | Should -Not -BeNullOrEmpty
    }
    It 'analizza solo il file, senza chiedere l''amministratore' {
        $data = [IO.File]::ReadAllText($script:FileJson.FullName) | ConvertFrom-Json
        $data.Meta.Mode | Should -Be 'File'
        @($data.Findings.Category | Sort-Object -Unique) | Should -Be 'File analizzato'
        $data.Findings[0].Reasons -join ' ' | Should -Match 'download\.example\.invalid'
    }
    It 'termina con "da verificare" per un eseguibile non firmato scaricato' {
        $script:FileExit | Should -BeIn 1, 2
    }
    It 'intitola il report con il nome del file' {
        $html = [IO.File]::ReadAllText([IO.Path]::ChangeExtension($script:FileJson.FullName, '.html'))
        $html | Should -Match '<h1>Controllo di scaricato\.exe</h1>'
    }
}

Describe 'Scansione completa' -Tag 'E2E' {
    It 'termina con un codice previsto (0, 1 o 2)' {
        $script:First.ExitCode | Should -BeIn 0, 1, 2 -Because $script:First.Output
    }
    It 'scrive report HTML, JSON e CSV' {
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.html').Count | Should -Be 1
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.json').Count | Should -Be 1
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.csv').Count | Should -Be 1
    }
    It 'produce un JSON leggibile con le aree saltate' {
        $json = Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.json' | Select-Object -First 1
        $data = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json
        $data.Meta.Version | Should -Not -BeNullOrEmpty
        @($data.Meta.Skipped) | Should -Contain 'FileSystem'
        @($data.Inventory).Count | Should -BeGreaterThan 0
    }
    It 'produce un report HTML che non carica nulla da internet' {
        $html = [IO.File]::ReadAllText((Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.html' | Select-Object -First 1).FullName)
        $html | Should -Match '<h1>Verifica di '
        $html | Should -Not -Match '<script[^>]+src=|<link[^>]+href=|<img\s'
    }
    It 'rifiuta un controllo sconosciuto in -Skip' {
        # L'errore arriva su stderr: lo si legge come testo, senza farlo diventare un'eccezione
        $ErrorActionPreference = 'Continue'
        $r = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -NoElevate -NoOpen -Skip 'Inesistente' -OutputDir $script:Out 2>&1 |
            ForEach-Object { "$_" } | Out-String
        $LASTEXITCODE | Should -Not -Be 0
        $r | Should -Match 'Controllo sconosciuto'
    }
    It 'non trova differenze confrontando due scansioni consecutive' {
        Start-Sleep -Seconds 1   # i nomi dei file hanno la risoluzione del secondo
        $second = Invoke-Scan -Extra '-CompareLast'
        $second.ExitCode | Should -BeIn 0, 1, 2
        $json = Get-ChildItem -LiteralPath $script:Out -Filter 'scansione_*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        $data = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json
        $data.Meta.ComparedTo | Should -Not -BeNullOrEmpty
        Split-Path -Leaf $data.Meta.ComparedTo | Should -Match '^scansione_'
        @($data.Findings | Where-Object { $_.Category -like 'Novit*' -and $_.Severity -ne 'Info' }) | Should -BeNullOrEmpty
    }
}
