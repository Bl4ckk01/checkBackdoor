# Controlli sul codice sorgente: sintassi, codifica, nessuna connessione nascosta,
# nessun dato personale nei file che finiscono nella repository.

BeforeDiscovery {
    $root = Split-Path -Parent $PSScriptRoot
    $scripts = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' -File |
        Where-Object { $_.FullName -notmatch '\\(report|\.taste-skill|\.impeccable|bin|obj)\\' } |
        ForEach-Object { @{ File = $_.FullName; Name = $_.FullName.Substring($root.Length + 1) } })
    # Letti da powershell.exe con la codifica ANSI: devono restare ASCII
    $ansiRead = @(@('CheckBackdoor.ps1', 'Azioni.ps1', 'Avvia-Scansione.bat', 'Controlla-File.bat') + @(Get-ChildItem -LiteralPath (Join-Path $root 'tests'), (Join-Path $root 'tools') -Filter '*.ps1' | ForEach-Object { "$($_.Directory.Name)\$($_.Name)" }) |
        ForEach-Object { @{ File = (Join-Path $root $_); Name = $_ } })
}

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    $root = $script:ProjectRoot
    function Get-Ast([string]$Path) {
        $t = $null; $e = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
    }
}

Describe 'Sintassi' {
    It '<Name> non ha errori di sintassi' -ForEach $scripts {
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$t, [ref]$e)
        $e | Should -BeNullOrEmpty
    }
}

Describe 'Codifica' {
    It '<Name> contiene solo caratteri ASCII' -ForEach $ansiRead {
        $bytes = [IO.File]::ReadAllBytes($File)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Struttura' {
    It 'ogni controllo dello script principale esiste in un modulo' {
        $defined = Get-ChildItem -LiteralPath (Join-Path $root 'modules') -Filter '*.ps1' | ForEach-Object {
            (Get-Ast $_.FullName).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name
        }
        $called = (Get-Ast (Join-Path $root 'CheckBackdoor.ps1')).FindAll({ param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -like 'Invoke-Check*' }, $true) |
            ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique
        $called | Should -Not -BeNullOrEmpty
        foreach ($c in $called) { $defined | Should -Contain $c }
    }
    It 'ogni modulo elencato nello script principale esiste' {
        $text = [IO.File]::ReadAllText((Join-Path $root 'CheckBackdoor.ps1'))
        $list = [regex]::Match($text, '\$modules = ([^\r\n]+)').Groups[1].Value
        foreach ($m in [regex]::Matches($list, "'(\w+)'")) {
            Join-Path $root "modules\$($m.Groups[1].Value).ps1" | Should -Exist
        }
    }
}

Describe 'Privacy' {
    It 'solo il modulo VirusTotal fa richieste di rete' {
        $netCommands = 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'curl', 'wget', 'Start-BitsTransfer', 'Send-MailMessage'
        $offenders = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $root 'modules') -Filter '*.ps1') {
            if ($f.Name -eq 'VirusTotal.ps1') { continue }
            $ast = Get-Ast $f.FullName
            $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.GetCommandName() -in $netCommands }
            $types = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true) |
                Where-Object { $_.TypeName.FullName -match 'WebClient|HttpClient|WebRequest|TcpClient' }
            $newObj = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Object' }, $true) |
                Where-Object { $_.Extent.Text -match 'WebClient|HttpClient|WebRequest|TcpClient' }
            if ($cmds -or $types -or $newObj) { $f.Name }
        }
        $offenders | Should -BeNullOrEmpty
    }
    It '.gitignore esclude report, lista bianca personale e compilazione dell''app' {
        $gi = Get-Content -LiteralPath (Join-Path $root '.gitignore')
        $gi | Should -Contain 'report/'
        $gi | Should -Contain 'allowlist.local.json'
        $gi | Should -Contain 'app/**/bin/'
        $gi | Should -Contain 'app/**/obj/'
    }
    It 'l''interfaccia dell''app non carica nulla da internet' {
        $ui = Join-Path $root 'app\CheckBackdoor.App\ui'
        foreach ($f in Get-ChildItem -LiteralPath $ui -File) {
            [IO.File]::ReadAllText($f.FullName) | Should -Not -Match '(src|href)\s*=\s*["'']https?://|@import|url\(\s*["'']?https?:' -Because $f.Name
        }
    }
    It 'la lista bianca condivisa e'' vuota' {
        $al = Get-Content -LiteralPath (Join-Path $root 'allowlist.json') -Raw | ConvertFrom-Json
        @($al.paths).Count + @($al.sha256).Count + @($al.titles).Count | Should -Be 0
    }
    It 'nessun file pubblicabile contiene il nome utente o il nome del PC di chi sviluppa' {
        $names = @($env:USERNAME, $env:COMPUTERNAME) | Where-Object { $_ -and $_.Length -ge 4 -and $_ -notmatch '^(runneradmin|runner|administrator|admin|user)$' }
        if (-not $names) { Set-ItResult -Skipped -Because 'nome utente e nome del PC troppo generici per il controllo'; return }
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
            $_.FullName -notmatch '\\(report|\.taste-skill|bin|obj)\\|\\\.impeccable\\(review|live)\\|\\\.impeccable\\[^\\]+\.cache\.json$|\\\.git\\|allowlist\.local\.json$|testResults\.xml$|\.user$' -and $_.Length -lt 2MB }
        $hits = $files | Select-String -Pattern ($names | ForEach-Object { [regex]::Escape($_) }) -SimpleMatch:$false -List -ErrorAction SilentlyContinue
        @($hits | ForEach-Object { $_.Path.Substring($root.Length + 1) }) | Should -BeNullOrEmpty
    }
}
