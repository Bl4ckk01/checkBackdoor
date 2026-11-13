# Source code checks: syntax, encoding, no hidden connections,
# no personal data in the files that end up in the repository.

BeforeDiscovery {
    $root = Split-Path -Parent $PSScriptRoot
    $scripts = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' -File |
        Where-Object { $_.FullName -notmatch '\\(report|\.taste-skill|\.impeccable|bin|obj)\\' } |
        ForEach-Object { @{ File = $_.FullName; Name = $_.FullName.Substring($root.Length + 1) } })
    # Read by powershell.exe with the ANSI code page: they must stay ASCII
    $ansiRead = @(@('CheckBackdoor.ps1', 'Actions.ps1', 'Start-Scan.bat', 'Check-File.bat') + @(Get-ChildItem -LiteralPath (Join-Path $root 'tests'), (Join-Path $root 'tools') -Filter '*.ps1' | ForEach-Object { "$($_.Directory.Name)\$($_.Name)" }) |
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

Describe 'Syntax' {
    It '<Name> has no syntax errors' -ForEach $scripts {
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$t, [ref]$e)
        $e | Should -BeNullOrEmpty
    }
}

Describe 'Encoding' {
    It '<Name> contains only ASCII characters' -ForEach $ansiRead {
        $bytes = [IO.File]::ReadAllBytes($File)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'Structure' {
    It 'every check of the main script exists in a module' {
        $defined = Get-ChildItem -LiteralPath (Join-Path $root 'modules') -Filter '*.ps1' | ForEach-Object {
            (Get-Ast $_.FullName).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name
        }
        $called = (Get-Ast (Join-Path $root 'CheckBackdoor.ps1')).FindAll({ param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -like 'Invoke-Check*' }, $true) |
            ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique
        $called | Should -Not -BeNullOrEmpty
        foreach ($c in $called) { $defined | Should -Contain $c }
    }
    It 'every module listed in the main script exists' {
        $text = [IO.File]::ReadAllText((Join-Path $root 'CheckBackdoor.ps1'))
        $list = [regex]::Match($text, '\$modules = ([^\r\n]+)').Groups[1].Value
        foreach ($m in [regex]::Matches($list, "'(\w+)'")) {
            Join-Path $root "modules\$($m.Groups[1].Value).ps1" | Should -Exist
        }
    }
}

Describe 'Privacy' {
    It 'only the VirusTotal module makes network requests' {
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
    It '.gitignore excludes reports, the personal allowlist and the app build' {
        $gi = Get-Content -LiteralPath (Join-Path $root '.gitignore')
        $gi | Should -Contain 'report/'
        $gi | Should -Contain 'allowlist.local.json'
        $gi | Should -Contain 'app/**/bin/'
        $gi | Should -Contain 'app/**/obj/'
    }
    It 'the app interface loads nothing from the internet' {
        $ui = Join-Path $root 'app\CheckBackdoor.App\ui'
        foreach ($f in Get-ChildItem -LiteralPath $ui -File) {
            [IO.File]::ReadAllText($f.FullName) | Should -Not -Match '(src|href)\s*=\s*["'']https?://|@import|url\(\s*["'']?https?:' -Because $f.Name
        }
    }
    It 'the shared allowlist is empty' {
        $al = Get-Content -LiteralPath (Join-Path $root 'allowlist.json') -Raw | ConvertFrom-Json
        @($al.paths).Count + @($al.sha256).Count + @($al.titles).Count | Should -Be 0
    }
    It 'no publishable file contains the developer''s user name or PC name' {
        $names = @($env:USERNAME, $env:COMPUTERNAME) | Where-Object { $_ -and $_.Length -ge 4 -and $_ -notmatch '^(runneradmin|runner|administrator|admin|user)$' }
        if (-not $names) { Set-ItResult -Skipped -Because 'user name and PC name too generic for the check'; return }
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
            $_.FullName -notmatch '\\(report|dist|\.taste-skill|bin|obj)\\|\\\.impeccable\\(review|live)\\|\\\.impeccable\\[^\\]+\.cache\.json$|\\\.git\\|allowlist\.local\.json$|testResults\.xml$|\.user$' -and $_.Length -lt 2MB }
        $hits = $files | Select-String -Pattern ($names | ForEach-Object { [regex]::Escape($_) }) -SimpleMatch:$false -List -ErrorAction SilentlyContinue
        @($hits | ForEach-Object { $_.Path.Substring($root.Length + 1) }) | Should -BeNullOrEmpty
    }
}
