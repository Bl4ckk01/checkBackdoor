# A real scan with powershell.exe, as a user starts it. Skips the slowest checks
# (files, processes, services, network, browsers) to stay under a minute.

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
    # The first scan runs as the app will start it: silently, with the event file
    $script:EventsPath = Join-Path $TestDrive 'events.jsonl'
    $script:First = Invoke-Scan -Extra '-Quiet', '-EventsFile', $script:EventsPath
    $script:Events = @(Get-Content -LiteralPath $script:EventsPath -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
}

Describe 'Scan events' -Tag 'E2E' {
    It 'writes nothing to the console with -Quiet' {
        $script:First.Output.Trim() | Should -BeNullOrEmpty
    }
    It 'opens with scan.started and closes with scan.completed' {
        $script:Events[0].type | Should -Be 'scan.started'
        $script:Events[-1].type | Should -Be 'scan.completed'
        $script:Events[-1].data.exitCode | Should -Be $script:First.ExitCode
    }
    It 'uses the same schema and continuous numbering' {
        $script:Events.schema | Sort-Object -Unique | Should -Be 'checkbackdoor.events/1'
        $script:Events.seq | Should -Be (1..$script:Events.Count)
    }
    It 'opens and closes every announced check' {
        $announced = $script:Events[0].data.checks.id
        $announced | Should -Not -Contain 'FileSystem'
        ($script:Events | Where-Object type -eq 'check.started').data.id | Should -Be $announced
        ($script:Events | Where-Object type -eq 'check.completed').data.id | Should -Be $announced
    }
    It 'reports the same findings as the report, with the same IDs' {
        $done = $script:Events[-1].data
        $report = [IO.File]::ReadAllText($done.report.json) | ConvertFrom-Json
        $fromEvents = @($script:Events | Where-Object type -eq 'finding' | ForEach-Object { $_.data.finding.Id }) | Sort-Object
        $fromReport = @($report.Findings.Id) | Sort-Object
        $fromEvents | Should -Be $fromReport
        $done.report.html | Should -Exist
    }
}

Describe 'Cancelling' -Tag 'E2E' {
    It 'stops with scan.cancelled and exit code 3 when it finds the .cancel file' {
        $dir = Join-Path $TestDrive 'cancelled'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $events = Join-Path $dir 'events.jsonl'
        Set-Content -LiteralPath "$events.cancel" -Value ''
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -NoElevate -NoOpen -Quiet -OutputDir $dir -EventsFile $events 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 3
        $ev = @(Get-Content -LiteralPath $events | ForEach-Object { $_ | ConvertFrom-Json })
        $ev[0].type | Should -Be 'scan.started'
        $ev[-1].type | Should -Be 'scan.cancelled'
        Test-Path -LiteralPath "$events.cancel" | Should -BeFalse
        Get-ChildItem -LiteralPath $dir -Filter 'scan_*' | Should -BeNullOrEmpty
    }
}

Describe 'Incomplete engine' -Tag 'E2E' {
    It 'explains that a module is missing (for example quarantined) and exits with code 4' {
        # A copy of the engine without one module, as after an antivirus stepped in
        $eng = Join-Path $TestDrive 'incomplete-engine'
        New-Item -ItemType Directory -Path (Join-Path $eng 'modules') -Force | Out-Null
        Copy-Item -LiteralPath $script:Main -Destination $eng
        Get-ChildItem -LiteralPath (Join-Path $script:ProjectRoot 'modules') -Filter '*.ps1' |
            Where-Object Name -ne 'Browser.ps1' | Copy-Item -Destination (Join-Path $eng 'modules')
        $events = Join-Path $eng 'events.jsonl'
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $eng 'CheckBackdoor.ps1') -NoElevate -NoOpen -Quiet -OutputDir $eng -EventsFile $events 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 4
        $ev = @(Get-Content -LiteralPath $events | ForEach-Object { $_ | ConvertFrom-Json })
        $ev[-1].type | Should -Be 'scan.failed'
        $ev[-1].data.message | Should -Match 'modules\\Browser\.ps1.*antivirus'
    }
}

Describe 'Checking a file' -Tag 'E2E' {
    BeforeAll {
        # An unsigned executable "downloaded from the internet", in the same folder as the reports:
        # the next comparison must ignore its check_*.json
        $exe = Join-Path $TestDrive 'downloaded.exe'
        $ns = 'CbE2E' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        Add-Type -TypeDefinition "namespace $ns { public static class P { public static void Main() { } } }" -OutputAssembly $exe -OutputType ConsoleApplication
        Set-Content -LiteralPath $exe -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://download.example.invalid/downloaded.exe"
        $ErrorActionPreference = 'Continue'
        $script:FileRun = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -File $exe -NoOpen -Quiet -OutputDir $script:Out 2>&1 | ForEach-Object { "$_" } | Out-String
        $script:FileExit = $LASTEXITCODE
        $script:FileJson = Get-ChildItem -LiteralPath $script:Out -Filter 'check_*.json' | Select-Object -First 1
    }
    It 'writes a check_* report instead of scan_*' {
        $script:FileJson | Should -Not -BeNullOrEmpty -Because $script:FileRun
        Get-ChildItem -LiteralPath $script:Out -Filter 'check_*.html' | Should -Not -BeNullOrEmpty
    }
    It 'analyzes only the file, without asking for the administrator' {
        $data = [IO.File]::ReadAllText($script:FileJson.FullName) | ConvertFrom-Json
        $data.Meta.Mode | Should -Be 'File'
        @($data.Findings.Category | Sort-Object -Unique) | Should -Be 'Checked file'
        $data.Findings[0].Reasons -join ' ' | Should -Match 'download\.example\.invalid'
    }
    It 'ends with "to review" for an unsigned downloaded executable' {
        $script:FileExit | Should -BeIn 1, 2
    }
    It 'titles the report with the file name' {
        $html = [IO.File]::ReadAllText([IO.Path]::ChangeExtension($script:FileJson.FullName, '.html'))
        $html | Should -Match '<h1>Check of downloaded\.exe</h1>'
    }
}

Describe 'Full scan' -Tag 'E2E' {
    It 'ends with an expected code (0, 1 or 2)' {
        $script:First.ExitCode | Should -BeIn 0, 1, 2 -Because $script:First.Output
    }
    It 'writes HTML, JSON and CSV reports' {
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.html').Count | Should -Be 1
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.json').Count | Should -Be 1
        (Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.csv').Count | Should -Be 1
    }
    It 'produces a readable JSON with the skipped areas' {
        $json = Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.json' | Select-Object -First 1
        $data = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json
        $data.Meta.Version | Should -Not -BeNullOrEmpty
        @($data.Meta.Skipped) | Should -Contain 'FileSystem'
        @($data.Inventory).Count | Should -BeGreaterThan 0
    }
    It 'produces an HTML report that loads nothing from the internet' {
        $html = [IO.File]::ReadAllText((Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.html' | Select-Object -First 1).FullName)
        $html | Should -Match '<h1>Scan of '
        $html | Should -Not -Match '<script[^>]+src=|<link[^>]+href=|<img\s'
    }
    It 'rejects an unknown check in -Skip' {
        # The error arrives on stderr: it is read as text, without turning it into an exception
        $ErrorActionPreference = 'Continue'
        $r = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Main -NoElevate -NoOpen -Skip 'Nonexistent' -OutputDir $script:Out 2>&1 |
            ForEach-Object { "$_" } | Out-String
        $LASTEXITCODE | Should -Not -Be 0
        $r | Should -Match 'Unknown check'
    }
    It 'finds no differences comparing two consecutive scans' {
        Start-Sleep -Seconds 1   # file names have one-second resolution
        $second = Invoke-Scan -Extra '-CompareLast'
        $second.ExitCode | Should -BeIn 0, 1, 2
        $json = Get-ChildItem -LiteralPath $script:Out -Filter 'scan_*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        $data = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json
        $data.Meta.ComparedTo | Should -Not -BeNullOrEmpty
        Split-Path -Leaf $data.Meta.ComparedTo | Should -Match '^scan_'
        @($data.Findings | Where-Object { $_.Category -like 'Changes since*' -and $_.Severity -ne 'Info' }) | Should -BeNullOrEmpty
    }
}
