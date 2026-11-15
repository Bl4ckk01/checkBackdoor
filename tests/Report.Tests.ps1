# Report: safe offline HTML, allowlist, comparison between scans.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript Report)

    function New-TestMeta {
        param([bool]$Admin = $true, [string[]]$Skipped = @())
        @{
            Version = 'test'; Computer = 'TEST-PC'; User = 'TEST-PC\user'; Date = '2026-01-01 10:00'; Duration = '1 min 2 s'
            Admin = $Admin; Skipped = $Skipped; Errors = @(); Ignored = 0
            Examined = @{ 'Autostart' = 10; 'Services' = 5 }; Files = @{ Json = 'a.json'; Csv = 'a.csv' }
        }
    }
}

Describe 'New-HtmlReport' {
    BeforeAll {
        $findings = @(
            New-TestFinding -Severity 'High' -Title '<img src=x onerror=alert(1)>' -Evidence '<script>alert(2)</script>'
            New-TestFinding -Severity 'Medium' -Category 'Services' -Title 'Test service'
            New-TestFinding -Severity 'Info' -Category 'Services' -Title 'Information only'
        )
        $html = New-HtmlReport -Findings $findings -Meta (New-TestMeta -Skipped 'Wmi')
    }
    It 'turns names chosen by an attacker into text' {
        $html | Should -Not -Match '<img src=x'
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
    }
    It 'loads nothing from the internet when opened' {
        $html | Should -Not -Match '<script[^>]+src='
        $html | Should -Not -Match '<link[^>]+href='
        $html | Should -Not -Match '<img\s'
        $html | Should -Not -Match '@import|url\(\s*["'']?https?:'
    }
    It 'is in English' {
        $html | Should -Match '<html lang="en">'
    }
    It 'shows the verdict for one high-risk clue' {
        $html | Should -Match 'One high-risk clue'
    }
    It 'counts only non-informational findings as visible' {
        $html | Should -Match '<span data-all-count>2</span>'
        $html | Should -Match 'data-count>2<'
    }
    It 'marks the area of a skipped check as not run' {
        $html | Should -Match 'data-area="WMI"[^>]*><span class="a-name">WMI</span><span class="a-meta">[^<]*</span><span class="a-state s-off">Not run'
    }
    It 'separates date, Windows version and scan type in the subtitle' {
        $meta = New-TestMeta
        $meta.OS = 'Windows 11 Pro'; $meta.Deep = $true
        New-HtmlReport -Findings @() -Meta $meta | Should -Match 'Scan of 2026-01-01 10:00 &middot; Windows 11 Pro &middot; deep scan'
    }
    It 'links the JSON and CSV files of the same scan' {
        $html | Should -Match 'href="a\.json"'
        $html | Should -Match 'href="a\.csv"'
    }
    It 'warns when the scan did not run as administrator' {
        New-HtmlReport -Findings $findings -Meta (New-TestMeta -Admin $false) | Should -Match 'Incomplete checks'
    }
    It 'says there are no clues when the list is empty' {
        $empty = New-HtmlReport -Findings @() -Meta (New-TestMeta)
        $empty | Should -Match 'No signs of a backdoor'
        $empty | Should -Match 'No findings: every area'
    }
}

Describe 'Items hidden by the allowlist in the report' {
    It 'lists them with the rule, as text' {
        $hidden = @([pscustomobject]@{ Id = 'a1'; Category = 'Autostart'; Severity = 'Medium'; Title = '<b>Hidden</b>'; Path = 'C:\SafeApps\x.exe'; Rule = 'path C:\SafeApps\*' })
        $html = New-HtmlReport -Findings @() -Meta (New-TestMeta) -Ignored $hidden
        $html | Should -Match 'id="ig-h"'
        $html | Should -Match '&lt;b&gt;Hidden&lt;/b&gt;'
        $html | Should -Match ([regex]::Escape('path C:\SafeApps\*'))
    }
    It 'does not show the section if nothing was hidden' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) | Should -Not -Match 'id="ig-h"'
    }
}

Describe 'Actions in the report' {
    It 'offers Disable only for items that can be undone, and Ignore never for Info' {
        $with = New-TestFinding -Title 'With action' -Path 'C:\Users\x\AppData\a.exe'
        $with | Add-Member -NotePropertyName Remedy -NotePropertyValue @{ Kind = 'RegistryValue' }
        $without = New-TestFinding -Title 'Without action'
        $info = New-TestFinding -Title 'Information only' -Severity 'Info'
        $html = New-HtmlReport -Findings @($with, $without, $info) -Meta (New-TestMeta)
        ([regex]::Matches($html, 'data-act="disable"')).Count | Should -Be 1
        ([regex]::Matches($html, 'data-act="ignore"')).Count | Should -Be 2
        $html | Should -Match ('class="acts" data-id="' + $with.Id + '"')
    }
    It 'names the action by kind, offers Delete only for files and Fix all for high and medium risk' {
        $file = New-TestFinding -Title 'Suspicious file' -Path 'C:\Users\x\AppData\a.exe'
        $file | Add-Member -NotePropertyName Remedy -NotePropertyValue @{ Kind = 'QuarantineFile'; Path = 'C:\Users\x\AppData\a.exe' }
        $excl = New-TestFinding -Title 'Exclusion' -Severity 'High'
        $excl | Add-Member -NotePropertyName Remedy -NotePropertyValue @{ Kind = 'DefenderExclusion'; Type = 'Path'; Value = 'C:\' }
        $low = New-TestFinding -Title 'Low process' -Severity 'Low'
        $low | Add-Member -NotePropertyName Remedy -NotePropertyValue @{ Kind = 'Process'; ProcessId = 1234; Path = 'C:\x.exe' }
        $html = New-HtmlReport -Findings @($file, $excl, $low) -Meta (New-TestMeta)
        $html | Should -Match '>Quarantine</button>'
        $html | Should -Match '>Remove exclusion</button>'
        $html | Should -Match '>End process</button>'
        ([regex]::Matches($html, 'data-act="delete"')).Count | Should -Be 1
        # Once, at the top: its number counts the items marked data-fix
        ([regex]::Matches($html, 'data-act="fixAll"')).Count | Should -Be 1
        $html | Should -Match 'class="actions"><span class="acts acts-all" data-id="all">'
        $html | Should -Match 'Fix all \(<span data-fix-count>2</span>\)'
        ([regex]::Matches($html, '" data-fix>')).Count | Should -Be 2
        $html | Should -Match 'CheckBackdoor can be wrong'
    }
    It 'offers to show a folder when the item is a folder (browser extensions)' {
        $dir = Join-Path $TestDrive 'ext-folder'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $html = New-HtmlReport -Findings @((New-TestFinding -Title 'Extension' -Path $dir), (New-TestFinding -Title 'File' -Path 'C:\missing\a.exe')) -Meta (New-TestMeta)
        $html | Should -Match 'data-act="reveal">Show the folder<'
        $html | Should -Match 'data-act="reveal">Show the file<'
    }
    It 'shows no Fix all when nothing can be fixed' {
        New-HtmlReport -Findings @(New-TestFinding) -Meta (New-TestMeta) | Should -Not -Match 'data-act="fixAll"'
    }
    It 'hides the actions outside the app' {
        New-HtmlReport -Findings @(New-TestFinding) -Meta (New-TestMeta) | Should -Match '\.acts\{display:none\}'
    }
}

Describe 'Timeline in the report' {
    BeforeAll {
        $finding = New-TestFinding -Category 'Timeline' -Title 'Account created: support' -Evidence 'Created by bob'
        function New-Entry([int]$Minutes, [string]$Text = 'Started tool.exe', [string]$FindingId) {
            [pscustomobject]@{ Time = (Get-Date '2026-03-01 10:00').AddMinutes($Minutes).ToString('s'); Source = 'Programs'; Text = $Text; Path = 'C:\Users\x\Downloads\tool.exe'; Severity = 'Info'; FindingId = $FindingId }
        }
    }
    It 'does not show the section if the check did not run' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) | Should -Not -Match 'id="tl-h"'
    }
    It 'says there are no events when the timeline is empty' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline @() | Should -Match 'No relevant events'
    }
    It 'puts the most recent events first and links the finding' {
        $html = New-HtmlReport -Findings @($finding) -Meta (New-TestMeta) -Timeline @((New-Entry 0 'older-event'), (New-Entry 5 'newer-event' $finding.Id))
        $html.IndexOf('newer-event') | Should -BeLessThan $html.IndexOf('older-event')
        $html | Should -Match ([regex]::Escape("href=""#f-$($finding.Id)"""))
        $html | Should -Match '2026-03-01 10:05'
    }
    It 'turns program names into text' {
        New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline @(New-Entry 0 'Started <img src=x>') | Should -Match '&lt;img src=x&gt;'
    }
    It 'shows at most 60 events and points to the JSON' {
        $many = foreach ($i in 1..65) { New-Entry $i }
        $html = New-HtmlReport -Findings @() -Meta (New-TestMeta) -Timeline $many
        ([regex]::Matches($html, 'class="tl-row"')).Count | Should -Be 60
        $html | Should -Match '5 more events'
    }
}

Describe 'Invoke-Allowlist' {
    BeforeEach {
        $script:Findings = New-Object System.Collections.Generic.List[object]
        $script:Findings.Add((New-TestFinding -Title 'Keep me' -Path 'C:\Other\x.exe'))
        $script:Findings.Add((New-TestFinding -Title 'By path' -Path 'C:\SafeApps\app\x.exe'))
        $script:Findings.Add((New-TestFinding -Title 'IgnoreMe please'))
        $script:Findings.Add((New-TestFinding -Title 'By hash' -Sha256 'abcdef'))
        $shared = Join-Path $TestDrive 'allowlist.json'
        $local = Join-Path $TestDrive 'allowlist.local.json'
        Set-Content -LiteralPath $shared -Value '{ "paths": ["C:\\SafeApps\\*"], "sha256": [], "titles": [] }'
        Set-Content -LiteralPath $local -Value '{ "paths": [], "sha256": ["ABCDEF"], "titles": ["*IgnoreMe*"] }'
    }
    It 'merges the shared list and the local one' {
        Invoke-Allowlist -Path $shared, $local | Should -Be 3
        $script:Findings | Should -HaveCount 1
        $script:Findings[0].Title | Should -Be 'Keep me'
    }
    It 'ignores a file that does not exist' {
        Invoke-Allowlist -Path (Join-Path $TestDrive 'missing.json') | Should -Be 0
        $script:Findings | Should -HaveCount 4
    }
}

Describe 'Compare-WithPrevious' {
    BeforeEach {
        $script:Findings.Clear(); $script:Inventory.Clear()
        $prev = [ordered]@{
            Meta = @{ Date = '2026-01-01 09:00' }
            Inventory = @(
                @{ Category = 'Autostart'; Key = 'Run | One'; Value = 'one.exe' }
                @{ Category = 'Autostart'; Key = 'Run | Gone'; Value = 'gone.exe' }
                @{ Category = 'Network'; Key = 'Established | app.exe | 50000'; Value = '1.2.3.4:443' }
                @{ Category = 'Certificates'; Key = 'Machine root'; Value = 'ABC' }
            )
        }
        $json = Join-Path $TestDrive 'prev.json'
        Set-Content -LiteralPath $json -Value ($prev | ConvertTo-Json -Depth 4)
        Add-InventoryItem 'Autostart' 'Run | One' 'one.exe'
        Add-InventoryItem 'Autostart' 'Run | New' 'new.exe'
        Add-InventoryItem 'Network' 'Established | app.exe | 50123' '5.6.7.8:443'
        Compare-WithPrevious -PreviousJson $json
    }
    It 'flags the startup entry that appeared after the previous scan' {
        $new = @($script:Findings | Where-Object Title -like 'New*')
        $new | Should -HaveCount 1
        $new[0].Title | Should -Match 'Run \| New'
        $new[0].Severity | Should -Be 'Medium'
        $new[0].Category | Should -Be 'Changes since the previous scan'
    }
    It 'ignores network connections, which change all the time' {
        $script:Findings | Where-Object Title -match 'Established' | Should -BeNullOrEmpty
    }
    It 'reports the removed entry as information' {
        $gone = @($script:Findings | Where-Object Title -like 'Removed*')
        $gone | Should -HaveCount 1
        $gone[0].Severity | Should -Be 'Info'
    }
    It 'does not treat items of a skipped check as removed' {
        $script:Findings | Where-Object Title -match 'Certificates' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ExaminedCounts' {
    It 'adds up the entries per area and uses the file counts' {
        $script:Inventory.Clear(); $script:ProcessTable = $null
        Add-InventoryItem 'Services' 'Service: a' 'a'
        Add-InventoryItem 'Safe Mode' 'Minimal | a' 'a'
        Add-InventoryItem 'Suspicious files' 'Executable files examined' '363'
        $c = Get-ExaminedCounts
        $c['Services'] | Should -Be 2
        $c['Suspicious files'] | Should -Be 363
        $c.ContainsKey('Processes') | Should -BeFalse
    }
}
