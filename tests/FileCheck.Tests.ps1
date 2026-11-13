# Checking a file before opening it, on files built in the TestDrive folder.
# The test executable is a real unsigned .NET program, compiled on the fly:
# it is never run, it is only a file to analyze.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript FileCheck)

    $fx = Join-Path $TestDrive 'fixtures'
    New-Item -ItemType Directory -Path $fx -Force | Out-Null
    $script:App = Join-Path $fx 'app.exe'
    $ns = 'CbTest' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    Add-Type -TypeDefinition "namespace $ns { public static class P { public static void Main() { System.Console.WriteLine(1); } } }" `
        -OutputAssembly $script:App -OutputType ConsoleApplication

    function New-Copy([string]$Name) { $p = Join-Path $fx $Name; Copy-Item -LiteralPath $script:App -Destination $p; $p }

    # Renames the first section of the executable, as packers do (UPX0)
    function Set-FirstSectionName([string]$Path, [string]$Name) {
        $b = [IO.File]::ReadAllBytes($Path)
        $pe = [BitConverter]::ToInt32($b, 0x3C)
        $optSize = [BitConverter]::ToUInt16($b, $pe + 20)
        $sec = $pe + 24 + $optSize
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($Name.PadRight(8, [char]0))
        [Array]::Copy($nameBytes, 0, $b, $sec, 8)
        [IO.File]::WriteAllBytes($Path, $b)
    }

    function Get-Result([string]$Path) {
        $script:Findings.Clear(); $script:Inventory.Clear(); $script:FileCache = @{}
        Invoke-CheckFile -Path $Path
        $script:Findings | Where-Object { $_.Path -eq $Path } | Select-Object -First 1
    }
}

Describe 'Get-PeInfo' {
    It 'recognizes a .NET executable' {
        $pe = Get-PeInfo $script:App
        $pe | Should -Not -BeNullOrEmpty
        $pe.IsDotNet | Should -BeTrue
        $pe.Sections.Name | Should -Contain '.text'
    }
    It 'recognizes a native 64-bit executable' {
        $pe = Get-PeInfo "$env:SystemRoot\System32\notepad.exe"
        $pe.Is64 | Should -BeTrue
        $pe.IsDotNet | Should -BeFalse
    }
    It 'returns $null for a file that is not an executable' {
        $t = Join-Path $TestDrive 'text.exe'
        Set-Content -LiteralPath $t -Value ('a' * 2000)
        Get-PeInfo $t | Should -BeNullOrEmpty
    }
    It 'measures the data appended after the last section' {
        $p = New-Copy 'overlay.exe'
        $fs = [IO.File]::Open($p, 'Append'); $fs.Write((New-Object byte[] 4096), 0, 4096); $fs.Dispose()
        $pe = Get-PeInfo $p
        $pe.OverlaySize | Should -Be 4096
        $pe.OverlayEntropy | Should -Be 0
    }
}

Describe 'Test-SingleFile' {
    It 'does not flag a signed Microsoft program' {
        $r = Get-Result "$env:SystemRoot\System32\notepad.exe"
        $r.Severity | Should -Be 'Info'
        $r.Reasons -join ' ' | Should -Match 'Signed by Microsoft'
    }
    It 'flags an unsigned executable' {
        (Get-Result $script:App).Reasons -join ' ' | Should -Match 'Not digitally signed'
    }
    It 'reports where it was downloaded from' {
        $p = New-Copy 'downloaded.exe'
        Set-Content -LiteralPath $p -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://download.example.invalid/downloaded.exe"
        $r = Get-Result $p
        $r.Reasons -join ' ' | Should -Match 'Downloaded from https://download\.example\.invalid'
        $r.Reasons -join ' ' | Should -Match 'Downloaded from the internet and unsigned'
    }
    It 'rates a program with a double extension as High' {
        (Get-Result (New-Copy 'holiday photo.jpg.exe')).Severity | Should -Be 'High'
    }
    It 'rates a name with the right-to-left override character as High' {
        $name = 'invoice' + [char]0x202E + 'fdp.exe'
        (Get-Result (New-Copy $name)).Severity | Should -Be 'High'
    }
    It 'rates as High an executable inflated with zeros to exceed antivirus limits' {
        $p = New-Copy 'inflated.exe'
        $fs = [IO.File]::Open($p, 'Append')
        $zeros = New-Object byte[] (1MB)
        for ($i = 0; $i -lt 52; $i++) { $fs.Write($zeros, 0, $zeros.Length) }
        $fs.Dispose()
        $r = Get-Result $p
        $r.Severity | Should -Be 'High'
        $r.Reasons -join ' ' | Should -Match 'Inflated'
    }
    It 'recognizes an executable packed with UPX' {
        $p = New-Copy 'packed.exe'
        Set-FirstSectionName $p 'UPX0'
        (Get-Result $p).Reasons -join ' ' | Should -Match 'UPX'
    }
    It 'flags an obfuscated script' {
        $p = Join-Path $fx 'startup.vbs'
        Set-Content -LiteralPath $p -Value ('x = "' + ('QUJD' * 120) + '"')
        $r = Get-Result $p
        $r.Severity | Should -BeIn 'Medium', 'High'
        $r.Reasons -join ' ' | Should -Match 'Obfuscated'
    }
    It 'flags a shortcut that launches PowerShell' {
        $p = Join-Path $fx 'Document.lnk'
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($p)
        $lnk.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $lnk.Arguments = '-NoProfile -File startup.ps1'
        $lnk.Save()
        (Get-Result $p).Reasons -join ' ' | Should -Match 'command interpreter'
    }
    It 'flags an archive that contains misleading files' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path $TestDrive 'zipsrc'
        New-Item -ItemType Directory -Path $src -Force | Out-Null
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $src 'document.pdf.exe')
        $zip = Join-Path $fx 'archive.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        $r = Get-Result $zip
        $r.Severity | Should -BeIn 'Medium', 'High'
        $r.Reasons -join ' ' | Should -Match 'document\.pdf\.exe'
    }
}

Describe 'Game folder with replaced DLLs' {
    BeforeAll {
        $game = Join-Path $TestDrive 'Game'
        New-Item -ItemType Directory -Path $game -Force | Out-Null
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'game.exe')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'version.dll')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'steam_api64.dll')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'normal-library.dll')
        $script:Findings.Clear(); $script:Inventory.Clear()
        Invoke-CheckFile -Path $game
    }
    It 'rates as High an unsigned system DLL next to the program' {
        ($script:Findings | Where-Object Title -like '*version.dll').Severity | Should -Be 'High'
    }
    It 'flags the game client DLL replaced by a crack' {
        ($script:Findings | Where-Object Title -like '*steam_api64.dll').Severity | Should -Be 'Medium'
    }
    It 'does not flag the other DLLs' {
        $script:Findings | Where-Object Title -like '*normal-library*' | Should -BeNullOrEmpty
    }
    It 'analyzes the executable of the folder' {
        $script:Findings | Where-Object Title -eq 'game.exe' | Should -Not -BeNullOrEmpty
    }
}
