# Controllo di un file prima di aprirlo, su file costruiti nella cartella TestDrive.
# L'eseguibile di prova e' un vero programma .NET non firmato, compilato al volo:
# non viene mai eseguito, serve solo come file da analizzare.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript FileCheck)

    $fx = Join-Path $TestDrive 'fixtures'
    New-Item -ItemType Directory -Path $fx -Force | Out-Null
    $script:App = Join-Path $fx 'app.exe'
    $ns = 'CbTest' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    Add-Type -TypeDefinition "namespace $ns { public static class P { public static void Main() { System.Console.WriteLine(1); } } }" `
        -OutputAssembly $script:App -OutputType ConsoleApplication

    function New-Copy([string]$Name) { $p = Join-Path $fx $Name; Copy-Item -LiteralPath $script:App -Destination $p; $p }

    # Rinomina la prima sezione dell'eseguibile, come fanno i compressori (UPX0)
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
    It 'riconosce un eseguibile .NET' {
        $pe = Get-PeInfo $script:App
        $pe | Should -Not -BeNullOrEmpty
        $pe.IsDotNet | Should -BeTrue
        $pe.Sections.Name | Should -Contain '.text'
    }
    It 'riconosce un eseguibile nativo a 64 bit' {
        $pe = Get-PeInfo "$env:SystemRoot\System32\notepad.exe"
        $pe.Is64 | Should -BeTrue
        $pe.IsDotNet | Should -BeFalse
    }
    It 'restituisce $null per un file che non e'' un eseguibile' {
        $t = Join-Path $TestDrive 'testo.exe'
        Set-Content -LiteralPath $t -Value ('a' * 2000)
        Get-PeInfo $t | Should -BeNullOrEmpty
    }
    It 'misura i dati accodati dopo l''ultima sezione' {
        $p = New-Copy 'overlay.exe'
        $fs = [IO.File]::Open($p, 'Append'); $fs.Write((New-Object byte[] 4096), 0, 4096); $fs.Dispose()
        $pe = Get-PeInfo $p
        $pe.OverlaySize | Should -Be 4096
        $pe.OverlayEntropy | Should -Be 0
    }
}

Describe 'Test-SingleFile' {
    It 'non segnala un programma Microsoft firmato' {
        $r = Get-Result "$env:SystemRoot\System32\notepad.exe"
        $r.Severity | Should -Be 'Info'
        $r.Reasons -join ' ' | Should -Match 'Firmato da Microsoft'
    }
    It 'segnala un eseguibile non firmato' {
        (Get-Result $script:App).Reasons -join ' ' | Should -Match 'Non firmato'
    }
    It 'riporta da dove e'' stato scaricato' {
        $p = New-Copy 'scaricato.exe'
        Set-Content -LiteralPath $p -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://download.example.invalid/scaricato.exe"
        $r = Get-Result $p
        $r.Reasons -join ' ' | Should -Match 'Scaricato da https://download\.example\.invalid'
        $r.Reasons -join ' ' | Should -Match 'Scaricato da internet e senza firma'
    }
    It 'segna come Alto un programma con doppia estensione' {
        (Get-Result (New-Copy 'foto vacanze.jpg.exe')).Severity | Should -Be 'Alto'
    }
    It 'segna come Alto un nome con il carattere che inverte il testo' {
        $name = 'fattura' + [char]0x202E + 'fdp.exe'
        (Get-Result (New-Copy $name)).Severity | Should -Be 'Alto'
    }
    It 'segna come Alto un eseguibile gonfiato di zeri per superare i limiti degli antivirus' {
        $p = New-Copy 'gonfiato.exe'
        $fs = [IO.File]::Open($p, 'Append')
        $zeros = New-Object byte[] (1MB)
        for ($i = 0; $i -lt 52; $i++) { $fs.Write($zeros, 0, $zeros.Length) }
        $fs.Dispose()
        $r = Get-Result $p
        $r.Severity | Should -Be 'Alto'
        $r.Reasons -join ' ' | Should -Match 'Gonfiato'
    }
    It 'riconosce un eseguibile compresso con UPX' {
        $p = New-Copy 'compresso.exe'
        Set-FirstSectionName $p 'UPX0'
        (Get-Result $p).Reasons -join ' ' | Should -Match 'UPX'
    }
    It 'segnala uno script offuscato' {
        $p = Join-Path $fx 'avvio.vbs'
        Set-Content -LiteralPath $p -Value ('x = "' + ('QUJD' * 120) + '"')
        $r = Get-Result $p
        $r.Severity | Should -BeIn 'Medio', 'Alto'
        $r.Reasons -join ' ' | Should -Match 'offuscato'
    }
    It 'segnala un collegamento che lancia PowerShell' {
        $p = Join-Path $fx 'Documento.lnk'
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($p)
        $lnk.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $lnk.Arguments = '-NoProfile -File avvio.ps1'
        $lnk.Save()
        (Get-Result $p).Reasons -join ' ' | Should -Match 'interprete di comandi'
    }
    It 'segnala un archivio che contiene file ingannevoli' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path $TestDrive 'zipsrc'
        New-Item -ItemType Directory -Path $src -Force | Out-Null
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $src 'documento.pdf.exe')
        $zip = Join-Path $fx 'archivio.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        $r = Get-Result $zip
        $r.Severity | Should -BeIn 'Medio', 'Alto'
        $r.Reasons -join ' ' | Should -Match 'documento\.pdf\.exe'
    }
}

Describe 'Cartella di un gioco con DLL sostituite' {
    BeforeAll {
        $game = Join-Path $TestDrive 'Gioco'
        New-Item -ItemType Directory -Path $game -Force | Out-Null
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'gioco.exe')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'version.dll')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'steam_api64.dll')
        Copy-Item -LiteralPath $script:App -Destination (Join-Path $game 'libreria-normale.dll')
        $script:Findings.Clear(); $script:Inventory.Clear()
        Invoke-CheckFile -Path $game
    }
    It 'segna come Alto una DLL di sistema non firmata accanto al programma' {
        ($script:Findings | Where-Object Title -like '*version.dll').Severity | Should -Be 'Alto'
    }
    It 'segnala la DLL del client di gioco sostituita da un crack' {
        ($script:Findings | Where-Object Title -like '*steam_api64.dll').Severity | Should -Be 'Medio'
    }
    It 'non segnala le altre DLL' {
        $script:Findings | Where-Object Title -like '*libreria-normale*' | Should -BeNullOrEmpty
    }
    It 'analizza l''eseguibile della cartella' {
        $script:Findings | Where-Object Title -eq 'gioco.exe' | Should -Not -BeNullOrEmpty
    }
}
