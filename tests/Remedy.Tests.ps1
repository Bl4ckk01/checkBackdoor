# "Disable" and "Undo" actions on a test key in HKCU and on files in TestDrive:
# they do not touch the real startup locations of the PC.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript CommandRisk)
    . (Get-ModuleScript Remedy)
    $script:TestKey = 'HKCU:\Software\CheckBackdoorTest\Run'
    $script:Backups = Join-Path $TestDrive 'backup'
    # Run as administrator (GitHub Actions) backups go to the protected folder:
    # in the tests it is a test folder, and the test startup files are in TestDrive
    $script:ProtectedBackupDir = Join-Path $TestDrive 'protected\backup'
    $script:DefaultStartupFileAdminPattern = $script:StartupFileAdminPattern
    $script:StartupFileAdminPattern = $script:StartupFilePattern
    function New-Request($Remedy, [string]$Title = 'Test item') {
        [pscustomobject]@{ FindingId = '0123456789abcdef'; Title = $Title; Remedy = [pscustomobject]$Remedy }
    }
}

AfterAll {
    Remove-Item -LiteralPath 'HKCU:\Software\CheckBackdoorTest' -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Allowed actions' {
    It 'rejects a registry key that is not an autostart key' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RegistryValue'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control'; Name = 'x' }) | Should -Match 'autostart keys'
    }
    It 'rejects a file outside the Startup folders' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'File'; Path = 'C:\Windows\System32\drivers\etc\hosts' }) | Should -Match 'Startup folders'
    }
    It 'rejects Windows tasks' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'ScheduledTask'; Path = '\Microsoft\Windows\Defrag\'; Name = 'ScheduledDefrag' }) | Should -Match 'Windows tasks'
    }
    It 'rejects a service that runs a Microsoft program' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Service'; Name = 'EventLog' }) | Should -Match 'Microsoft'
    }
    It 'rejects an unknown kind' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Delete'; Path = 'C:\x' }) | Should -Match 'Unknown kind'
    }
    It 'allows a Run entry' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'x' }) | Should -BeNullOrEmpty
    }
    It 'rejects a path that leaves the Startup folder with ".."' {
        $p = Join-Path $TestDrive 'u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\..\Startup\x.lnk'
        Test-StartupFilePath $p | Should -Match 'Startup folders'
    }
    It 'as administrator allows only the real Startup folders' {
        $was = $script:IsAdmin; $lax = $script:StartupFileAdminPattern
        try {
            $script:IsAdmin = $true; $script:StartupFileAdminPattern = $script:DefaultStartupFileAdminPattern
            Test-StartupFilePath (Join-Path $TestDrive 'fake\Start Menu\Programs\Startup\x.lnk') | Should -Match 'Startup folders'
            Test-StartupFilePath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\missing-checkbackdoor.lnk' | Should -BeNullOrEmpty
        } finally { $script:IsAdmin = $was; $script:StartupFileAdminPattern = $lax }
    }
}

Describe 'Antivirus services' {
    BeforeAll {
        $script:AvDir = Join-Path $TestDrive 'Program Files\AV Vendor'
        New-Item -ItemType Directory -Path (Join-Path $script:AvDir 'Engine') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:AvDir 'Engine\av.exe') -Value 'x'
        Set-Content -LiteralPath (Join-Path $script:AvDir 'Engine\avsvc.exe') -Value 'x'
        Mock Get-AntivirusProducts { @([pscustomobject]@{ displayName = 'Test Antivirus'; pathToSignedProductExe = (Join-Path $script:AvDir 'Engine\av.exe'); pathToSignedReportingExe = 'windowsdefender://' }) }
    }
    It 'recognizes a file in the folder of the registered antivirus' {
        Get-OwningAntivirus (Join-Path $script:AvDir 'Engine\avsvc.exe') | Should -Be 'Test Antivirus'
    }
    It 'does not attribute a file elsewhere to the antivirus' {
        Get-OwningAntivirus (Join-Path $TestDrive 'other\service.exe') | Should -BeNullOrEmpty
    }
}

Describe 'Trusted backups for the administrator' {
    It 'rejects a backup outside the protected folder' {
        $f = Join-Path $script:Backups 'fake.json'
        New-Item -ItemType Directory -Path $script:Backups -Force | Out-Null
        Set-Content -LiteralPath $f -Value '{}'
        Test-TrustedBackupFile $f | Should -Match 'any program can change'
    }
    It 'rejects a backup in a subfolder of the protected one' {
        Test-TrustedBackupFile (Join-Path $script:ProtectedBackupDir 'sub\x.json') | Should -Match 'any program can change'
    }
    It 'rejects a file in the protected folder that is not owned by an administrator' -Skip:$script:IsAdmin {
        New-Item -ItemType Directory -Path $script:ProtectedBackupDir -Force | Out-Null
        $f = Join-Path $script:ProtectedBackupDir 'left-by-others.json'
        Set-Content -LiteralPath $f -Value '{}'
        Test-TrustedBackupFile $f | Should -Match 'not written by an administrator'
    }
    It 'as administrator saves to the protected folder and undoes from there' -Skip:(-not $script:IsAdmin) {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Protected' -Value 'C:\x.exe' -Force | Out-Null
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Protected' }) -BackupDir $script:Backups
        Split-Path -Parent $done.BackupFile | Should -Be $script:ProtectedBackupDir
        Test-TrustedBackupFile $done.BackupFile | Should -BeNullOrEmpty
        (Get-Acl -LiteralPath $script:ProtectedBackupDir).AreAccessRulesProtected | Should -BeTrue
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        (Get-Item -LiteralPath $script:TestKey).GetValue('Protected') | Should -Be 'C:\x.exe'
    }
}

Describe 'Registry startup entry' {
    BeforeEach {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Updater' -PropertyType ExpandString -Value '"%APPDATA%\upd\upd.exe" -s' -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'List' -PropertyType MultiString -Value @('a', 'b') -Force | Out-Null
    }
    It 'removes the entry, saves the backup and puts it back identical with Undo' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Updater' }) -BackupDir $script:Backups
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Not -Contain 'Updater'
        Test-Path -LiteralPath $done.BackupFile | Should -BeTrue

        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        $k = Get-Item -LiteralPath $script:TestKey
        $k.GetValueKind('Updater') | Should -Be 'ExpandString'
        $k.GetValue('Updater', $null, 'DoNotExpandEnvironmentNames') | Should -Be '"%APPDATA%\upd\upd.exe" -s'
    }
    It 'keeps the type of a multi-line value' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'List' }) -BackupDir $script:Backups
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        $k = Get-Item -LiteralPath $script:TestKey
        $k.GetValueKind('List') | Should -Be 'MultiString'
        @($k.GetValue('List')) | Should -Be @('a', 'b')
    }
    It 'does not undo twice' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Updater' }) -BackupDir $script:Backups
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*already been undone*'
    }
    It 'leaves no backup if the entry does not exist' {
        $before = @(Get-ChildItem -LiteralPath $script:Backups -ErrorAction SilentlyContinue).Count
        { Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Nonexistent' }) -BackupDir $script:Backups } | Should -Throw
        @(Get-ChildItem -LiteralPath $script:Backups -ErrorAction SilentlyContinue).Count | Should -Be $before
    }
}

Describe 'File in the Startup folder' {
    BeforeAll {
        $script:Startup = Join-Path $TestDrive 'User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        New-Item -ItemType Directory -Path $script:Startup -Force | Out-Null
    }
    It 'moves the file to the backups, without deleting it, and puts it back' {
        $f = Join-Path $script:Startup 'update.vbs'
        Set-Content -LiteralPath $f -Value 'test content'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Test-Path -LiteralPath $f | Should -BeFalse
        Get-Content -LiteralPath $done.Backup.Before.MovedTo | Should -Be 'test content'

        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath $f | Should -Be 'test content'
    }
    It 'does not overwrite a file with the same name that appeared in the meantime' {
        $f = Join-Path $script:Startup 'double.lnk'
        Set-Content -LiteralPath $f -Value 'first'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Set-Content -LiteralPath $f -Value 'second'
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*same name*'
        Get-Content -LiteralPath $f | Should -Be 'second'
    }
    It 'does not put back a file changed inside the backups' {
        $f = Join-Path $script:Startup 'tampered.vbs'
        Set-Content -LiteralPath $f -Value 'original'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Set-Content -LiteralPath $done.Backup.Before.MovedTo -Value 'replaced'
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*was changed*'
        Test-Path -LiteralPath $f | Should -BeFalse
    }
    It 'ignores the path written in the backup and takes back only the file next to it' {
        $f = Join-Path $script:Startup 'hijacked.vbs'
        Set-Content -LiteralPath $f -Value 'real'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        $other = Join-Path $TestDrive 'other.vbs'
        Set-Content -LiteralPath $other -Value 'someone else''s'
        $b = Get-Content -LiteralPath $done.BackupFile -Raw | ConvertFrom-Json
        $b.Before.MovedTo = $other; $b.Before.Sha256 = $null
        $b | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $done.BackupFile
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath $f | Should -Be 'real'
        Get-Content -LiteralPath $other | Should -Be 'someone else''s'
    }
}

Describe 'Actions.ps1' -Tag 'E2E' {
    It 'runs Disable and Undo from the command line and writes the result' {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'FromCli' -Value 'C:\x.exe' -Force | Out-Null
        $req = Join-Path $TestDrive 'request.json'
        $res = Join-Path $TestDrive 'result.json'
        (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'FromCli' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        $script = Join-Path $script:ProjectRoot 'Actions.ps1'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        $out = Get-Content -LiteralPath $res -Raw | ConvertFrom-Json
        $out.ok | Should -BeTrue
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Not -Contain 'FromCli'

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -BackupFile $out.backupFile -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        (Get-Item -LiteralPath $script:TestKey).GetValue('FromCli') | Should -Be 'C:\x.exe'
        # As administrator the backup ended up in the real protected folder: do not leave it there
        Remove-Item -LiteralPath $out.backupFile -Force -ErrorAction SilentlyContinue
    }
    It 'rejects a request different from the confirmed one' {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Pinned' -Value 'C:\x.exe' -Force | Out-Null
        $req = Join-Path $TestDrive 'request-pinned.json'
        $res = Join-Path $TestDrive 'result-pinned.json'
        (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Pinned' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        $script = Join-Path $script:ProjectRoot 'Actions.ps1'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -RequestSha256 ('0' * 64) -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 1
        (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).message | Should -Match 'changed after you confirmed it'
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Contain 'Pinned'

        $sha = (Get-FileHash -LiteralPath $req -Algorithm SHA256).Hash
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -RequestSha256 $sha -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        Remove-Item -LiteralPath (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).backupFile -Force -ErrorAction SilentlyContinue
    }
    It 'rejects a request that is not allowed without changing anything' {
        $req = Join-Path $TestDrive 'request-no.json'
        $res = Join-Path $TestDrive 'result-no.json'
        (New-Request @{ Kind = 'File'; Path = 'C:\Windows\win.ini' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:ProjectRoot 'Actions.ps1') -RequestFile $req -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 1
        (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).ok | Should -BeFalse
        Test-Path -LiteralPath 'C:\Windows\win.ini' | Should -BeTrue
    }
}
