# "Disable" and "Undo" actions on a test key in HKCU and on files in TestDrive:
# they do not touch the real startup locations of the PC.

BeforeDiscovery {
    # -Skip is decided while the tests are discovered, before BeforeAll loads the modules:
    # $script:IsAdmin does not exist yet at that point
    $runAsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
    It 'rejects a file in the protected folder that is not owned by an administrator' {
        New-Item -ItemType Directory -Path $script:ProtectedBackupDir -Force | Out-Null
        $f = Join-Path $script:ProtectedBackupDir 'left-by-others.json'
        Set-Content -LiteralPath $f -Value '{}'
        # Owned by the current user, also when the tests run as administrator (where new
        # files would belong to the Administrators group)
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
        Set-ItemSecurity -Path $f -Acl $acl
        Test-TrustedBackupFile $f | Should -Match 'not written by an administrator'
    }
    It 'as administrator saves to the protected folder and undoes from there' -Skip:(-not $runAsAdmin) {
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

Describe 'Suspicious files: quarantine and delete' {
    BeforeAll {
        # The real folders (AppData, ProgramData...) are replaced by a test folder
        $script:DefaultQuarantineRoot = $script:QuarantineRootPattern
        $script:QuarantineRootPattern = '(?i)^' + [regex]::Escape((Join-Path $TestDrive 'q')) + '\\'
        $script:QDir = Join-Path $TestDrive 'q\AppData\Tool'
        New-Item -ItemType Directory -Path $script:QDir -Force | Out-Null
        function New-SuspiciousFile([string]$Name) {
            $f = Join-Path $script:QDir $Name
            Set-Content -LiteralPath $f -Value "content of $Name"
            return $f
        }
    }
    AfterAll { $script:QuarantineRootPattern = $script:DefaultQuarantineRoot }
    It 'quarantines the file and Undo puts it back' {
        $f = New-SuspiciousFile 'tool.exe'
        $sha = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'QuarantineFile'; Path = $f; Sha256 = $sha }) -BackupDir $script:Backups
        Test-Path -LiteralPath $f | Should -BeFalse
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath $f | Should -Be 'content of tool.exe'
    }
    It 'deletes for good a quarantined file, read-only too, with its backup' {
        $f = New-SuspiciousFile 'purge.exe'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'QuarantineFile'; Path = $f }) -BackupDir $script:Backups
        $moved = [IO.Path]::ChangeExtension($done.BackupFile, '.file')
        (Get-Item -LiteralPath $moved).IsReadOnly = $true
        Invoke-RemedyPurge -BackupFile $done.BackupFile | Out-Null
        Test-Path -LiteralPath $moved | Should -BeFalse
        Test-Path -LiteralPath $done.BackupFile | Should -BeFalse
    }
    It 'does not move a file that changed after the scan' {
        $f = New-SuspiciousFile 'changed.exe'
        { Invoke-RemedyDisable -Request (New-Request @{ Kind = 'QuarantineFile'; Path = $f; Sha256 = ('A' * 64) }) -BackupDir $script:Backups } | Should -Throw '*changed after the scan*'
        Test-Path -LiteralPath $f | Should -BeTrue
    }
    It 'deletes the file for good when asked, leaving no backup' {
        $f = New-SuspiciousFile 'gone.exe'
        $req = New-Request @{ Kind = 'QuarantineFile'; Path = $f; Sha256 = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash }
        $req | Add-Member -NotePropertyName Mode -NotePropertyValue 'Delete'
        $done = Invoke-RemedyDisable -Request $req -BackupDir $script:Backups
        Test-Path -LiteralPath $f | Should -BeFalse
        $done.BackupFile | Should -BeNullOrEmpty
    }
    It 'deletes only files' {
        $req = New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'x' }
        $req | Add-Member -NotePropertyName Mode -NotePropertyValue 'Delete'
        { Invoke-RemedyDisable -Request $req -BackupDir $script:Backups } | Should -Throw '*Only files*'
    }
    It 'rejects files outside the checked folders and other extensions' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'QuarantineFile'; Path = 'C:\Windows\System32\notepad.exe' }) | Should -Match 'Only executables'
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'QuarantineFile'; Path = (Join-Path $script:QDir 'notes.txt') }) | Should -Match 'Only executables'
    }
    It 'does not go through a link to another folder' {
        $real = Join-Path $TestDrive 'elsewhere'
        New-Item -ItemType Directory -Path $real -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $real 'a.exe') -Value 'x'
        $link = Join-Path $script:QDir 'link'
        New-Item -ItemType Junction -Path $link -Target $real | Out-Null
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'QuarantineFile'; Path = (Join-Path $link 'a.exe') }) | Should -Match 'link'
    }
}

Describe 'Browser extensions' {
    BeforeAll {
        function New-TestExtension([string]$Name) {
            $dir = Join-Path $TestDrive "ext\$Name"
            New-Item -ItemType Directory -Path (Join-Path $dir '1.0_0') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir '1.0_0\manifest.json') -Value '{ "name": "Test" }'
            return $dir
        }
        function New-ExtRequest([string]$Dir) { New-Request @{ Kind = 'BrowserExtension'; Path = $Dir; Browser = 'Vivaldi'; Exe = 'vivaldi'; Id = 'abc' } }
        Mock Get-Process { $null } -ParameterFilter { $Name -eq 'vivaldi' }
    }
    It 'moves the extension folder away and Undo puts it back' {
        $dir = New-TestExtension 'moved'
        $done = Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups
        Test-Path -LiteralPath $dir | Should -BeFalse
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Test-Path -LiteralPath (Join-Path $dir '1.0_0\manifest.json') | Should -BeTrue
    }
    It 'deletes the extension folder for good when asked' {
        $dir = New-TestExtension 'deleted'
        $req = New-ExtRequest $dir
        $req | Add-Member -NotePropertyName Mode -NotePropertyValue 'Delete'
        (Invoke-RemedyDisable -Request $req -BackupDir $script:Backups).BackupFile | Should -BeNullOrEmpty
        Test-Path -LiteralPath $dir | Should -BeFalse
    }
    It 'does not touch a folder that is not an extension' {
        $dir = Join-Path $TestDrive 'ext\notext'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        { Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups } | Should -Throw '*manifest.json*'
        Test-Path -LiteralPath $dir | Should -BeTrue
    }
    It 'refuses system folders and whole user profiles' {
        Test-ExtensionPath 'C:\Windows\System32\drivers' | Should -Match 'Only the folder'
        Test-ExtensionPath 'C:\Users\someone' | Should -Match 'Only the folder'
        Test-ExtensionPath 'C:\Program Files\Browser\ext' | Should -Match 'Only the folder'
    }
    It 'deletes for good an extension in quarantine, with its backup' {
        $dir = New-TestExtension 'purged'
        $done = Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups
        $moved = [IO.Path]::ChangeExtension($done.BackupFile, '.ext')
        Test-Path -LiteralPath $moved | Should -BeTrue
        Invoke-RemedyPurge -BackupFile $done.BackupFile | Out-Null
        Test-Path -LiteralPath $moved | Should -BeFalse
        Test-Path -LiteralPath $done.BackupFile | Should -BeFalse
    }
    It 'does not follow a link inside the extension while deleting it' {
        $outside = Join-Path $TestDrive 'outside'
        New-Item -ItemType Directory -Path $outside -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $outside 'precious.txt') -Value 'keep me'
        $dir = New-TestExtension 'withlink'
        New-Item -ItemType Junction -Path (Join-Path $dir 'link') -Target $outside | Out-Null
        $done = Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups
        Invoke-RemedyPurge -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath (Join-Path $outside 'precious.txt') | Should -Be 'keep me'
    }
    It 'has nothing to delete after Restore' {
        $dir = New-TestExtension 'restored'
        $done = Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        { Invoke-RemedyPurge -BackupFile $done.BackupFile } | Should -Throw '*already put back*'
        Test-Path -LiteralPath (Join-Path $dir '1.0_0\manifest.json') | Should -BeTrue
    }
    It 'asks to close the browser first' {
        Mock Get-Process { [pscustomobject]@{ Name = 'vivaldi' } } -ParameterFilter { $Name -eq 'vivaldi' }
        $dir = New-TestExtension 'open'
        { Invoke-RemedyDisable -Request (New-ExtRequest $dir) -BackupDir $script:Backups } | Should -Throw '*Close Vivaldi first*'
        Test-Path -LiteralPath $dir | Should -BeTrue
    }
}

Describe 'Processes, exclusions, accounts and certificates' {
    It 'does not end a Windows program or CheckBackdoor itself' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Process'; ProcessId = 1234; Path = "$env:SystemRoot\System32\notepad.exe" }) | Should -Match 'Windows program'
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Process'; ProcessId = $PID; Path = 'C:\x.exe' }) | Should -Match 'Invalid process'
    }
    It 'does not end a process whose number now belongs to another program' {
        { Stop-RemedyProcess ([pscustomobject]@{ Kind = 'Process'; ProcessId = $PID; Path = 'C:\other\x.exe' }) } | Should -Throw '*another program*'
    }
    It 'accepts only known kinds of Defender exclusion' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'DefenderExclusion'; Type = 'Path'; Value = 'C:\Games' }) | Should -BeNullOrEmpty
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'DefenderExclusion'; Type = 'Registry'; Value = 'x' }) | Should -Match 'Unknown kind of exclusion'
    }
    It 'never disables the account in use, nor groups' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Account'; Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }) | Should -Match 'account you are using'
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Account'; Sid = 'S-1-5-32-544' }) | Should -Match 'local accounts'
    }
    It 'checks the thumbprint and the store of a certificate' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RootCertificate'; Store = 'Machine'; Thumbprint = '12AB' }) | Should -Match 'Invalid certificate'
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RootCertificate'; Store = 'Other'; Thumbprint = ('A' * 40) }) | Should -Match 'Unknown certificate store'
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RootCertificate'; Store = 'Machine'; Thumbprint = ('A' * 40) }) | Should -BeNullOrEmpty
    }
}

Describe 'Root certificate of a user' {
    BeforeAll {
        # A test key instead of the real root store of the user
        Mock Get-UserRootKey { "HKCU:\Software\CheckBackdoorTest\Certs\$Thumbprint" }
    }
    It 'removes it keeping its content and puts it back with Undo' {
        $tp = 'AB' * 20
        $key = "HKCU:\Software\CheckBackdoorTest\Certs\$tp"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -LiteralPath $key -Name Blob -PropertyType Binary -Value ([byte[]](1, 2, 3, 4)) -Force | Out-Null
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RootCertificate'; Store = 'User'; Sid = $sid; Thumbprint = $tp }) -BackupDir $script:Backups
        Test-Path -LiteralPath $key | Should -BeFalse
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        @([byte[]](Get-ItemPropertyValue -LiteralPath $key -Name Blob)) | Should -Be @(1, 2, 3, 4)
    }
}

Describe 'Actions.ps1' -Tag 'E2E' {
    It 'carries out a list of requests ("Fix all") one by one and reports each' {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Batch' -Value 'C:\x.exe' -Force | Out-Null
        $req = Join-Path $TestDrive 'request-batch.json'
        $res = Join-Path $TestDrive 'result-batch.json'
        $list = @((New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Batch' } 'One'), (New-Request @{ Kind = 'File'; Path = 'C:\Windows\win.ini' } 'Two'))
        ConvertTo-Json -InputObject $list -Depth 5 | Set-Content -LiteralPath $req
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:ProjectRoot 'Actions.ps1') -RequestFile $req -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        $out = Get-Content -LiteralPath $res -Raw | ConvertFrom-Json
        @($out.items) | Should -HaveCount 2
        $out.items[0].ok | Should -BeTrue
        $out.items[1].ok | Should -BeFalse
        $out.message | Should -Be 'Fixed 1 of 2.'
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Not -Contain 'Batch'
        Test-Path -LiteralPath 'C:\Windows\win.ini' | Should -BeTrue
        Remove-Item -LiteralPath $out.items[0].backupFile -Force -ErrorAction SilentlyContinue
    }
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
