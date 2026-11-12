# Azioni "Disattiva" e "Annulla" su una chiave di prova in HKCU e su file in TestDrive:
# non toccano i punti di avvio veri del PC.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    . (Get-ModuleScript Common)
    . (Get-ModuleScript Remedy)
    $script:TestKey = 'HKCU:\Software\CheckBackdoorTest\Run'
    $script:Backups = Join-Path $TestDrive 'backup'
    # Eseguiti come amministratore (GitHub Actions) i backup vanno nella cartella protetta:
    # nei test e' una cartella di prova, e i file di avvio di prova stanno in TestDrive
    $script:ProtectedBackupDir = Join-Path $TestDrive 'protetti\backup'
    $script:DefaultStartupFileAdminPattern = $script:StartupFileAdminPattern
    $script:StartupFileAdminPattern = $script:StartupFilePattern
    function New-Request($Remedy, [string]$Title = 'Elemento di prova') {
        [pscustomobject]@{ FindingId = '0123456789abcdef'; Title = $Title; Remedy = [pscustomobject]$Remedy }
    }
}

AfterAll {
    Remove-Item -LiteralPath 'HKCU:\Software\CheckBackdoorTest' -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Azioni ammesse' {
    It 'rifiuta una chiave del registro che non e'' di avvio' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RegistryValue'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control'; Name = 'x' }) | Should -Match 'chiavi di avvio'
    }
    It 'rifiuta un file fuori dalle cartelle Esecuzione automatica' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'File'; Path = 'C:\Windows\System32\drivers\etc\hosts' }) | Should -Match 'Esecuzione automatica'
    }
    It 'rifiuta le attivita'' di Windows' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'ScheduledTask'; Path = '\Microsoft\Windows\Defrag\'; Name = 'ScheduledDefrag' }) | Should -Match 'di Windows'
    }
    It 'rifiuta un servizio che esegue un programma di Microsoft' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Service'; Name = 'EventLog' }) | Should -Match 'Microsoft'
    }
    It 'rifiuta un tipo sconosciuto' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'Cancella'; Path = 'C:\x' }) | Should -Match 'sconosciuto'
    }
    It 'ammette una voce Run' {
        Test-RemedyAllowed ([pscustomobject]@{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'x' }) | Should -BeNullOrEmpty
    }
    It 'rifiuta un percorso che esce dalla cartella di avvio con ".."' {
        $p = Join-Path $TestDrive 'u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\..\Startup\x.lnk'
        Test-StartupFilePath $p | Should -Match 'Esecuzione automatica'
    }
    It 'come amministratore ammette solo le vere cartelle di avvio' {
        $was = $script:IsAdmin; $lax = $script:StartupFileAdminPattern
        try {
            $script:IsAdmin = $true; $script:StartupFileAdminPattern = $script:DefaultStartupFileAdminPattern
            Test-StartupFilePath (Join-Path $TestDrive 'finta\Start Menu\Programs\Startup\x.lnk') | Should -Match 'Esecuzione automatica'
            Test-StartupFilePath 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\inesistente-checkbackdoor.lnk' | Should -BeNullOrEmpty
        } finally { $script:IsAdmin = $was; $script:StartupFileAdminPattern = $lax }
    }
}

Describe 'Servizi dell''antivirus' {
    BeforeAll {
        $script:AvDir = Join-Path $TestDrive 'Program Files\Produttore AV'
        New-Item -ItemType Directory -Path (Join-Path $script:AvDir 'Motore') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:AvDir 'Motore\av.exe') -Value 'x'
        Set-Content -LiteralPath (Join-Path $script:AvDir 'Motore\avsvc.exe') -Value 'x'
        Mock Get-AntivirusProducts { @([pscustomobject]@{ displayName = 'Antivirus di prova'; pathToSignedProductExe = (Join-Path $script:AvDir 'Motore\av.exe'); pathToSignedReportingExe = 'windowsdefender://' }) }
    }
    It 'riconosce un file nella cartella dell''antivirus registrato' {
        Get-OwningAntivirus (Join-Path $script:AvDir 'Motore\avsvc.exe') | Should -Be 'Antivirus di prova'
    }
    It 'non considera dell''antivirus un file altrove' {
        Get-OwningAntivirus (Join-Path $TestDrive 'altro\servizio.exe') | Should -BeNullOrEmpty
    }
}

Describe 'Backup affidabili per l''amministratore' {
    It 'rifiuta un backup fuori dalla cartella protetta' {
        $f = Join-Path $script:Backups 'finto.json'
        New-Item -ItemType Directory -Path $script:Backups -Force | Out-Null
        Set-Content -LiteralPath $f -Value '{}'
        Test-TrustedBackupFile $f | Should -Match 'qualsiasi programma'
    }
    It 'rifiuta un backup in una sottocartella di quella protetta' {
        Test-TrustedBackupFile (Join-Path $script:ProtectedBackupDir 'sotto\x.json') | Should -Match 'qualsiasi programma'
    }
    It 'rifiuta un file della cartella protetta che non e'' di un amministratore' -Skip:$script:IsAdmin {
        New-Item -ItemType Directory -Path $script:ProtectedBackupDir -Force | Out-Null
        $f = Join-Path $script:ProtectedBackupDir 'lasciato-da-altri.json'
        Set-Content -LiteralPath $f -Value '{}'
        Test-TrustedBackupFile $f | Should -Match 'non e'' stato scritto da un amministratore'
    }
    It 'come amministratore salva nella cartella protetta e annulla da li''' -Skip:(-not $script:IsAdmin) {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Protetto' -Value 'C:\x.exe' -Force | Out-Null
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Protetto' }) -BackupDir $script:Backups
        Split-Path -Parent $done.BackupFile | Should -Be $script:ProtectedBackupDir
        Test-TrustedBackupFile $done.BackupFile | Should -BeNullOrEmpty
        (Get-Acl -LiteralPath $script:ProtectedBackupDir).AreAccessRulesProtected | Should -BeTrue
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        (Get-Item -LiteralPath $script:TestKey).GetValue('Protetto') | Should -Be 'C:\x.exe'
    }
}

Describe 'Voce di avvio nel registro' {
    BeforeEach {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Aggiornatore' -PropertyType ExpandString -Value '"%APPDATA%\upd\upd.exe" -s' -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Lista' -PropertyType MultiString -Value @('a', 'b') -Force | Out-Null
    }
    It 'toglie la voce, salva il backup e la rimette identica con Annulla' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Aggiornatore' }) -BackupDir $script:Backups
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Not -Contain 'Aggiornatore'
        Test-Path -LiteralPath $done.BackupFile | Should -BeTrue

        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        $k = Get-Item -LiteralPath $script:TestKey
        $k.GetValueKind('Aggiornatore') | Should -Be 'ExpandString'
        $k.GetValue('Aggiornatore', $null, 'DoNotExpandEnvironmentNames') | Should -Be '"%APPDATA%\upd\upd.exe" -s'
    }
    It 'conserva il tipo di un valore con piu'' righe' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Lista' }) -BackupDir $script:Backups
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        $k = Get-Item -LiteralPath $script:TestKey
        $k.GetValueKind('Lista') | Should -Be 'MultiString'
        @($k.GetValue('Lista')) | Should -Be @('a', 'b')
    }
    It 'non annulla due volte' {
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Aggiornatore' }) -BackupDir $script:Backups
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*gia''*annullata*'
    }
    It 'non lascia un backup se la voce non esiste' {
        $before = @(Get-ChildItem -LiteralPath $script:Backups -ErrorAction SilentlyContinue).Count
        { Invoke-RemedyDisable -Request (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Inesistente' }) -BackupDir $script:Backups } | Should -Throw
        @(Get-ChildItem -LiteralPath $script:Backups -ErrorAction SilentlyContinue).Count | Should -Be $before
    }
}

Describe 'File nella cartella Esecuzione automatica' {
    BeforeAll {
        $script:Startup = Join-Path $TestDrive 'Utente\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        New-Item -ItemType Directory -Path $script:Startup -Force | Out-Null
    }
    It 'sposta il file nei backup, senza cancellarlo, e lo rimette al suo posto' {
        $f = Join-Path $script:Startup 'aggiorna.vbs'
        Set-Content -LiteralPath $f -Value 'contenuto di prova'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Test-Path -LiteralPath $f | Should -BeFalse
        Get-Content -LiteralPath $done.Backup.Before.MovedTo | Should -Be 'contenuto di prova'

        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath $f | Should -Be 'contenuto di prova'
    }
    It 'non sovrascrive un file comparso nel frattempo con lo stesso nome' {
        $f = Join-Path $script:Startup 'doppio.lnk'
        Set-Content -LiteralPath $f -Value 'primo'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Set-Content -LiteralPath $f -Value 'secondo'
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*stesso nome*'
        Get-Content -LiteralPath $f | Should -Be 'secondo'
    }
    It 'non rimette al suo posto un file modificato dentro i backup' {
        $f = Join-Path $script:Startup 'ritoccato.vbs'
        Set-Content -LiteralPath $f -Value 'originale'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        Set-Content -LiteralPath $done.Backup.Before.MovedTo -Value 'sostituito'
        { Invoke-RemedyUndo -BackupFile $done.BackupFile } | Should -Throw '*modificato*'
        Test-Path -LiteralPath $f | Should -BeFalse
    }
    It 'ignora il percorso scritto nel backup e riprende solo il file accanto' {
        $f = Join-Path $script:Startup 'dirottato.vbs'
        Set-Content -LiteralPath $f -Value 'vero'
        $done = Invoke-RemedyDisable -Request (New-Request @{ Kind = 'File'; Path = $f }) -BackupDir $script:Backups
        $altro = Join-Path $TestDrive 'altro.vbs'
        Set-Content -LiteralPath $altro -Value 'di un altro'
        $b = Get-Content -LiteralPath $done.BackupFile -Raw | ConvertFrom-Json
        $b.Before.MovedTo = $altro; $b.Before.Sha256 = $null
        $b | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $done.BackupFile
        Invoke-RemedyUndo -BackupFile $done.BackupFile | Out-Null
        Get-Content -LiteralPath $f | Should -Be 'vero'
        Get-Content -LiteralPath $altro | Should -Be 'di un altro'
    }
}

Describe 'Azioni.ps1' -Tag 'E2E' {
    It 'esegue Disattiva e Annulla da riga di comando e scrive l''esito' {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'DaRiga' -Value 'C:\x.exe' -Force | Out-Null
        $req = Join-Path $TestDrive 'richiesta.json'
        $res = Join-Path $TestDrive 'esito.json'
        (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'DaRiga' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        $script = Join-Path $script:ProjectRoot 'Actions.ps1'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        $out = Get-Content -LiteralPath $res -Raw | ConvertFrom-Json
        $out.ok | Should -BeTrue
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Not -Contain 'DaRiga'

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -BackupFile $out.backupFile -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        (Get-Item -LiteralPath $script:TestKey).GetValue('DaRiga') | Should -Be 'C:\x.exe'
        # Come amministratore il backup e' finito nella vera cartella protetta: non va lasciato li'
        Remove-Item -LiteralPath $out.backupFile -Force -ErrorAction SilentlyContinue
    }
    It 'rifiuta una richiesta diversa da quella confermata' {
        New-Item -Path $script:TestKey -Force | Out-Null
        New-ItemProperty -LiteralPath $script:TestKey -Name 'Vincolata' -Value 'C:\x.exe' -Force | Out-Null
        $req = Join-Path $TestDrive 'richiesta-vincolata.json'
        $res = Join-Path $TestDrive 'esito-vincolato.json'
        (New-Request @{ Kind = 'RegistryValue'; Key = $script:TestKey; Name = 'Vincolata' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        $script = Join-Path $script:ProjectRoot 'Actions.ps1'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -RequestSha256 ('0' * 64) -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 1
        (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).message | Should -Match 'cambiata dopo la tua conferma'
        (Get-Item -LiteralPath $script:TestKey).GetValueNames() | Should -Contain 'Vincolata'

        $sha = (Get-FileHash -LiteralPath $req -Algorithm SHA256).Hash
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -RequestFile $req -RequestSha256 $sha -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 0
        Remove-Item -LiteralPath (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).backupFile -Force -ErrorAction SilentlyContinue
    }
    It 'rifiuta una richiesta non ammessa senza modificare nulla' {
        $req = Join-Path $TestDrive 'richiesta-no.json'
        $res = Join-Path $TestDrive 'esito-no.json'
        (New-Request @{ Kind = 'File'; Path = 'C:\Windows\win.ini' }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $req
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:ProjectRoot 'Actions.ps1') -RequestFile $req -BackupDir $script:Backups -ResultFile $res
        $LASTEXITCODE | Should -Be 1
        (Get-Content -LiteralPath $res -Raw | ConvertFrom-Json).ok | Should -BeFalse
        Test-Path -LiteralPath 'C:\Windows\win.ini' | Should -BeTrue
    }
}
