# Azioni sulle segnalazioni: disattivare un punto di avvio salvando prima tutto cio' che
# serve per tornare indietro, e annullare. Mai cancellazioni: i file vengono spostati
# nella cartella dei backup, le attivita' disattivate, i servizi messi su "Disabilitato".
# La usa Azioni.ps1, che l'app lancia (come amministratore quando serve).

$script:BackupSchema = 'checkbackdoor.backup/1'
# Solo le chiavi di avvio: l'azione non deve poter cancellare valori qualsiasi del registro
$script:RunKeyPattern = '(?i)^(HKLM|HKCU|HKU):\\.+\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)$'
$script:StartupFilePattern = '(?i)\\Start Menu\\Programs\\Startup\\[^\\]+$'

function Initialize-HkuDrive {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global | Out-Null
    }
}

# Motivo per cui l'azione non e' ammessa, o $null se si puo' fare.
# Il report da cui arriva la richiesta e' un file dell'utente: non ci si fida del suo
# contenuto per toccare parti di Windows.
function Test-RemedyAllowed {
    param($Remedy)
    if (-not $Remedy) { return "Nessuna azione disponibile per questo elemento." }
    switch ("$($Remedy.Kind)") {
        'RegistryValue' {
            if ("$($Remedy.Key)" -notmatch $script:RunKeyPattern) { return "Si possono disattivare solo voci delle chiavi di avvio (Run, RunOnce)." }
            if (-not $Remedy.Name -or $Remedy.Name -eq '(Predefinito)') { return "Voce del registro senza nome." }
            return $null
        }
        'File' {
            if ("$($Remedy.Path)" -notmatch $script:StartupFilePattern) { return "Si possono spostare solo file delle cartelle Esecuzione automatica." }
            return $null
        }
        'ScheduledTask' {
            if ("$($Remedy.Path)" -like '\Microsoft\Windows\*') { return "Le attivita' di Windows non si disattivano da qui." }
            if (-not $Remedy.Name) { return "Attivita' senza nome." }
            return $null
        }
        'Service' {
            if ("$($Remedy.Name)" -notmatch '^[\w .\-{}$]+$') { return "Nome del servizio non valido." }
            $img = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($Remedy.Name)" 'ImagePath'
            $target = Resolve-CommandPath $img
            if ($target -and (Get-FileInfo $target).IsMicrosoft) { return "Il servizio esegue un programma di Microsoft: disattivarlo potrebbe danneggiare Windows." }
            return $null
        }
    }
    return "Tipo di azione sconosciuto: $($Remedy.Kind)"
}

function Save-Backup {
    param($Backup, [string]$Path)
    [IO.File]::WriteAllText($Path, ($Backup | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}

function Invoke-RemedyDisable {
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)][string]$BackupDir)
    $r = $Request.Remedy
    $why = Test-RemedyAllowed $r
    if ($why) { throw $why }
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    $id = (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $file = Join-Path $BackupDir "$id.json"
    $backup = [ordered]@{
        Schema = $script:BackupSchema; Id = $id; Date = (Get-Date).ToString('s'); Title = "$($Request.Title)"
        FindingId = "$($Request.FindingId)"; Remedy = $r; Before = $null; Undone = $false; UndoneDate = $null
    }
    # Prima si salva il backup, poi si modifica il sistema; se la modifica fallisce il
    # backup viene tolto, cosi' non resta un "Annulla" che non annulla nulla.
    switch ("$($r.Kind)") {
        'RegistryValue' {
            Initialize-HkuDrive
            $key = Get-Item -LiteralPath $r.Key -ErrorAction Stop
            if ($key.GetValueNames() -notcontains $r.Name) { throw "La voce '$($r.Name)' non esiste piu'." }
            $kind = $key.GetValueKind($r.Name)
            $data = $key.GetValue($r.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $backup.Before = [ordered]@{ Type = "$kind"; Data = $data }
            Save-Backup $backup $file
            try { Remove-ItemProperty -LiteralPath $r.Key -Name $r.Name -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'File' {
            if (-not (Test-Path -LiteralPath $r.Path -PathType Leaf)) { throw "Il file non esiste piu'." }
            $dest = Join-Path $BackupDir "$id.file"
            $backup.Before = [ordered]@{ MovedTo = $dest }
            Save-Backup $backup $file
            try { Move-Item -LiteralPath $r.Path -Destination $dest -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'ScheduledTask' {
            $t = Get-ScheduledTask -TaskPath $r.Path -TaskName $r.Name -ErrorAction Stop
            $backup.Before = [ordered]@{ State = "$($t.State)" }
            Save-Backup $backup $file
            try { Disable-ScheduledTask -TaskPath $r.Path -TaskName $r.Name -ErrorAction Stop | Out-Null }
            catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'Service' {
            $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$($r.Name)"
            $start = (Get-ItemProperty -LiteralPath $k -Name Start -ErrorAction Stop).Start
            $backup.Before = [ordered]@{ Start = [int]$start }
            Save-Backup $backup $file
            try { Set-ItemProperty -LiteralPath $k -Name Start -Value 4 -Type DWord -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $file -Force; throw }
            Stop-Service -Name $r.Name -Force -ErrorAction SilentlyContinue
        }
    }
    return [pscustomobject]@{ BackupFile = $file; Backup = $backup }
}

function Invoke-RemedyUndo {
    param([Parameter(Mandatory)][string]$BackupFile)
    $b = [IO.File]::ReadAllText($BackupFile) | ConvertFrom-Json
    if ($b.Schema -ne $script:BackupSchema) { throw "Backup in un formato sconosciuto." }
    if ($b.Undone) { throw "Questa modifica e' gia' stata annullata." }
    $r = $b.Remedy
    switch ("$($r.Kind)") {
        'RegistryValue' {
            Initialize-HkuDrive
            if ("$($r.Key)" -notmatch $script:RunKeyPattern) { throw "Chiave non ammessa." }
            if (-not (Test-Path -LiteralPath $r.Key)) { New-Item -Path $r.Key -Force | Out-Null }
            $type = "$($b.Before.Type)"
            $data = $b.Before.Data
            switch ($type) {
                'MultiString' { $data = [string[]]@($data) }
                'Binary' { $data = [byte[]]@($data) }
                'DWord' { $data = [int]$data }
                'QWord' { $data = [long]$data }
                default { $data = [string]$data }
            }
            New-ItemProperty -LiteralPath $r.Key -Name $r.Name -PropertyType $type -Value $data -Force -ErrorAction Stop | Out-Null
        }
        'File' {
            if ("$($r.Path)" -notmatch $script:StartupFilePattern) { throw "Percorso non ammesso." }
            if (Test-Path -LiteralPath $r.Path) { throw "Esiste gia' un file con lo stesso nome: $($r.Path)" }
            Move-Item -LiteralPath $b.Before.MovedTo -Destination $r.Path -ErrorAction Stop
        }
        'ScheduledTask' {
            if ("$($b.Before.State)" -ne 'Disabled') { Enable-ScheduledTask -TaskPath $r.Path -TaskName $r.Name -ErrorAction Stop | Out-Null }
        }
        'Service' {
            Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($r.Name)" -Name Start -Value ([int]$b.Before.Start) -Type DWord -ErrorAction Stop
        }
        default { throw "Tipo di azione sconosciuto." }
    }
    $b.Undone = $true
    $b.UndoneDate = (Get-Date).ToString('s')
    Save-Backup $b $BackupFile
    return $b
}
