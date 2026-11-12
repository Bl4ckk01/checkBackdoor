# Azioni sulle segnalazioni: disattivare un punto di avvio salvando prima tutto cio' che
# serve per tornare indietro, e annullare. Mai cancellazioni: i file vengono spostati
# nella cartella dei backup, le attivita' disattivate, i servizi messi su "Disabilitato".
# La usa Actions.ps1, che l'app lancia (come amministratore quando serve).
#
# Di chi ci si fida. La richiesta e i backup arrivano da file: quelli nel profilo
# dell'utente li puo' riscrivere qualsiasi programma che gira con il suo account, cioe'
# proprio il malware che si sta cercando. Per questo:
# - senza privilegi si lavora con quei file, e Windows impedisce da solo di toccare cio'
#   che non e' dell'utente;
# - con i privilegi di amministratore i backup si scrivono e si leggono solo in una
#   cartella che gli utenti non possono modificare, e ogni dato viene ricontrollato.

$script:BackupSchema = 'checkbackdoor.backup/1'
# Solo le chiavi di avvio: l'azione non deve poter cancellare valori qualsiasi del registro
$script:RunKeyPattern = '(?i)^(HKLM|HKCU|HKU):\\.+\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)$'
$script:StartupFilePattern = '(?i)\\Start Menu\\Programs\\Startup\\[^\\]+$'
# Come amministratore non basta che il percorso "finisca" come una cartella di avvio: deve
# essere una di quelle vere (di tutti gli utenti o del profilo di un utente)
$script:StartupFileAdminPattern = '(?i)^[A-Z]:\\(ProgramData|Users\\[^\\]+\\AppData\\Roaming)\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\[^\\]+$'
$script:ServiceNamePattern = '^[\w .\-{}$]+$'

$script:AdminsSid = 'S-1-5-32-544'
$script:SystemSid = 'S-1-5-18'
$script:UsersSid = 'S-1-5-32-545'
$script:ProtectedBackupDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CheckBackdoor\backup'

function Initialize-HkuDrive {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global | Out-Null
    }
}

function Test-PathInside {
    param([string]$Path, [string]$Dir)
    if (-not $Path -or -not $Dir) { return $false }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($Dir).TrimEnd('\') + '\'
    return $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)
}

function Test-ReparsePoint {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return [bool]($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))
}

# Toglie i permessi propri di un file o di una cartella, lasciando solo quelli ereditati
# dalla cartella che lo contiene; con -Owner ne cambia anche il proprietario.
function Reset-ItemAcl {
    param([Parameter(Mandatory)][string]$Path, [string]$Owner)
    $acl = if (Test-Path -LiteralPath $Path -PathType Container) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    if ($Owner) { $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($Owner))) }
    $acl.SetAccessRuleProtection($false, $false)
    Set-ItemSecurity -Path $Path -Acl $acl
}

# Non Set-Acl: scrive anche la parte di controllo (SACL), che richiede un privilegio in piu'
# e fallisce perfino per un amministratore. Il metodo di .NET scrive solo cio' che e' cambiato.
function Set-ItemSecurity {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Acl)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSObject.Methods['SetAccessControl']) { $item.SetAccessControl($Acl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl($item, $Acl) }
}

# Cartella dei backup fatti come amministratore: la possono scrivere solo amministratori
# e SYSTEM. ProgramData lascia creare cartelle a chiunque, quindi i permessi si impostano
# ogni volta (anche su una cartella che esisteva gia') e non ci si fida di cio' che contiene:
# vedi Test-TrustedBackupFile.
function Initialize-ProtectedBackupDir {
    $dir = $script:ProtectedBackupDir
    $parent = Split-Path -Parent $dir
    foreach ($d in $parent, $dir) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
        if (Test-ReparsePoint $d) { throw "La cartella dei backup protetti e' un collegamento a un'altra cartella: $d. Eliminala e riprova." }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:AdminsSid)))
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @(@($script:AdminsSid, 'FullControl'), @($script:SystemSid, 'FullControl'), @($script:UsersSid, 'ReadAndExecute'))) {
            $sid = New-Object Security.Principal.SecurityIdentifier($rule[0])
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        }
        Set-ItemSecurity -Path $d -Acl $acl
    }
    return $dir
}

# Motivo per cui un backup non puo' essere annullato con i privilegi di amministratore, o
# $null se e' affidabile: deve stare nella cartella protetta ed essere stato scritto da un
# amministratore (un file lasciato li' da altri prima che la cartella fosse protetta ha un
# altro proprietario).
function Test-TrustedBackupFile {
    param([string]$BackupFile)
    $manual = "Il contenuto da ripristinare e' scritto nel file $BackupFile`: se lo riconosci, ripristinalo a mano."
    if (-not (Test-PathInside $BackupFile $script:ProtectedBackupDir) -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BackupFile)).TrimEnd('\') -ne [IO.Path]::GetFullPath($script:ProtectedBackupDir).TrimEnd('\')) {
        return "Questo backup sta in una cartella che qualsiasi programma puo' modificare: per sicurezza non viene ripristinato con i privilegi di amministratore. Se l'avevi creato senza quei privilegi, riapri CheckBackdoor normalmente (non come amministratore). $manual"
    }
    if (Test-ReparsePoint $BackupFile) { return "Il backup e' un collegamento a un altro file. $manual" }
    $owner = $null
    try { $owner = (Get-Acl -LiteralPath $BackupFile -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($owner -notin $script:AdminsSid, $script:SystemSid) {
        return "Questo backup non e' stato scritto da un amministratore: per sicurezza non viene ripristinato. $manual"
    }
    return $null
}

# Antivirus registrati nel Centro sicurezza di Windows
function Get-AntivirusProducts {
    @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
}

# Nome dell'antivirus a cui appartiene il file, o $null. Un servizio dell'antivirus non si
# disattiva da qui: e' proprio cio' che vorrebbe un malware, e basterebbe una segnalazione
# falsa nel report per farlo fare all'utente.
function Get-OwningAntivirus {
    param([string]$Path)
    if (-not $Path) { return $null }
    $signer = (Get-FileInfo $Path).Signer
    foreach ($av in Get-AntivirusProducts) {
        foreach ($exe in $av.pathToSignedProductExe, $av.pathToSignedReportingExe) {
            if (-not $exe) { continue }
            $p = Resolve-CommandPath $exe
            if (-not $p -or -not [IO.Path]::IsPathRooted($p)) { continue }
            # Cartella del produttore (C:\Program Files\Produttore) quando c'e', altrimenti quella del file
            $root = Split-Path -Parent $p
            if ($p -match '(?i)^([A-Z]:\\(Program Files( \(x86\))?|ProgramData)\\[^\\]+)\\') { $root = $Matches[1] }
            if ($root -match '^[A-Za-z]:\\[^\\]+\\[^\\]+' -and (Test-PathInside $Path $root)) { return "$($av.displayName)" }
            $info = Get-FileInfo $p
            if ($signer -and $info -and $info.SignatureStatus -eq 'Valid' -and $info.Signer -eq $signer -and -not (Test-MicrosoftSigner $signer)) { return "$($av.displayName)" }
        }
    }
    return $null
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
            return (Test-StartupFilePath "$($Remedy.Path)")
        }
        'ScheduledTask' {
            if ("$($Remedy.Path)" -like '\Microsoft\Windows\*') { return "Le attivita' di Windows non si disattivano da qui." }
            if (-not $Remedy.Name) { return "Attivita' senza nome." }
            return $null
        }
        'Service' {
            if ("$($Remedy.Name)" -notmatch $script:ServiceNamePattern) { return "Nome del servizio non valido." }
            $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Remedy.Name)"
            $img = Get-RegValue $svcKey 'ImagePath'
            $files = @(Resolve-CommandPath $img)
            # I servizi ospitati da svchost eseguono una DLL: conta anche quella
            $dll = Get-RegValue "$svcKey\Parameters" 'ServiceDll'
            if ($dll) { $files += [Environment]::ExpandEnvironmentVariables("$dll") }
            foreach ($target in $files | Where-Object { $_ }) {
                $av = Get-OwningAntivirus $target
                if ($av) { return "Il servizio appartiene all'antivirus installato ($av): disattivarlo lascerebbe il PC senza protezione. Se non lo vuoi piu', disinstallalo dalle impostazioni di Windows." }
            }
            $target = $files | Where-Object { $_ } | Select-Object -Last 1
            if ($target -and (Get-FileInfo $target).IsMicrosoft) { return "Il servizio esegue un programma di Microsoft: disattivarlo potrebbe danneggiare Windows." }
            return $null
        }
    }
    return "Tipo di azione sconosciuto: $($Remedy.Kind)"
}

# Motivo per cui il percorso non e' un file di una cartella Esecuzione automatica, o $null
function Test-StartupFilePath {
    param([string]$Path)
    $no = "Si possono spostare solo file delle cartelle Esecuzione automatica."
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $no }
    # Niente ".." o altre forme che indicano una cartella diversa da quella scritta
    $full = $null
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $no }
    if ($full -ne $Path) { return $no }
    $pattern = if ($script:IsAdmin) { $script:StartupFileAdminPattern } else { $script:StartupFilePattern }
    if ($Path -notmatch $pattern) { return $no }
    if ($script:IsAdmin -and ((Test-ReparsePoint (Split-Path -Parent $Path)) -or (Test-ReparsePoint $Path))) {
        return "Il percorso passa da un collegamento a un'altra cartella: per sicurezza non viene toccato."
    }
    return $null
}

function Save-Backup {
    param($Backup, [string]$Path)
    [IO.File]::WriteAllText($Path, ($Backup | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    if (Test-PathInside $Path $script:ProtectedBackupDir) { Reset-ItemAcl -Path $Path -Owner $script:AdminsSid }
}

function Invoke-RemedyDisable {
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)][string]$BackupDir)
    $r = $Request.Remedy
    $why = Test-RemedyAllowed $r
    if ($why) { throw $why }
    # Come amministratore il backup va nella cartella protetta, qualunque sia quella chiesta
    if ($script:IsAdmin) { $BackupDir = Initialize-ProtectedBackupDir }
    else { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
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
            # L'impronta serve ad "Annulla" per rimettere al suo posto solo quel file
            $hash = (Get-FileHash -LiteralPath $r.Path -Algorithm SHA256 -ErrorAction Stop).Hash
            $backup.Before = [ordered]@{ MovedTo = $dest; Sha256 = $hash }
            Save-Backup $backup $file
            try {
                Move-Item -LiteralPath $r.Path -Destination $dest -ErrorAction Stop
                # Un file spostato conserva i suoi permessi: nella cartella protetta deve avere quelli della cartella
                if ($script:IsAdmin) { Reset-ItemAcl -Path $dest -Owner $script:AdminsSid }
            } catch { Remove-Item -LiteralPath $file -Force; throw }
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
    $BackupFile = [IO.Path]::GetFullPath($BackupFile)
    # Con i privilegi di amministratore si ripristina solo cio' che un amministratore ha salvato
    if ($script:IsAdmin) {
        $why = Test-TrustedBackupFile $BackupFile
        if ($why) { throw $why }
    }
    $b = [IO.File]::ReadAllText($BackupFile) | ConvertFrom-Json
    if ($b.Schema -ne $script:BackupSchema) { throw "Backup in un formato sconosciuto." }
    if ($b.Undone) { throw "Questa modifica e' gia' stata annullata." }
    $r = $b.Remedy
    try {
        switch ("$($r.Kind)") {
            'RegistryValue' {
                Initialize-HkuDrive
                if ("$($r.Key)" -notmatch $script:RunKeyPattern) { throw "Chiave non ammessa." }
                if (-not $r.Name -or $r.Name -eq '(Predefinito)') { throw "Voce del registro senza nome." }
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
                $why = Test-StartupFilePath "$($r.Path)"
                if ($why) { throw "Percorso non ammesso." }
                if (Test-Path -LiteralPath $r.Path) { throw "Esiste gia' un file con lo stesso nome: $($r.Path)" }
                # Il file salvato e' quello accanto al backup, con lo stesso nome: non il
                # percorso scritto nel backup, che potrebbe indicare qualsiasi altro file
                $moved = [IO.Path]::ChangeExtension($BackupFile, '.file')
                if (-not (Test-Path -LiteralPath $moved -PathType Leaf) -or (Test-ReparsePoint $moved)) { throw "Il file salvato nel backup non c'e' piu'." }
                if ($b.Before.Sha256 -and (Get-FileHash -LiteralPath $moved -Algorithm SHA256 -ErrorAction Stop).Hash -ne "$($b.Before.Sha256)") {
                    throw "Il file salvato nel backup e' stato modificato dopo lo spostamento: non viene rimesso al suo posto. Si trova in $moved"
                }
                Move-Item -LiteralPath $moved -Destination $r.Path -ErrorAction Stop
                # Di nuovo i permessi della cartella in cui torna, non quelli della cartella dei backup
                try { Reset-ItemAcl -Path $r.Path } catch { }
            }
            'ScheduledTask' {
                if ("$($r.Path)" -like '\Microsoft\Windows\*' -or -not $r.Name) { throw "Attivita' non ammessa." }
                if ("$($b.Before.State)" -ne 'Disabled') { Enable-ScheduledTask -TaskPath $r.Path -TaskName $r.Name -ErrorAction Stop | Out-Null }
            }
            'Service' {
                if ("$($r.Name)" -notmatch $script:ServiceNamePattern) { throw "Nome del servizio non valido." }
                $start = [int]$b.Before.Start
                if ($start -lt 0 -or $start -gt 4) { throw "Tipo di avvio non valido." }
                Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($r.Name)" -Name Start -Value $start -Type DWord -ErrorAction Stop
            }
            default { throw "Tipo di azione sconosciuto." }
        }
    } catch [UnauthorizedAccessException], [Security.SecurityException] {
        if ($script:IsAdmin) { throw }
        throw "Per annullare servono i privilegi di amministratore, ma questo backup sta in una cartella che qualsiasi programma puo' modificare: per sicurezza non viene ripristinato come amministratore. Il contenuto da ripristinare e' scritto nel file $BackupFile`: se lo riconosci, ripristinalo a mano."
    }
    $b.Undone = $true
    $b.UndoneDate = (Get-Date).ToString('s')
    Save-Backup $b $BackupFile
    return $b
}
