<#
.SYNOPSIS
    Disattiva un elemento segnalato da CheckBackdoor salvando un backup, o annulla.

.DESCRIPTION
    Lo usa l'app quando scegli "Disattiva" o "Annulla". Non cancella mai nulla:
    - voce di avvio nel registro: la toglie dopo averne salvato tipo e contenuto;
    - file nella cartella Esecuzione automatica: lo sposta nella cartella dei backup;
    - attivita' pianificata: la disattiva;
    - servizio: lo imposta su Disabilitato e lo ferma.
    Ogni modifica ha un file di backup checkbackdoor.backup/1 che permette di annullarla.

    Come amministratore i backup vanno in %ProgramData%\CheckBackdoor\backup, che solo gli
    amministratori possono scrivere, e si annullano solo i backup di quella cartella: un
    backup nel profilo dell'utente potrebbe essere stato ritoccato da qualsiasi programma.

.PARAMETER RequestSha256
    Impronta SHA-256 che il file della richiesta deve avere. Chi lancia lo script come
    amministratore la calcola quando mostra la richiesta all'utente: se nel frattempo il file
    viene sostituito, l'azione non parte.

.EXAMPLE
    .\Actions.ps1 -RequestFile richiesta.json -BackupDir backup -ResultFile esito.json
.EXAMPLE
    .\Actions.ps1 -BackupFile backup\20261111_120000_ab12cd.json -ResultFile esito.json
#>
[CmdletBinding(DefaultParameterSetName = 'Disable')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Disable')][string]$RequestFile,
    [Parameter(ParameterSetName = 'Disable')][string]$RequestSha256,
    [Parameter(Mandatory, ParameterSetName = 'Disable')][string]$BackupDir,
    [Parameter(Mandatory, ParameterSetName = 'Undo')][string]$BackupFile,
    [Parameter(Mandatory)][string]$ResultFile
)

$ErrorActionPreference = 'Stop'
$result = [ordered]@{ ok = $false; message = $null; backupFile = $null; title = $null }
try {
    foreach ($m in 'Common', 'Remedy') {
        . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $PSScriptRoot "modules\$m.ps1"))))
    }
    if ($PSCmdlet.ParameterSetName -eq 'Disable') {
        # Il file si legge una volta sola: l'impronta e la richiesta eseguita sono dello stesso contenuto
        $bytes = [IO.File]::ReadAllBytes($RequestFile)
        if ($RequestSha256) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $actual = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
            if ($actual -ne $RequestSha256.ToLowerInvariant()) { throw "La richiesta e' cambiata dopo la tua conferma: non e' stato modificato nulla." }
        }
        $req = (New-Object Text.UTF8Encoding($false)).GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
        $done = Invoke-RemedyDisable -Request $req -BackupDir $BackupDir
        $result.backupFile = $done.BackupFile
        $result.title = $done.Backup.Title
        $result.message = 'Disattivato. Puoi annullare quando vuoi dalle impostazioni.'
    } else {
        $b = Invoke-RemedyUndo -BackupFile $BackupFile
        $result.backupFile = $BackupFile
        $result.title = $b.Title
        $result.message = 'Modifica annullata: l''elemento e'' tornato com''era.'
    }
    $result.ok = $true
} catch {
    $result.message = $_.Exception.Message
}
[IO.File]::WriteAllText($ResultFile, ($result | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
if ($result.ok) { exit 0 } else { exit 1 }
