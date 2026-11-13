<#
.SYNOPSIS
    Disables an item reported by CheckBackdoor after saving a backup, or undoes it.

.DESCRIPTION
    The app uses it when you choose "Disable" or "Undo". It never deletes anything:
    - autostart entry in the registry: removed after saving its type and content;
    - file in the Startup folder: moved into the backup folder;
    - scheduled task: disabled;
    - service: set to Disabled and stopped.
    Every change has a checkbackdoor.backup/1 backup file that allows undoing it.

    As administrator, backups go to %ProgramData%\CheckBackdoor\backup, which only
    administrators can write, and only backups in that folder are undone: a backup in the
    user's profile could have been altered by any program.

.PARAMETER RequestSha256
    SHA-256 hash the request file must have. Whoever runs the script as administrator
    computes it when showing the request to the user: if the file is replaced in the
    meantime, the action does not start.

.EXAMPLE
    .\Actions.ps1 -RequestFile request.json -BackupDir backup -ResultFile result.json
.EXAMPLE
    .\Actions.ps1 -BackupFile backup\20261111_120000_ab12cd.json -ResultFile result.json
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
    foreach ($m in 'Common', 'CommandRisk', 'Remedy') {
        . ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $PSScriptRoot "modules\$m.ps1"))))
    }
    if ($PSCmdlet.ParameterSetName -eq 'Disable') {
        # The file is read only once: the hash and the request carried out come from the same content
        $bytes = [IO.File]::ReadAllBytes($RequestFile)
        if ($RequestSha256) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $actual = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
            if ($actual -ne $RequestSha256.ToLowerInvariant()) { throw 'The request changed after you confirmed it: nothing was changed.' }
        }
        $req = (New-Object Text.UTF8Encoding($false)).GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
        $done = Invoke-RemedyDisable -Request $req -BackupDir $BackupDir
        $result.backupFile = $done.BackupFile
        $result.title = $done.Backup.Title
        $result.message = 'Disabled. You can undo it any time from the settings.'
    } else {
        $b = Invoke-RemedyUndo -BackupFile $BackupFile
        $result.backupFile = $BackupFile
        $result.title = $b.Title
        $result.message = 'Change undone: the item is back as it was.'
    }
    $result.ok = $true
} catch {
    $result.message = $_.Exception.Message
}
[IO.File]::WriteAllText($ResultFile, ($result | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
if ($result.ok) { exit 0 } else { exit 1 }
