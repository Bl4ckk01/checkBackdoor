# Actions on findings: disabling an autostart location after saving everything needed to
# go back, and undoing. Never deletions: files are moved into the backup folder, tasks
# disabled, services set to "Disabled".
# Used by Actions.ps1, which the app runs (as administrator when needed).
#
# Whom to trust. The request and the backups come from files: those in the user profile can
# be rewritten by any program running under the user's account, which is exactly the malware
# being looked for. Therefore:
# - without privileges, those files are used, and Windows itself prevents touching what does
#   not belong to the user;
# - with administrator rights, backups are written and read only in a folder that users
#   cannot change, and every piece of data is checked again.

$script:BackupSchema = 'checkbackdoor.backup/1'
# Only autostart keys: the action must not be able to delete arbitrary registry values
$script:RunKeyPattern = '(?i)^(HKLM|HKCU|HKU):\\.+\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce)$'
$script:StartupFilePattern = '(?i)\\Start Menu\\Programs\\Startup\\[^\\]+$'
# As administrator it is not enough for the path to "end" like a Startup folder: it must be
# one of the real ones (for all users or in a user's profile)
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

# Removes the explicit permissions of a file or folder, leaving only those inherited from
# its parent folder; with -Owner it also changes the owner.
function Reset-ItemAcl {
    param([Parameter(Mandatory)][string]$Path, [string]$Owner)
    $acl = if (Test-Path -LiteralPath $Path -PathType Container) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    if ($Owner) { $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($Owner))) }
    $acl.SetAccessRuleProtection($false, $false)
    Set-ItemSecurity -Path $Path -Acl $acl
}

# Not Set-Acl: it also writes the audit part (SACL), which needs an extra privilege and
# fails even for an administrator. The .NET method writes only what changed.
function Set-ItemSecurity {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Acl)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSObject.Methods['SetAccessControl']) { $item.SetAccessControl($Acl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl($item, $Acl) }
}

# Folder for backups made as administrator: only administrators and SYSTEM can write it.
# ProgramData lets anyone create folders, so the permissions are set every time (even on a
# folder that already existed) and its content is not trusted: see Test-TrustedBackupFile.
function Initialize-ProtectedBackupDir {
    $dir = $script:ProtectedBackupDir
    $parent = Split-Path -Parent $dir
    foreach ($d in $parent, $dir) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
        if (Test-ReparsePoint $d) { throw "The protected backup folder is a link to another folder: $d. Delete it and try again." }
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

# Why a backup cannot be undone with administrator rights, or $null when it is trusted: it
# must be in the protected folder and must have been written by an administrator (a file
# left there by someone else before the folder was protected has another owner).
function Test-TrustedBackupFile {
    param([string]$BackupFile)
    $manual = "The content to restore is written in the file $BackupFile`: if you recognise it, restore it by hand."
    if (-not (Test-PathInside $BackupFile $script:ProtectedBackupDir) -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BackupFile)).TrimEnd('\') -ne [IO.Path]::GetFullPath($script:ProtectedBackupDir).TrimEnd('\')) {
        return "This backup is in a folder any program can change: for safety it is not restored with administrator rights. If you created it without those rights, open CheckBackdoor normally (not as administrator). $manual"
    }
    if (Test-ReparsePoint $BackupFile) { return "The backup is a link to another file. $manual" }
    $owner = $null
    try { $owner = (Get-Acl -LiteralPath $BackupFile -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($owner -notin $script:AdminsSid, $script:SystemSid) {
        return "This backup was not written by an administrator: for safety it is not restored. $manual"
    }
    return $null
}

# Antivirus products registered in Windows Security Center
function Get-AntivirusProducts {
    @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
}

# Name of the antivirus the file belongs to, or $null. An antivirus service is never
# disabled from here: that is exactly what malware would want, and a fake finding in the
# report would be enough to make the user do it.
function Get-OwningAntivirus {
    param([string]$Path)
    if (-not $Path) { return $null }
    $signer = (Get-FileInfo $Path).Signer
    foreach ($av in Get-AntivirusProducts) {
        foreach ($exe in $av.pathToSignedProductExe, $av.pathToSignedReportingExe) {
            if (-not $exe) { continue }
            $p = Resolve-CommandPath $exe
            if (-not $p -or -not [IO.Path]::IsPathRooted($p)) { continue }
            # The vendor folder (C:\Program Files\Vendor) when there is one, otherwise the file's folder
            $root = Split-Path -Parent $p
            if ($p -match '(?i)^([A-Z]:\\(Program Files( \(x86\))?|ProgramData)\\[^\\]+)\\') { $root = $Matches[1] }
            if ($root -match '^[A-Za-z]:\\[^\\]+\\[^\\]+' -and (Test-PathInside $Path $root)) { return "$($av.displayName)" }
            $info = Get-FileInfo $p
            if ($signer -and $info -and $info.SignatureStatus -eq 'Valid' -and $info.Signer -eq $signer -and -not (Test-MicrosoftSigner $signer)) { return "$($av.displayName)" }
        }
    }
    return $null
}

# Why the action is not allowed, or $null when it can be done.
# The report the request comes from is a user file: its content is not trusted to touch
# parts of Windows.
function Test-RemedyAllowed {
    param($Remedy)
    if (-not $Remedy) { return 'No action available for this item.' }
    switch ("$($Remedy.Kind)") {
        'RegistryValue' {
            if ("$($Remedy.Key)" -notmatch $script:RunKeyPattern) { return 'Only entries of the autostart keys (Run, RunOnce) can be disabled.' }
            if (-not $Remedy.Name -or $Remedy.Name -eq '(Default)') { return 'Registry entry without a name.' }
            return $null
        }
        'File' {
            return (Test-StartupFilePath "$($Remedy.Path)")
        }
        'ScheduledTask' {
            if ("$($Remedy.Path)" -like '\Microsoft\Windows\*') { return 'Windows tasks are not disabled from here.' }
            if (-not $Remedy.Name) { return 'Task without a name.' }
            return $null
        }
        'Service' {
            if ("$($Remedy.Name)" -notmatch $script:ServiceNamePattern) { return 'Invalid service name.' }
            $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Remedy.Name)"
            $img = Get-RegValue $svcKey 'ImagePath'
            $files = @(Resolve-CommandPath $img)
            # Services hosted by svchost run a DLL: that counts too
            $dll = Get-RegValue "$svcKey\Parameters" 'ServiceDll'
            if ($dll) { $files += [Environment]::ExpandEnvironmentVariables("$dll") }
            foreach ($target in $files | Where-Object { $_ }) {
                $av = Get-OwningAntivirus $target
                if ($av) { return "The service belongs to the installed antivirus ($av): disabling it would leave the PC unprotected. If you no longer want it, uninstall it from Windows settings." }
            }
            $target = $files | Where-Object { $_ } | Select-Object -Last 1
            if ($target -and (Get-FileInfo $target).IsMicrosoft) { return 'The service runs a Microsoft program: disabling it could damage Windows.' }
            return $null
        }
    }
    return "Unknown kind of action: $($Remedy.Kind)"
}

# Why the path is not a file in a Startup folder, or $null
function Test-StartupFilePath {
    param([string]$Path)
    $no = 'Only files in the Startup folders can be moved.'
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $no }
    # No ".." or other forms that point to a folder other than the one written
    $full = $null
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $no }
    if ($full -ne $Path) { return $no }
    $pattern = if ($script:IsAdmin) { $script:StartupFileAdminPattern } else { $script:StartupFilePattern }
    if ($Path -notmatch $pattern) { return $no }
    if ($script:IsAdmin -and ((Test-ReparsePoint (Split-Path -Parent $Path)) -or (Test-ReparsePoint $Path))) {
        return 'The path goes through a link to another folder: for safety it is not touched.'
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
    # As administrator the backup goes into the protected folder, whatever folder was asked for
    if ($script:IsAdmin) { $BackupDir = Initialize-ProtectedBackupDir }
    else { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $id = (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $file = Join-Path $BackupDir "$id.json"
    $backup = [ordered]@{
        Schema = $script:BackupSchema; Id = $id; Date = (Get-Date).ToString('s'); Title = "$($Request.Title)"
        FindingId = "$($Request.FindingId)"; Remedy = $r; Before = $null; Undone = $false; UndoneDate = $null
    }
    # The backup is saved first, then the system is changed; if the change fails the backup
    # is removed, so no "Undo" is left behind that undoes nothing.
    switch ("$($r.Kind)") {
        'RegistryValue' {
            Initialize-HkuDrive
            $key = Get-Item -LiteralPath $r.Key -ErrorAction Stop
            if ($key.GetValueNames() -notcontains $r.Name) { throw "The entry '$($r.Name)' no longer exists." }
            $kind = $key.GetValueKind($r.Name)
            $data = $key.GetValue($r.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $backup.Before = [ordered]@{ Type = "$kind"; Data = $data }
            Save-Backup $backup $file
            try { Remove-ItemProperty -LiteralPath $r.Key -Name $r.Name -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'File' {
            if (-not (Test-Path -LiteralPath $r.Path -PathType Leaf)) { throw 'The file no longer exists.' }
            $dest = Join-Path $BackupDir "$id.file"
            # Undo uses the hash to put back only that file
            $hash = (Get-FileHash -LiteralPath $r.Path -Algorithm SHA256 -ErrorAction Stop).Hash
            $backup.Before = [ordered]@{ MovedTo = $dest; Sha256 = $hash }
            Save-Backup $backup $file
            try {
                Move-Item -LiteralPath $r.Path -Destination $dest -ErrorAction Stop
                # A moved file keeps its permissions: in the protected folder it must get the folder's
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
    # With administrator rights only what an administrator saved is restored
    if ($script:IsAdmin) {
        $why = Test-TrustedBackupFile $BackupFile
        if ($why) { throw $why }
    }
    $b = [IO.File]::ReadAllText($BackupFile) | ConvertFrom-Json
    if ($b.Schema -ne $script:BackupSchema) { throw 'Backup in an unknown format.' }
    if ($b.Undone) { throw 'This change has already been undone.' }
    $r = $b.Remedy
    try {
        switch ("$($r.Kind)") {
            'RegistryValue' {
                Initialize-HkuDrive
                if ("$($r.Key)" -notmatch $script:RunKeyPattern) { throw 'Key not allowed.' }
                if (-not $r.Name -or $r.Name -eq '(Default)') { throw 'Registry entry without a name.' }
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
                if ($why) { throw 'Path not allowed.' }
                if (Test-Path -LiteralPath $r.Path) { throw "A file with the same name already exists: $($r.Path)" }
                # The saved file is the one next to the backup, with the same name: not the path
                # written in the backup, which could point to any other file
                $moved = [IO.Path]::ChangeExtension($BackupFile, '.file')
                if (-not (Test-Path -LiteralPath $moved -PathType Leaf) -or (Test-ReparsePoint $moved)) { throw 'The file saved in the backup is no longer there.' }
                if ($b.Before.Sha256 -and (Get-FileHash -LiteralPath $moved -Algorithm SHA256 -ErrorAction Stop).Hash -ne "$($b.Before.Sha256)") {
                    throw "The file saved in the backup was changed after it was moved: it is not put back. It is in $moved"
                }
                Move-Item -LiteralPath $moved -Destination $r.Path -ErrorAction Stop
                # Back to the permissions of the folder it returns to, not those of the backup folder
                try { Reset-ItemAcl -Path $r.Path } catch { }
            }
            'ScheduledTask' {
                if ("$($r.Path)" -like '\Microsoft\Windows\*' -or -not $r.Name) { throw 'Task not allowed.' }
                if ("$($b.Before.State)" -ne 'Disabled') { Enable-ScheduledTask -TaskPath $r.Path -TaskName $r.Name -ErrorAction Stop | Out-Null }
            }
            'Service' {
                if ("$($r.Name)" -notmatch $script:ServiceNamePattern) { throw 'Invalid service name.' }
                $start = [int]$b.Before.Start
                if ($start -lt 0 -or $start -gt 4) { throw 'Invalid start type.' }
                Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($r.Name)" -Name Start -Value $start -Type DWord -ErrorAction Stop
            }
            default { throw 'Unknown kind of action.' }
        }
    } catch [UnauthorizedAccessException], [Security.SecurityException] {
        if ($script:IsAdmin) { throw }
        throw "Undoing needs administrator rights, but this backup is in a folder any program can change: for safety it is not restored as administrator. The content to restore is written in the file $BackupFile`: if you recognise it, restore it by hand."
    }
    $b.Undone = $true
    $b.UndoneDate = (Get-Date).ToString('s')
    Save-Backup $b $BackupFile
    return $b
}
