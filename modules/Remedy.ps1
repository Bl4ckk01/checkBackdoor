# Actions on findings: disabling an item after saving everything needed to go back, and
# undoing. Files are moved into the backup folder, tasks disabled, services set to
# "Disabled", Defender exclusions removed, accounts disabled, root certificates removed
# (their content stays in the backup). Two actions cannot be undone, and the app warns
# about it: ending a process and deleting a file (only files, only when asked).
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
# Suspicious files: only executables and scripts in the folders the file check looks at
$script:QuarantineRootPattern = '(?i)^[A-Z]:\\(Users\\[^\\]+\\AppData\\|Users\\Public\\|ProgramData\\|PerfLogs\\|Intel\\|\$Recycle\.Bin\\|Windows\\Temp\\)'
$script:QuarantineExtPattern = '(?i)\.(exe|dll|sys|scr|pif|com|cpl|ocx|jar|vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)$'
$script:ThumbprintPattern = '^[0-9A-Fa-f]{40}$'
$script:UserSidPattern = '^S-1-5-21-\d+-\d+-\d+-\d+$'
# Browser extensions: the browser process that must be closed first
$script:BrowserProcessPattern = '^(chrome|msedge|brave|opera|vivaldi|browser|firefox)$'
# Defender exclusion kinds and the Add/Remove-MpPreference parameter of each
$script:ExclusionParams = @{ Path = 'ExclusionPath'; Process = 'ExclusionProcess'; Extension = 'ExclusionExtension'; IpAddress = 'ExclusionIpAddress' }

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
        'QuarantineFile' {
            $why = Test-QuarantinePath "$($Remedy.Path)"
            if ($why) { return $why }
            return (Test-ProtectedProgram "$($Remedy.Path)")
        }
        'BrowserExtension' {
            if ("$($Remedy.Exe)" -notmatch $script:BrowserProcessPattern) { return 'Unknown browser.' }
            return (Test-ExtensionPath "$($Remedy.Path)")
        }
        'Process' {
            $procId = 0
            if (-not [int]::TryParse("$($Remedy.ProcessId)", [ref]$procId) -or $procId -le 4 -or $procId -eq $PID) { return 'Invalid process.' }
            if (-not $Remedy.Path -or -not [IO.Path]::IsPathRooted("$($Remedy.Path)")) { return 'Only processes whose program file is known can be ended.' }
            return (Test-ProtectedProgram "$($Remedy.Path)")
        }
        'DefenderExclusion' {
            if (-not $script:ExclusionParams.ContainsKey("$($Remedy.Type)")) { return 'Unknown kind of exclusion.' }
            if (-not "$($Remedy.Value)" -or "$($Remedy.Value)" -match '[\r\n]|^N/A') { return 'Invalid exclusion.' }
            return $null
        }
        'Account' {
            if ("$($Remedy.Sid)" -notmatch $script:UserSidPattern) { return 'Only local accounts can be disabled.' }
            if ("$($Remedy.Sid)" -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { return 'This is the account you are using: it cannot be disabled from here.' }
            return $null
        }
        'RootCertificate' {
            if ("$($Remedy.Thumbprint)" -notmatch $script:ThumbprintPattern) { return 'Invalid certificate.' }
            if ("$($Remedy.Store)" -eq 'User') {
                if ("$($Remedy.Sid)" -notmatch $script:UserSidPattern) { return 'Invalid user.' }
            } elseif ("$($Remedy.Store)" -ne 'Machine') { return 'Unknown certificate store.' }
            return $null
        }
    }
    return "Unknown kind of action: $($Remedy.Kind)"
}

# Why the path is not a suspicious file that can be quarantined or deleted, or $null.
# The same folders the file check looks at, and never through links: a link could lead
# from AppData into Windows.
function Test-QuarantinePath {
    param([string]$Path)
    $no = 'Only executables and scripts in the folders CheckBackdoor checks (AppData, Temp, ProgramData, Public) can be quarantined or deleted.'
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $no }
    $full = $null
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $no }
    if ($full -ne $Path) { return $no }
    if ($Path -notmatch $script:QuarantineRootPattern -or $Path -notmatch $script:QuarantineExtPattern) { return $no }
    if (Test-PathThroughLink $Path) { return 'The path goes through a link to another folder: for safety it is not touched.' }
    return $null
}

# Why the path is not a browser extension that can be removed, or $null: the folder of an
# extension (it is checked to hold a manifest.json before touching it) or a Firefox .xpi file,
# never a system folder or a whole user profile.
function Test-ExtensionPath {
    param([string]$Path)
    $no = 'Only the folder of a browser extension or a Firefox .xpi file can be removed.'
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $no }
    $Path = $Path.TrimEnd('\')
    $full = $null
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $no }
    if ($full -ne $Path) { return $no }
    if ($Path -notmatch '^[A-Za-z]:\\[^\\]+\\[^\\]+' -or $Path -match '(?i)^[A-Z]:\\Users\\[^\\]+$' -or
        $Path -match '(?i)^[A-Z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData\\Microsoft)(\\|$)') { return $no }
    if (Test-PathThroughLink $Path) { return 'The path goes through a link to another folder: for safety it is not touched.' }
    return $null
}

# The extension is still there and really is one: a .xpi file, or a folder with a
# manifest.json (Chrome keeps one subfolder per version, each with its manifest)
function Assert-ExtensionPresent {
    param($Remedy)
    $p = "$($Remedy.Path)".TrimEnd('\')
    if (Get-Process -Name "$($Remedy.Exe)" -ErrorAction SilentlyContinue) {
        throw "Close $($Remedy.Browser) first (all its windows), then try again: while it is open it could put the extension back."
    }
    if ($p -match '(?i)\.xpi$') {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw 'The extension is no longer there.' }
        return
    }
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw 'The extension is no longer there.' }
    $hasManifest = (Test-Path -LiteralPath (Join-Path $p 'manifest.json') -PathType Leaf) -or
        [bool](Get-ChildItem -LiteralPath $p -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') -PathType Leaf })
    if (-not $hasManifest) { throw 'This folder does not look like a browser extension (no manifest.json): it was not touched.' }
}

# True when the file, or one of the folders above it, is a link (junction or symbolic link)
function Test-PathThroughLink {
    param([string]$Path)
    $p = $Path
    while ($p -and $p.Length -gt 3) {
        if (Test-ReparsePoint $p) { return $true }
        $p = Split-Path -Parent $p
    }
    return $false
}

# Why the program must not be touched (Windows or the installed antivirus), or $null
function Test-ProtectedProgram {
    param([string]$Path)
    if ((Get-FileInfo $Path).IsMicrosoft) { return 'It is a Windows program: touching it could damage Windows.' }
    $av = Get-OwningAntivirus $Path
    if ($av) { return "It belongs to the installed antivirus ($av)." }
    return $null
}

# Thumbprints of the root certificates of the machine (all physical stores: also those
# set by a policy, which cannot be removed from here)
function Test-MachineRootPresent {
    param([string]$Thumbprint)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    try {
        $store.Open('ReadOnly')
        return @($store.Certificates.Find('FindByThumbprint', $Thumbprint, $false)).Count -gt 0
    } finally { $store.Close() }
}

function Get-UserRootKey {
    param([string]$Sid, [string]$Thumbprint)
    return "HKU:\$Sid\Software\Microsoft\SystemCertificates\Root\Certificates\$($Thumbprint.ToUpperInvariant())"
}

function Test-DefenderExclusionPresent {
    param([string]$Type, [string]$Value)
    $pref = Get-MpPreference -ErrorAction Stop
    return [bool](@($pref.($script:ExclusionParams[$Type])) | Where-Object { "$_" -eq $Value })
}

# Ends the process, after checking it is still the program shown in the report (the same
# number could have been given to another process in the meantime). It cannot be undone.
function Stop-RemedyProcess {
    param($Remedy)
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$Remedy.ProcessId)" -ErrorAction SilentlyContinue
    if (-not $p) { throw 'The process is no longer running.' }
    $exe = "$($p.ExecutablePath)"; if ($exe -like '\\?\*') { $exe = $exe.Substring(4) }
    $sameStart = -not $Remedy.Started -or ($p.CreationDate -and ([datetime]$p.CreationDate).ToString('o') -eq "$($Remedy.Started)")
    if ($exe -ne "$($Remedy.Path)" -or -not $sameStart) { throw 'That process number now belongs to another program: nothing was done.' }
    Stop-Process -Id ([int]$Remedy.ProcessId) -Force -ErrorAction Stop
}

# Deletes a file or a folder with everything in it. A link inside (junction, symbolic link)
# is removed as a link and never followed: it could lead to any other folder of the disk.
function Remove-Tree {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $isLink = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    if (-not $item.PSIsContainer) {
        $item.Attributes = 'Normal'
        $item.Delete()
        return
    }
    if (-not $isLink) {
        foreach ($child in $item.GetFileSystemInfos()) { Remove-Tree $child.FullName }
    }
    $item.Attributes = 'Directory'
    # On a link, Delete() without "recursive" removes only the link
    $item.Delete()
}

# Deletes for good an item in quarantine (moved there by "Disable", "Quarantine" or "Remove
# extension"), together with its backup. Only what lies next to the backup file is deleted.
function Invoke-RemedyPurge {
    param([Parameter(Mandatory)][string]$BackupFile)
    $BackupFile = [IO.Path]::GetFullPath($BackupFile)
    if ($script:IsAdmin) {
        $why = Test-TrustedBackupFile $BackupFile
        if ($why) { throw $why }
    }
    $b = [IO.File]::ReadAllText($BackupFile) | ConvertFrom-Json
    if ($b.Schema -ne $script:BackupSchema) { throw 'Backup in an unknown format.' }
    if ($b.Undone) { throw 'It was already put back: there is nothing to delete.' }
    $ext = @{ File = '.file'; QuarantineFile = '.file'; BrowserExtension = '.ext' }["$($b.Remedy.Kind)"]
    if (-not $ext) { throw 'Only files and extensions in quarantine can be deleted.' }
    $moved = [IO.Path]::ChangeExtension($BackupFile, $ext)
    if (Test-Path -LiteralPath $moved) { Remove-Tree $moved }
    Remove-Item -LiteralPath $BackupFile -Force -ErrorAction Stop
    return $b
}

# Deletes a suspicious file for good (only when the user chose "Delete"). Only the file
# shown in the report: if its content changed after the scan, it is not deleted.
function Remove-RemedyFile {
    param($Remedy)
    $path = "$($Remedy.Path)"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'The file no longer exists.' }
    if ($Remedy.Sha256 -and (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -ne "$($Remedy.Sha256)".ToUpperInvariant()) {
        throw 'The file changed after the scan: it was not deleted. Run a new scan.'
    }
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
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
    # Actions that leave nothing to undo: no backup
    if ("$($Request.Mode)" -eq 'Delete') {
        if ("$($r.Kind)" -eq 'BrowserExtension') {
            Assert-ExtensionPresent $r
            Remove-Tree "$($r.Path)".TrimEnd('\')
            return [pscustomobject]@{ BackupFile = $null; Backup = [ordered]@{ Title = "$($Request.Title)" }; Message = 'Extension deleted.' }
        }
        if ("$($r.Kind)" -notin 'File', 'QuarantineFile') { throw 'Only files and browser extensions can be deleted.' }
        Remove-RemedyFile $r
        return [pscustomobject]@{ BackupFile = $null; Backup = [ordered]@{ Title = "$($Request.Title)" }; Message = 'File deleted.' }
    }
    if ("$($r.Kind)" -eq 'Process') {
        Stop-RemedyProcess $r
        return [pscustomobject]@{ BackupFile = $null; Backup = [ordered]@{ Title = "$($Request.Title)" }; Message = 'Process ended.' }
    }
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
        { $_ -in 'File', 'QuarantineFile' } {
            if (-not (Test-Path -LiteralPath $r.Path -PathType Leaf)) { throw 'The file no longer exists.' }
            $dest = Join-Path $BackupDir "$id.file"
            # Undo uses the hash to put back only that file
            $hash = (Get-FileHash -LiteralPath $r.Path -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($r.Sha256 -and $hash -ne "$($r.Sha256)".ToUpperInvariant()) { throw 'The file changed after the scan: it was not moved. Run a new scan.' }
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
        'BrowserExtension' {
            Assert-ExtensionPresent $r
            # The whole folder (or the .xpi) goes next to the backup: the browser no longer finds it
            $dest = Join-Path $BackupDir "$id.ext"
            $backup.Before = [ordered]@{ MovedTo = $dest }
            Save-Backup $backup $file
            try {
                Move-Item -LiteralPath "$($r.Path)".TrimEnd('\') -Destination $dest -ErrorAction Stop
                if ($script:IsAdmin) { Reset-ItemAcl -Path $dest -Owner $script:AdminsSid }
            } catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'DefenderExclusion' {
            $param = $script:ExclusionParams["$($r.Type)"]
            if (-not (Test-DefenderExclusionPresent $r.Type $r.Value)) { throw 'The exclusion is no longer there.' }
            $backup.Before = [ordered]@{ Type = "$($r.Type)"; Value = "$($r.Value)" }
            Save-Backup $backup $file
            try {
                $arg = @{ $param = [string[]]@("$($r.Value)"); ErrorAction = 'Stop' }
                Remove-MpPreference @arg
                if (Test-DefenderExclusionPresent $r.Type $r.Value) { throw 'Defender kept the exclusion: it is probably set by a policy or protected by tamper protection.' }
            } catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'Account' {
            $u = Get-LocalUser -SID $r.Sid -ErrorAction Stop
            if (-not $u.Enabled) { throw 'The account is already disabled.' }
            $backup.Before = [ordered]@{ Enabled = $true; Name = "$($u.Name)" }
            Save-Backup $backup $file
            try { Disable-LocalUser -SID $r.Sid -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $file -Force; throw }
        }
        'RootCertificate' {
            $tp = "$($r.Thumbprint)".ToUpperInvariant()
            if ("$($r.Store)" -eq 'Machine') {
                $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
                $store.Open('ReadWrite')
                try {
                    $c = @($store.Certificates.Find('FindByThumbprint', $tp, $false)) | Select-Object -First 1
                    if (-not $c) { throw 'The certificate is no longer there.' }
                    $backup.Before = [ordered]@{ Der = [Convert]::ToBase64String($c.RawData) }
                    Save-Backup $backup $file
                    try { $store.Remove($c) } catch { Remove-Item -LiteralPath $file -Force; throw }
                } finally { $store.Close() }
                if (Test-MachineRootPresent $tp) {
                    Remove-Item -LiteralPath $file -Force
                    throw 'Windows kept the certificate: it is probably set by a policy.'
                }
            } else {
                Initialize-HkuDrive
                $key = Get-UserRootKey $r.Sid $tp
                $blob = Get-ItemPropertyValue -LiteralPath $key -Name Blob -ErrorAction SilentlyContinue
                if (-not $blob) { throw 'The certificate is no longer there (or that user is not signed in).' }
                $backup.Before = [ordered]@{ Blob = [Convert]::ToBase64String([byte[]]$blob) }
                Save-Backup $backup $file
                try { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop }
                catch { Remove-Item -LiteralPath $file -Force; throw }
            }
        }
    }
    return [pscustomobject]@{ BackupFile = $file; Backup = $backup; Message = $null }
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
            { $_ -in 'File', 'QuarantineFile' } {
                $why = if ("$($r.Kind)" -eq 'File') { Test-StartupFilePath "$($r.Path)" } else { Test-QuarantinePath "$($r.Path)" }
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
            'BrowserExtension' {
                $target = "$($r.Path)".TrimEnd('\')
                if (Test-ExtensionPath $target) { throw 'Path not allowed.' }
                if (Test-Path -LiteralPath $target) { throw "Something with the same name already exists: $target" }
                # What goes back is the folder next to the backup, not a path written in it
                $moved = [IO.Path]::ChangeExtension($BackupFile, '.ext')
                if (-not (Test-Path -LiteralPath $moved) -or (Test-ReparsePoint $moved)) { throw 'The extension saved in the backup is no longer there.' }
                Move-Item -LiteralPath $moved -Destination $target -ErrorAction Stop
                try { Reset-ItemAcl -Path $target } catch { }
            }
            'DefenderExclusion' {
                $param = $script:ExclusionParams["$($r.Type)"]
                if (-not $param -or -not "$($r.Value)") { throw 'Invalid exclusion.' }
                $arg = @{ $param = [string[]]@("$($r.Value)"); ErrorAction = 'Stop' }
                Add-MpPreference @arg
            }
            'Account' {
                if ("$($r.Sid)" -notmatch $script:UserSidPattern) { throw 'Invalid account.' }
                Enable-LocalUser -SID $r.Sid -ErrorAction Stop
            }
            'RootCertificate' {
                $tp = "$($r.Thumbprint)"
                if ($tp -notmatch $script:ThumbprintPattern) { throw 'Invalid certificate.' }
                if ("$($r.Store)" -eq 'Machine') {
                    $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String("$($b.Before.Der)"))
                    # Only the certificate that was removed, not whatever the backup file says
                    if ($c.Thumbprint -ne $tp.ToUpperInvariant()) { throw 'The certificate in the backup is not the one that was removed.' }
                    $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
                    $store.Open('ReadWrite')
                    try { $store.Add($c) } finally { $store.Close() }
                } else {
                    if ("$($r.Sid)" -notmatch $script:UserSidPattern) { throw 'Invalid user.' }
                    Initialize-HkuDrive
                    $key = Get-UserRootKey $r.Sid $tp
                    if (Test-Path -LiteralPath $key) { throw 'The certificate is already there.' }
                    New-Item -Path $key -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -LiteralPath $key -Name Blob -PropertyType Binary -Value ([Convert]::FromBase64String("$($b.Before.Blob)")) -ErrorAction Stop | Out-Null
                }
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
