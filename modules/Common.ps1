# Shared by every module: collecting findings, file analysis, command-line analysis
# and the risk score.

$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:Inventory = New-Object System.Collections.Generic.List[object]
$script:FileCache = @{}
$script:ProcessTable = $null
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Events for whoever follows the scan live (the desktop app).
# Format described in docs/EVENTS.md: one JSON line per event, appended.
# ---------------------------------------------------------------------------

$script:EventSchema = 'checkbackdoor.events/1'
$script:EventSink = $null      # full path; $null = no events
$script:EventSeq = 0
$script:CurrentCheck = $null    # check in progress, reported in every finding
$script:QuietMode = $false

function Write-ScanEvent {
    param([Parameter(Mandatory)][string]$Type, $Data = @{})
    if (-not $script:EventSink) { return }
    $script:EventSeq++
    $evt = [ordered]@{ schema = $script:EventSchema; seq = $script:EventSeq; time = (Get-Date).ToString('o'); pid = $PID; type = $Type; data = $Data }
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $evt -Depth 8 -Compress) + "`n")
    # Append with FileShare.ReadWrite: the app reads the file while the scan writes it
    for ($try = 0; $try -lt 5; $try++) {
        try {
            $fs = [IO.File]::Open($script:EventSink, 'Append', 'Write', 'ReadWrite')
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            return
        } catch { Start-Sleep -Milliseconds 50 }
    }
}

function Write-ScanWarning {
    param([Parameter(Mandatory)][string]$Message)
    Write-ScanEvent 'warning' ([ordered]@{ check = $script:CurrentCheck; message = $Message })
    if (-not $script:QuietMode) { Write-Warning $Message }
}

# ---------------------------------------------------------------------------
# Allowlist: allowlist.json (shared) and allowlist.local.json (personal).
# Applied while the scan runs, so whoever follows the events never sees items
# appear that later vanish from the report.
#
# The allowlist is also the easiest place to hide: these are files any program of the
# user can rewrite. That is why overly broad rules are not applied and are reported, an
# item ignored from the app shows up again if its file changes, and everything hidden
# stays listed in the report.
# ---------------------------------------------------------------------------

$script:Allowlist = @{ Paths = @(); Hashes = @(); Titles = @(); Ids = @{} }
$script:AllowlistRejected = New-Object System.Collections.Generic.List[object]
$script:Ignored = New-Object System.Collections.Generic.List[object]
$script:IgnoredCount = 0
$script:AllowlistCategory = 'Allowlist'

# True when the rule would hide whole parts of the PC instead of one specific program:
# too little fixed text (e.g. "*", "*.exe", "C:\*") or, for paths, a rule that on its own
# covers a folder where malware installs itself.
function Test-BroadAllowlistRule {
    param([string]$Rule, [switch]$IsPath)
    $literal = ($Rule -replace '[\*\?\[\]]', '') -replace '^[A-Za-z]:', ''
    if ($literal.Trim('\ ').Length -lt 6) { return $true }
    if ($IsPath) {
        $user = "$env:SystemDrive\Users\someone"
        $canaries = @(
            "$user\AppData\Roaming\canary.exe", "$user\AppData\Local\canary.exe", "$user\AppData\Local\Temp\canary.exe"
            "$user\Downloads\canary.exe", "$user\Desktop\canary.exe", "$env:SystemDrive\Users\Public\canary.exe"
            "$env:ProgramData\canary.exe", "$env:SystemRoot\canary.exe", "$env:SystemRoot\System32\canary.exe"
            "$env:SystemRoot\Temp\canary.exe", "$env:ProgramFiles\canary.exe"
        )
        foreach ($c in $canaries) { if ($c -like $Rule) { return $true } }
    }
    return $false
}

function Import-Allowlist {
    param([string[]]$Path)
    $script:Allowlist = @{ Paths = @(); Hashes = @(); Titles = @(); Ids = @{} }
    $script:AllowlistRejected = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Path) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        try { $al = [IO.File]::ReadAllText($p) | ConvertFrom-Json } catch { Write-ScanWarning "$([IO.Path]::GetFileName($p)) is not valid: $($_.Exception.Message)"; continue }
        foreach ($rule in @($al.paths | Where-Object { $_ })) {
            if (Test-BroadAllowlistRule "$rule" -IsPath) { $script:AllowlistRejected.Add([pscustomobject]@{ File = $p; Kind = 'path'; Rule = "$rule" }) }
            else { $script:Allowlist.Paths += "$rule" }
        }
        foreach ($rule in @($al.titles | Where-Object { $_ })) {
            if (Test-BroadAllowlistRule "$rule") { $script:AllowlistRejected.Add([pscustomobject]@{ File = $p; Kind = 'title'; Rule = "$rule" }) }
            else { $script:Allowlist.Titles += "$rule" }
        }
        $script:Allowlist.Hashes += @($al.sha256 | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
        # "ids": items ignored one by one from the app (the ID from Get-FindingId). In
        # "items" the app also records the hash the file had when it was ignored.
        foreach ($id in @($al.ids | Where-Object { $_ })) {
            $k = "$id".ToLowerInvariant()
            if (-not $script:Allowlist.Ids.ContainsKey($k)) { $script:Allowlist.Ids[$k] = $null }
        }
        foreach ($it in @($al.items | Where-Object { $_ -and $_.id -and $_.sha256 })) {
            $script:Allowlist.Ids["$($it.id)".ToLowerInvariant()] = "$($it.sha256)".ToUpperInvariant()
        }
    }
}

# True when the item was ignored from the app but its file is no longer the same
function Test-IgnoredFileChanged {
    param($Finding)
    if (-not $Finding.Id -or -not $Finding.Sha256) { return $false }
    $pinned = $script:Allowlist.Ids["$($Finding.Id)".ToLowerInvariant()]
    return [bool]($pinned -and $pinned -ne "$($Finding.Sha256)".ToUpperInvariant())
}

# The allowlist rule that hides the finding, or $null
function Get-AllowlistMatch {
    param($Finding)
    if ($Finding.Category -eq $script:AllowlistCategory) { return $null }
    foreach ($p in $script:Allowlist.Paths) {
        if (($Finding.Path -and $Finding.Path -like $p) -or ($Finding.Evidence -and $Finding.Evidence -like $p)) { return "path $p" }
    }
    if ($Finding.Sha256 -and $script:Allowlist.Hashes -contains "$($Finding.Sha256)".ToUpperInvariant()) { return 'SHA-256 hash' }
    foreach ($t in $script:Allowlist.Titles) { if ($Finding.Title -like $t) { return "title $t" } }
    if ($Finding.Id -and $script:Allowlist.Ids.ContainsKey("$($Finding.Id)".ToLowerInvariant()) -and -not (Test-IgnoredFileChanged $Finding)) {
        return 'ignored in the app'
    }
    return $null
}

function Test-Allowlisted {
    param($Finding)
    return [bool](Get-AllowlistMatch $Finding)
}

# Rejected rules become findings: if the user did not write them, someone tried to make
# results disappear.
function Add-AllowlistFindings {
    foreach ($r in $script:AllowlistRejected) {
        Add-Finding -Category $script:AllowlistCategory -Severity 'Medium' -Title "Allowlist rule too broad, not applied: $($r.Rule)" `
            -Detail $r.File -Evidence "$($r.Kind): $($r.Rule)" -Mitre 'T1562.001' `
            -Reasons @('This rule would hide whole folders or almost every finding, not one specific program: it was not applied.',
                'If you did not write it, someone changed the allowlist to make results disappear.') `
            -Recommendation 'Open the file and remove the rule, or replace it with the full path of the program or its SHA-256 hash.'
    }
}

# Stable ID of a finding: the same item gets the same ID in every scan, even when
# VirusTotal changes its severity. The app uses it for "ignore" and for actions.
function Get-FindingId {
    param([string]$Category, [string]$Title, [string]$Path, [string]$Evidence)
    $key = ("$Category|$Title|$Path|$Evidence").ToLowerInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)) } finally { $sha.Dispose() }
    return (($hash[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------------------------------------------------------------------------
# Collecting findings
# ---------------------------------------------------------------------------

function ConvertTo-Severity {
    param([int]$Score)
    if ($Score -ge 60) { return 'High' }
    if ($Score -ge 35) { return 'Medium' }
    if ($Score -ge 15) { return 'Low' }
    return 'Info'
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [string]$Path,
        [string]$Evidence,
        [string]$Mitre,
        [string]$Recommendation,
        [string[]]$Reasons,
        [string]$Sha256,
        [string]$Signer,
        # How to disable the item (Actions.ps1): only for kinds that can be undone
        [hashtable]$Remedy
    )
    if ($Path -and [IO.Path]::IsPathRooted($Path)) {
        if (-not $Sha256) { $Sha256 = Get-FileSha256 $Path }
        if (-not $Signer) { $Signer = (Get-FileInfo $Path).Signer }
    }
    $finding = [pscustomobject]@{
        Id             = Get-FindingId $Category $Title $Path $Evidence
        Check          = $script:CurrentCheck
        Category       = $Category
        Severity       = $Severity
        Title          = $Title
        Detail         = $Detail
        Path           = $Path
        Evidence       = $Evidence
        Mitre          = $Mitre
        Recommendation = $Recommendation
        Reasons        = @($Reasons | Where-Object { $_ })
        Sha256         = $Sha256
        Signer         = $Signer
        VirusTotal     = $null
        Remedy         = $Remedy
    }
    $rule = Get-AllowlistMatch $finding
    if ($rule) {
        # Hidden, but not without a trace: the report lists what was hidden and why
        $script:IgnoredCount++
        $script:Ignored.Add([pscustomobject]@{ Id = $finding.Id; Category = $Category; Severity = $Severity; Title = $Title; Path = $Path; Sha256 = $finding.Sha256; Rule = $rule })
        return
    }
    if (Test-IgnoredFileChanged $finding) {
        $finding.Reasons = @('You chose to ignore this item, but the file is no longer the same as it was then: check it again.') + @($finding.Reasons)
    }
    $script:Findings.Add($finding)
    Write-ScanEvent 'finding' ([ordered]@{ check = $script:CurrentCheck; finding = $finding })
}

# Every autostart entry goes into the inventory, even a clean one: it is used to
# compare two scans (-CompareTo) and see what changed.
function Add-InventoryItem {
    param([string]$Category, [string]$Key, [string]$Value)
    $script:Inventory.Add([pscustomobject]@{ Category = $Category; Key = $Key; Value = $Value })
}

# Records a persistence entry: adds it to the inventory and, if the score is high
# enough, reports it as a finding.
function Register-AutorunEntry {
    param(
        [string]$Category,
        [string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Mitre,
        [int]$ExtraScore = 0,
        [string[]]$ExtraReasons,
        [hashtable]$Remedy,
        [string]$Recommendation = 'If you do not recognise this program, search the file name online, upload it to virustotal.com and then remove the autostart entry.'
    )
    Add-InventoryItem -Category $Category -Key "$Location | $Name" -Value $Command
    $risk = Get-CommandRisk -CommandLine $Command
    $score = $risk.Score + $ExtraScore
    $reasons = @($ExtraReasons) + @($risk.Reasons) | Where-Object { $_ }
    $severity = ConvertTo-Severity $score
    if ($severity -ne 'Info') {
        Add-Finding -Category $Category -Severity $severity -Title "$Name" `
            -Detail $Location -Path $risk.Target -Evidence $Command -Mitre $Mitre `
            -Reasons $reasons -Sha256 $risk.Sha256 -Signer $risk.Signer -Recommendation $Recommendation -Remedy $Remedy
    }
}

# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------

$script:UserWritablePattern = '(?i)(\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents|Music|Videos|Pictures|Saved Games)\\|\\Users\\Public\\|^[A-Z]:\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\\$Recycle\.Bin\\|^[A-Z]:\\PerfLogs\\|\\Windows\\Tasks\\|\\Windows\\Debug\\|\\Windows\\Fonts\\|\\Windows\\Help\\|\\Windows\\addins\\|\\System32\\Tasks\\)'

function Test-UserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -match $script:UserWritablePattern)
}

function Test-MicrosoftSigner {
    param([string]$Signer)
    return ($Signer -match '^Microsoft (Windows|Corporation)|^Microsoft Windows (Publisher|Production PCA)')
}

function Get-FileInfo {
    param([string]$Path)
    if (-not $Path) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:FileCache.ContainsKey($key)) { return $script:FileCache[$key] }

    $info = [pscustomobject]@{
        Path = $Path; Exists = $false; Size = 0; Created = $null; Modified = $null
        SignatureStatus = 'Unknown'; Signer = $null; IsMicrosoft = $false
        Sha256 = $null; Company = $null; Description = $null; OriginalName = $null; Hidden = $false
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and -not $item.PSIsContainer) {
        $info.Exists = $true
        $info.Size = $item.Length
        $info.Created = $item.CreationTime
        $info.Modified = $item.LastWriteTime
        $info.Hidden = [bool]($item.Attributes -band ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
        try {
            $vi = $item.VersionInfo
            $info.Company = $vi.CompanyName
            $info.Description = $vi.FileDescription
            $info.OriginalName = $vi.OriginalFilename
        } catch { }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $info.SignatureStatus = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $info.Signer = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            }
            $info.IsMicrosoft = ($info.SignatureStatus -eq 'Valid' -and (Test-MicrosoftSigner $info.Signer))
        } catch { }
        # Microsoft Store apps have no signature on each file: the package is signed and
        # Windows verifies it at install time. The WindowsApps folder is writable only by
        # the system. 8wekyb3d8bbwe is Microsoft's publisher ID.
        if ($info.SignatureStatus -eq 'NotSigned' -and $Path -match '(?i)^[A-Z]:\\Program Files\\WindowsApps\\([^\\]+)\\') {
            $info.SignatureStatus = 'Valid'
            $info.Signer = "Microsoft Store package ($($Matches[1]))"
            $info.IsMicrosoft = $Matches[1] -match '_8wekyb3d8bbwe$'
        }
    }
    $script:FileCache[$key] = $info
    return $info
}

# The hash is computed only for files that end up in the report (hashing every
# executable examined would slow the scan down a lot).
function Get-FileSha256 {
    param([string]$Path)
    $info = Get-FileInfo $Path
    if (-not $info -or -not $info.Exists) { return $null }
    if (-not $info.Sha256 -and $info.Size -lt 300MB) {
        try { $info.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    }
    return $info.Sha256
}

# Random file names (e.g. "xkqzvbte.exe", "a8f3c1d9e2.exe") are typical of droppers.
function Test-RandomLookingName {
    param([string]$Path)
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    if (-not $name -or $name.Length -lt 7) { return $false }
    if ($name -match '^[0-9a-f]{8,}$' -or $name -match '^\{?[0-9a-f\-]{32,}\}?$') { return $true }
    # Names with separators or version numbers (pngcrush_1_8_w64, setup-x64) look human
    if ($name -match '[\s_\-\.]') { return $false }
    $letters = ($name -replace '[^a-zA-Z]', '')
    if ($letters.Length -lt 7) { return $false }
    $vowels = ($letters -replace '[^aeiouyAEIOUY]', '').Length
    return (($vowels / $letters.Length) -lt 0.15)
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

function Get-RegValues {
    param([string]$Path)
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $key) { return @() }
    foreach ($n in $key.GetValueNames()) {
        [pscustomobject]@{ Name = $(if ($n) { $n } else { '(Default)' }); Value = $key.GetValue($n) }
    }
}

# Opens a key with the .NET API from a PowerShell-style path (HKLM:\..., HKCU:\...,
# HKU:\SID\...). Much faster than the cmdlets on large branches.
function Open-RegistryKey {
    param([string]$Path)
    $m = [regex]::Match($Path, '^(HKLM|HKCU|HKU):\\?(.*)$')
    if (-not $m.Success) { return $null }
    $hive = switch ($m.Groups[1].Value) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
        'HKU' { [Microsoft.Win32.Registry]::Users }
    }
    try { return $hive.OpenSubKey($m.Groups[2].Value) } catch { return $null }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# Hives of every loaded user (not just the current one: when you run as administrator
# with another account, HKCU is no longer yours).
function Get-UserHives {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
    }
    $hives = @()
    foreach ($k in Get-ChildItem -LiteralPath 'HKU:\' -ErrorAction SilentlyContinue) {
        if ($k.PSChildName -match '^S-1-5-21-[\d\-]+$') {
            $user = $k.PSChildName
            try { $user = (New-Object Security.Principal.SecurityIdentifier($k.PSChildName)).Translate([Security.Principal.NTAccount]).Value } catch { }
            $hives += [pscustomobject]@{ Root = "HKU:\$($k.PSChildName)"; User = $user }
        }
    }
    if (-not $hives) { $hives += [pscustomobject]@{ Root = 'HKCU:'; User = $env:USERNAME } }
    return $hives
}

function Get-ProcessTable {
    if (-not $script:ProcessTable) {
        $script:ProcessTable = @{}
        foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
            # Some processes report their path as \\?\C:\...
            $exe = $p.ExecutablePath
            if ($exe -like '\\?\*') { $exe = $exe.Substring(4) }
            $script:ProcessTable[[int]$p.ProcessId] = [pscustomobject]@{
                ProcessId = $p.ProcessId; ParentProcessId = $p.ParentProcessId; Name = $p.Name
                ExecutablePath = $exe; CommandLine = $p.CommandLine; CreationDate = $p.CreationDate
            }
        }
    }
    return $script:ProcessTable
}

function Get-EditDistance {
    param([string]$A, [string]$B)
    $A = $A.ToLowerInvariant(); $B = $B.ToLowerInvariant()
    $d = New-Object 'int[,]' ($A.Length + 1), ($B.Length + 1)
    for ($i = 0; $i -le $A.Length; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $B.Length; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $A.Length; $i++) {
        for ($j = 1; $j -le $B.Length; $j++) {
            $cost = 1
            if ($A[$i - 1] -eq $B[$j - 1]) { $cost = 0 }
            $del = $d[($i - 1), $j] + 1
            $ins = $d[$i, ($j - 1)] + 1
            $sub = $d[($i - 1), ($j - 1)] + $cost
            $d[$i, $j] = [Math]::Min([Math]::Min($del, $ins), $sub)
        }
    }
    return $d[$A.Length, $B.Length]
}

function Resolve-Shortcut {
    param([string]$Path)
    try {
        if (-not $script:WshShell) { $script:WshShell = New-Object -ComObject WScript.Shell }
        $lnk = $script:WshShell.CreateShortcut($Path)
        return [pscustomobject]@{ Target = $lnk.TargetPath; Arguments = $lnk.Arguments }
    } catch { return $null }
}

# How to disable a registry entry: administrator rights are needed unless it is in the
# branch of the user running the app (HKCU or HKU\<their SID>).
function New-RegistryRemedy {
    param([string]$Key, [string]$Name)
    if (-not $Name -or $Name -eq '(Default)') { return $null }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $own = $Key -like 'HKCU:*' -or $Key -like "HKU:\$sid\*"
    return @{ Kind = 'RegistryValue'; Key = $Key; Name = $Name; Admin = -not $own }
}

# True when the command runs exactly this CheckBackdoor.ps1 (same content), for example
# the check scheduled by the app. A task called CheckBackdoor that runs something else
# is still reported as usual.
function Test-OwnEngineCommand {
    param([string]$CommandLine)
    if (-not $script:EngineRoot) { return $false }
    $own = Join-Path $script:EngineRoot 'CheckBackdoor.ps1'
    $ownHash = Get-FileSha256 $own
    if (-not $ownHash) { return $false }
    foreach ($p in Get-EmbeddedPaths $CommandLine) {
        if ([IO.Path]::GetFileName($p) -eq 'CheckBackdoor.ps1' -and (Get-FileSha256 $p) -eq $ownHash) { return $true }
    }
    return $false
}

# A secret encrypted with DPAPI for the current user (the VirusTotal key saved by the
# app). Only the same Windows user, on the same PC, can decrypt it.
$script:SecretEntropy = [Text.Encoding]::UTF8.GetBytes('CheckBackdoor.VirusTotal/1')
function Read-ProtectedSecret {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        Add-Type -AssemblyName System.Security
        $blob = [Convert]::FromBase64String([IO.File]::ReadAllText($Path).Trim())
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $script:SecretEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plain)
    } catch {
        Write-ScanWarning 'The VirusTotal key cannot be read: save it again from the app settings.'
        return $null
    }
}
