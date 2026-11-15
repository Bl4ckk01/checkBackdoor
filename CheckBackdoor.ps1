<#
.SYNOPSIS
    Looks for backdoors, RATs, miners and other signs of compromise on Windows.

.DESCRIPTION
    Examines, read-only, the places where malware hides to survive reboots and to talk
    to the outside: autostart keys, scheduled tasks, services and drivers, WMI
    subscriptions, processes, network connections, browsers, Defender exclusions,
    accounts, certificates and files in user folders.
    It changes and deletes nothing. It produces an HTML, JSON and CSV report.

.PARAMETER Deep
    Deeper scan of user folders (more depth, DLLs included). Slower.

.PARAMETER CompareLast
    Compares with the last saved scan and shows what was added or removed.

.PARAMETER CompareTo
    Compares with a specific scan_*.json file.

.PARAMETER VirusTotalApiKey
    Free VirusTotal API key: looks up the hashes of suspicious files (only the hash is sent).
    Alternatively set the VT_API_KEY environment variable.

.PARAMETER VirusTotalKeyFile
    File with the VirusTotal key encrypted with DPAPI for the current user (the app writes
    it). The key never goes through the command line or environment variables.

.PARAMETER AllowlistFile
    An extra allowlist besides allowlist.json and allowlist.local.json (the app keeps the
    items the user chose to ignore here).

.PARAMETER Skip
    Checks to skip: Persistence, ScheduledTasks, Services, Wmi, Processes, Network,
    Browser, Injections, Security, Accounts, Certificates, FileSystem, Timeline.

.PARAMETER File
    Checks a single file or folder BEFORE you open it, instead of the whole PC: signature,
    origin, executable structure, antivirus-evasion tricks, replaced DLLs.
    The file is only read, never run. No administrator rights needed.

.PARAMETER EventsFile
    Writes progress and findings, as they happen, to this file (one JSON line per event,
    format in docs\EVENTS.md). Used by an interface that follows the scan.

.PARAMETER Quiet
    No console output (and no visible window if it has to restart as administrator).
    Meant to be used with -EventsFile.

.EXAMPLE
    .\CheckBackdoor.ps1
.EXAMPLE
    .\CheckBackdoor.ps1 -CompareLast -VirusTotalApiKey 0123abc...
.EXAMPLE
    .\CheckBackdoor.ps1 -File "$env:USERPROFILE\Downloads\setup.exe"
.EXAMPLE
    .\CheckBackdoor.ps1 -EventsFile "$env:TEMP\scan.jsonl" -Quiet -NoOpen
#>
[CmdletBinding()]
param(
    [string]$File,
    [string]$OutputDir,
    [switch]$Deep,
    [switch]$CompareLast,
    [string]$CompareTo,
    [string]$VirusTotalApiKey = $env:VT_API_KEY,
    [string]$VirusTotalKeyFile,
    [string]$AllowlistFile,
    [int]$VirusTotalMax = 20,
    [string[]]$Skip = @(),
    [string]$EventsFile,
    [switch]$Quiet,
    [switch]$NoOpen,
    [switch]$NoElevate,
    [switch]$PauseAtEnd
)

$Version = '1.4.0'
$ErrorActionPreference = 'Continue'
$ProgressPreference = if ($Quiet) { 'SilentlyContinue' } else { 'Continue' }
if (-not $OutputDir) { $OutputDir = Join-Path $PSScriptRoot 'report' }

# With "powershell -File" a list "A,B" arrives as one string: split it here
$validChecks = 'Persistence', 'ScheduledTasks', 'Services', 'Wmi', 'Processes', 'Network', 'Browser', 'Injections', 'Security', 'Accounts', 'Certificates', 'FileSystem', 'Timeline'
$Skip = @($Skip | ForEach-Object { $_ -split '\s*,\s*' } | Where-Object { $_ })
foreach ($s in $Skip) {
    if ($s -notin $validChecks) { throw "Unknown check in -Skip: '$s'. Allowed values: $($validChecks -join ', ')" }
}

# Absolute paths: the process restarted as administrator starts in System32, where a
# relative path would point somewhere else.
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
if ($PSBoundParameters.ContainsKey('OutputDir')) { $PSBoundParameters['OutputDir'] = $OutputDir }
if ($EventsFile) {
    $EventsFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EventsFile)
    $PSBoundParameters['EventsFile'] = $EventsFile
}
foreach ($pathParam in 'VirusTotalKeyFile', 'AllowlistFile') {
    $v = Get-Variable -Name $pathParam -ValueOnly
    if ($v) {
        $v = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($v)
        Set-Variable -Name $pathParam -Value $v
        $PSBoundParameters[$pathParam] = $v
    }
}
# Checking a single file: reading a file does not need administrator rights
if ($File) {
    $File = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)
    if (-not (Test-Path -LiteralPath $File)) { throw "File or folder not found: $File" }
    $NoElevate = [switch]$true
}

# --- Loading the modules -----------------------------------------------------
# Reading the text explicitly works even with paths that contain [ ]
$script:EngineRoot = $PSScriptRoot
$modules = 'Common', 'CommandRisk', 'Persistence', 'AutorunExtra', 'ScheduledTasks', 'Services', 'Wmi', 'Processes', 'Network', 'Browser', 'Injections', 'Security', 'Accounts', 'Certificates', 'FileSystem', 'Timeline', 'FileCheck', 'VirusTotal', 'Report'
# An antivirus may quarantine a module: better to say so clearly than to fail halfway
$missingModules = @($modules | Where-Object { -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "modules\$_.ps1")) })
if ($missingModules) {
    $msg = "Some CheckBackdoor files are missing: modules\$($missingModules -join '.ps1, modules\').ps1. " +
        "Usually the antivirus quarantined them, because CheckBackdoor reads the same places of the system that malware reads. " +
        "Restore them from quarantine (or download the project again) and add the folder to the antivirus exclusions."
    if ($EventsFile) {
        $line = [ordered]@{ schema = 'checkbackdoor.events/1'; seq = 1; time = (Get-Date).ToString('o'); pid = $PID; type = 'scan.failed'; data = [ordered]@{ message = $msg } } | ConvertTo-Json -Compress -Depth 4
        [IO.File]::AppendAllText($EventsFile, $line + "`n")
    }
    if (-not $Quiet) { Write-Host "`n  $msg`n" -ForegroundColor Red }
    if ($PauseAtEnd) { Read-Host '  Press Enter to close' | Out-Null }
    exit 4
}
foreach ($m in $modules) {
    # Not $file: in PowerShell it would be the same name as the -File parameter
    $modulePath = Join-Path $PSScriptRoot "modules\$m.ps1"
    . ([scriptblock]::Create([IO.File]::ReadAllText($modulePath)))
}
$script:QuietMode = [bool]$Quiet
if (-not $VirusTotalApiKey -and $VirusTotalKeyFile) { $VirusTotalApiKey = Read-ProtectedSecret -Path $VirusTotalKeyFile }
if ($EventsFile) {
    $dir = Split-Path -Parent $EventsFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $script:EventSink = $EventsFile
}

function Write-Console {
    param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray, [switch]$NoNewline)
    if (-not $script:QuietMode) { Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline }
}

# An unexpected error ends the scan with an event, so the interface does not wait forever.
# A trap covers the whole script, including errors before the modules are loaded (like a
# wrong -Skip): in that case there is no events file yet.
trap {
    if (Get-Command Write-ScanEvent -ErrorAction SilentlyContinue) {
        Write-ScanEvent 'scan.failed' ([ordered]@{ message = $_.Exception.Message; check = $script:CurrentCheck })
    }
    break
}

# --- Asking for administrator rights ------------------------------------------
if (-not $script:IsAdmin -and -not $NoElevate) {
    Write-Console 'Asking for administrator rights (needed to read Defender exclusions, WMI and system processes)...' Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-NoElevate')
    if (-not $Quiet) { $argList += '-PauseAtEnd' }
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Key -in 'NoElevate', 'PauseAtEnd') { continue }
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        elseif ($kv.Value -is [array]) { $argList += "-$($kv.Key)"; $argList += ($kv.Value -join ',') }
        else { $argList += "-$($kv.Key)"; $argList += "`"$($kv.Value)`"" }
    }
    $windowStyle = if ($Quiet) { 'Hidden' } else { 'Normal' }
    # Full path: a bare 'powershell.exe' is looked up in the current folder and in PATH first
    $powershellExe = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    # Written before launching: the next events come from the administrator process
    # (same file, another pid) or, if UAC is denied, from this one
    Write-ScanEvent 'scan.elevating' ([ordered]@{ message = 'Asking for administrator rights.' })
    try {
        Start-Process -FilePath $powershellExe -ArgumentList $argList -Verb RunAs -WindowStyle $windowStyle -ErrorAction Stop
        return
    } catch {
        Write-ScanWarning 'Administrator rights denied: continuing as a normal user, some checks will be incomplete.'
    }
}

$banner = @'

   ____ _               _    ____             _       _
  / ___| |__   ___  ___| | _| __ )  __ _  ___| | ____| | ___   ___  _ __
 | |   | '_ \ / _ \/ __| |/ /  _ \ / _` |/ __| |/ / _` |/ _ \ / _ \| '__|
 | |___| | | |  __/ (__|   <| |_) | (_| | (__|   < (_| | (_) | (_) | |
  \____|_| |_|\___|\___|_|\_\____/ \__,_|\___|_|\_\__,_|\___/ \___/|_|

'@
Write-Console $banner Cyan
Write-Console "  Version $Version - read-only analysis, no file is changed.`n"

$checks = @(
    @{ Id = 'Security'; Label = 'Windows defenses (Defender, exclusions, UAC, updates)'; Run = { Invoke-CheckSecurity } }
    @{ Id = 'Persistence'; Label = 'Autostart locations (registry, Startup folders, IFEO, COM)'; Run = { Invoke-CheckPersistence } }
    @{ Id = 'ScheduledTasks'; Label = 'Scheduled tasks (hidden ones too)'; Run = { Invoke-CheckScheduledTasks } }
    @{ Id = 'Services'; Label = 'Services, drivers and Safe Mode'; Run = { Invoke-CheckServices } }
    @{ Id = 'Wmi'; Label = 'Permanent WMI subscriptions'; Run = { Invoke-CheckWmi } }
    @{ Id = 'Processes'; Label = 'Running processes and CPU usage'; Run = { Invoke-CheckProcesses } }
    @{ Id = 'Network'; Label = 'Network (ports, connections, hosts, proxy, firewall, remote control)'; Run = { Invoke-CheckNetwork } }
    @{ Id = 'Browser'; Label = 'Browsers (extensions, policies, shortcuts)'; Run = { Invoke-CheckBrowser } }
    @{ Id = 'Injections'; Label = 'App injections (Discord, crypto wallets)'; Run = { Invoke-CheckInjections } }
    @{ Id = 'Accounts'; Label = 'User accounts and remote access'; Run = { Invoke-CheckAccounts } }
    @{ Id = 'Certificates'; Label = 'Root certificates'; Run = { Invoke-CheckCertificates } }
    @{ Id = 'FileSystem'; Label = "Suspicious files in AppData, Temp, ProgramData$(if ($Deep) { ' (deep)' })"; Run = { Invoke-CheckFileSystem -Deep:$Deep } }
    @{ Id = 'Timeline'; Label = 'Timeline (event logs and programs started in the last 30 days)'; Run = { Invoke-CheckTimeline } }
)
$toRun = @($checks | Where-Object { $Skip -notcontains $_.Id })
$mode = 'Scan'
if ($File) {
    $mode = 'File'
    $toRun = @(@{ Id = 'File'; Label = "Check of $(Split-Path -Leaf $File)"; Run = { Invoke-CheckFile -Path $File } })
}

# The allowlist applies while the scan runs: allowlist.json is the shared example,
# allowlist.local.json the personal list (ignored by git).
# It does not apply to a file check: whoever asks for it explicitly wants the result.
if ($mode -eq 'Scan') {
    Import-Allowlist -Path (Join-Path $PSScriptRoot 'allowlist.json'), (Join-Path $PSScriptRoot 'allowlist.local.json'), $AllowlistFile
}

$start = Get-Date
Write-ScanEvent 'scan.started' ([ordered]@{
    version = $Version; mode = $mode; target = $File; computer = $env:COMPUTERNAME; user = "$env:USERDOMAIN\$env:USERNAME"; admin = $script:IsAdmin
    deep = [bool]$Deep; skipped = $Skip; compareTo = $CompareTo; compareLast = [bool]$CompareLast; virusTotal = [bool]$VirusTotalApiKey
    outputDir = $OutputDir; checks = @($toRun | ForEach-Object { [ordered]@{ id = $_.Id; label = $_.Label } })
})
if (-not $script:IsAdmin -and $mode -eq 'Scan') { Write-ScanWarning 'You are not an administrator: the results will be incomplete.' }
# Allowlist rules that were too broad to apply are reported: they may be an attempt to hide results
Add-AllowlistFindings

# Runs one step of the scan with its start and end events
function Invoke-ScanStep {
    param([string]$Id, [string]$Label, [scriptblock]$Run, [int]$Index, [int]$Total)
    $script:CurrentCheck = $Id
    Write-ScanEvent 'check.started' ([ordered]@{ id = $Id; label = $Label; index = $Index; total = $Total })
    if ($Total) { Write-Progress -Activity 'CheckBackdoor' -Status $Label -PercentComplete (100 * ($Index - 1) / $Total) }
    Write-Console ("[{0,2}/{1}] {2}" -f $Index, $Total, $Label) -NoNewline
    $before = $script:Findings.Count
    $t0 = Get-Date
    $status = 'ok'; $message = $null
    try {
        & $Run
    } catch {
        $status = 'error'; $message = $_.Exception.Message
        $script:ScanErrors += "$($Label): $message"
    }
    $ms = [int]((Get-Date) - $t0).TotalMilliseconds
    $n = $script:Findings.Count - $before
    if ($status -eq 'ok') { Write-Console (" ... ok ({0:N0}s, {1} findings)" -f ($ms / 1000), $n) DarkGray }
    else { Write-Console " ... error: $message" Red }
    Write-ScanEvent 'check.completed' ([ordered]@{ id = $Id; status = $status; error = $message; durationMs = $ms; findings = $n })
    $script:CurrentCheck = $null
}

# Cancelling: whoever follows the events creates "<events file>.cancel". A file and not a
# signal to the process, because a normal app cannot stop an administrator process.
# It is checked between steps.
function Stop-IfCancelRequested {
    if (-not $EventsFile) { return }
    $flag = "$EventsFile.cancel"
    if (Test-Path -LiteralPath $flag) {
        Remove-Item -LiteralPath $flag -Force -ErrorAction SilentlyContinue
        Write-ScanEvent 'scan.cancelled' ([ordered]@{ durationMs = [int]((Get-Date) - $start).TotalMilliseconds; message = 'Scan cancelled.' })
        Write-Console "`nScan cancelled." Yellow
        exit 3
    }
}

$script:ScanErrors = @()
$i = 0
foreach ($c in $toRun) {
    $i++
    Stop-IfCancelRequested
    Invoke-ScanStep -Id $c.Id -Label $c.Label -Run $c.Run -Index $i -Total $toRun.Count
}
Stop-IfCancelRequested
Write-Progress -Activity 'CheckBackdoor' -Completed

if ($VirusTotalApiKey) {
    Write-Console 'Looking up hashes on VirusTotal (only the hash is sent, never the file)...'
    # When checking a file, the "clean" file is looked up too: it is the main question
    Invoke-ScanStep -Id 'VirusTotal' -Label 'VirusTotal hash lookup' -Run { Invoke-VirusTotalLookup -ApiKey $VirusTotalApiKey -Max $VirusTotalMax -IncludeInfo:($mode -eq 'File') }
}

# Comparison with a previous scan (pointless when checking a single file)
if ($mode -eq 'File') { $CompareLast = $false; $CompareTo = $null }
if ($CompareLast -and -not $CompareTo) {
    $last = Get-ChildItem -LiteralPath $OutputDir -Filter 'scan_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($last) { $CompareTo = $last.FullName } else { Write-ScanWarning 'No previous scan found to compare with.' }
}
if ($CompareTo) {
    Invoke-ScanStep -Id 'Compare' -Label 'Comparison with the previous scan' -Run { Compare-WithPrevious -PreviousJson $CompareTo }
}

$meta = @{
    Version = $Version; Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"
    Date = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Duration = $(
        $span = (Get-Date) - $start
        if ($span.TotalMinutes -ge 1) { '{0} min {1} s' -f [int][Math]::Floor($span.TotalMinutes), $span.Seconds } else { '{0} s' -f [int]$span.TotalSeconds })
    Admin = $script:IsAdmin; Deep = [bool]$Deep; ComparedTo = $CompareTo; Ignored = $script:IgnoredCount; Errors = $script:ScanErrors
    Skipped = $Skip; VirusTotal = [bool]$VirusTotalApiKey; Mode = $mode; Target = $File
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
}
# "check_" for single files: -CompareLast only looks at full scans ("scan_")
$report = Export-Results -OutputDir $OutputDir -Meta $meta -Prefix $(if ($mode -eq 'File') { 'check' } else { 'scan' })

$counts = $script:Findings | Group-Object Severity -AsHashTable -AsString
$n = { param($s) if ($counts -and $counts[$s]) { $counts[$s].Count } else { 0 } }
$exitCode = if ((& $n 'High') -gt 0) { 2 } elseif ((& $n 'Medium') -gt 0) { 1 } else { 0 }
Write-ScanEvent 'scan.completed' ([ordered]@{
    exitCode = $exitCode; durationMs = [int]((Get-Date) - $start).TotalMilliseconds; ignored = $script:IgnoredCount
    counts = [ordered]@{ High = (& $n 'High'); Medium = (& $n 'Medium'); Low = (& $n 'Low'); Info = (& $n 'Info') }
    errors = $script:ScanErrors
    report = [ordered]@{ html = $report; json = [IO.Path]::ChangeExtension($report, '.json'); csv = [IO.Path]::ChangeExtension($report, '.csv') }
})

# --- Console summary -----------------------------------------------------------
Write-Console ''
Write-Console '================= SUMMARY ================='
Write-Console ("  High risk      : {0}" -f (& $n 'High')) Red
Write-Console ("  To review      : {0}" -f (& $n 'Medium')) Yellow
Write-Console ("  Low risk       : {0}" -f (& $n 'Low')) Cyan
Write-Console ("  Information    : {0}" -f (& $n 'Info')) DarkGray
foreach ($f in $script:Findings | Where-Object Severity -eq 'High' | Select-Object -First 15) {
    Write-Console "  [HIGH] $($f.Category): $($f.Title)" Red
}
Write-Console "`nReport: $report"

if (-not $NoOpen) { Invoke-Item -LiteralPath $report }
if ($PauseAtEnd) { Read-Host "`nPress ENTER to close" | Out-Null }

exit $exitCode
