# Timeline: what happened in the last 30 days according to the Windows logs.
# A backdoor can delete its own files, but the traces of the installation remain:
# registered services (7045), Defender turned off or given exclusions (5001, 5007),
# threats found (1116-1119), accounts created (4720, 4732), suspicious PowerShell scripts
# (4104) and programs started (BAM key).
#
# Each reader returns simple { Time, Id, Data } objects: the Test-* functions evaluate
# them and can be tested with fake events.

$script:Timeline = New-Object System.Collections.Generic.List[object]
$script:TimelineExamined = 0
$script:TimelineRan = $false
$script:TimelineDays = 30
$script:TimelineCategory = 'Timeline'

function Add-TimelineEntry {
    param([datetime]$Time, [string]$Source, [string]$Text, [string]$Path, [string]$Severity = 'Info', [string]$FindingId)
    $script:Timeline.Add([pscustomobject]@{
            Time = $Time.ToString('s'); Source = $Source; Text = $Text; Path = $Path; Severity = $Severity; FindingId = $FindingId
        })
}

# Records the finding and the timeline entry linked to it.
function Add-TimelineFinding {
    param([datetime]$Time, [string]$Source, [string]$Severity, [string]$Title, [string]$Text, [string]$Path, [string]$Evidence,
        [string]$Detail, [string]$Mitre, [string[]]$Reasons, [string]$Recommendation)
    Add-Finding -Category $script:TimelineCategory -Severity $Severity -Title $Title -Detail $Detail -Path $Path -Evidence $Evidence `
        -Mitre $Mitre -Reasons $Reasons -Recommendation $Recommendation
    Add-TimelineEntry -Time $Time -Source $Source -Text $Text -Path $Path -Severity $Severity `
        -FindingId (Get-FindingId $script:TimelineCategory $Title $Path $Evidence)
}

function Read-WinEvents {
    param([string]$LogName, [int[]]$Id, [datetime]$Since, [int]$Max = 300, [int]$Level)
    $filter = @{ LogName = $LogName; Id = $Id; StartTime = $Since }
    if ($Level) { $filter.Level = $Level }
    try { $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
    foreach ($ev in $events) {
        $data = @{}
        try {
            foreach ($d in ([xml]$ev.ToXml()).Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
            }
        } catch { }
        [pscustomobject]@{ Time = $ev.TimeCreated; Id = $ev.Id; Data = $data }
    }
}

function Format-TimelineDate([datetime]$Time) { $Time.ToString('yyyy-MM-dd HH:mm') }

# --- Installed services (7045) ------------------------------------------------------
function Test-ServiceExists([string]$Name) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name")
    if ($k) { $k.Close(); return $true }
    return $false
}

function Test-ServiceInstallEvents {
    param($Events)
    # VPN and anti-cheat drivers reinstall themselves at every start: one entry per service
    # and command, with the latest date and the number of times.
    $groups = @(@($Events) | Where-Object { $_.Data['ServiceName'] } |
            Group-Object { "$($_.Data['ServiceName'])|$($_.Data['ImagePath'])".ToLowerInvariant() })
    foreach ($g in $groups) {
        $ev = @($g.Group | Sort-Object Time)[-1]
        $name = $ev.Data['ServiceName']; $image = $ev.Data['ImagePath']
        $exists = Test-ServiceExists $name
        $text = "Service $name installed"
        if ($g.Count -gt 1) { $text += " ($($g.Count) times)" }
        if (-not $exists) { $text += ', then removed' }
        $risk = Get-CommandRisk $image
        $sev = ConvertTo-Severity $risk.Score
        # A service that still exists is already evaluated by the services check; what matters
        # here is one removed after running a suspicious command: typical of self-deleting tools.
        if (-not $exists -and $sev -in 'High', 'Medium') {
            Add-TimelineFinding -Time $ev.Time -Source 'Services' -Severity $sev -Title "Service installed and then removed: $name" `
                -Text $text -Path $risk.Target -Evidence $image -Detail "System event log, event 7045 of $(Format-TimelineDate $ev.Time)" `
                -Mitre 'T1543.003' -Reasons (@('The service no longer exists: it was installed, ran the command and was removed') + @($risk.Reasons)) `
                -Recommendation 'A service that appears and disappears with a command like this is typical of remote-access tools. Run Microsoft Defender Offline and check the other events of the same day.'
        } else {
            $tlSev = if ($sev -in 'High', 'Medium') { $sev } else { 'Info' }
            # Updates of signed drivers and services (VPN, antivirus, anti-cheat): noise
            if ($tlSev -eq 'Info' -and $risk.Target -and [IO.Path]::IsPathRooted($risk.Target)) {
                $info = Get-FileInfo $risk.Target
                if ($info.Exists -and $info.SignatureStatus -eq 'Valid') { continue }
            }
            Add-TimelineEntry -Time $ev.Time -Source 'Services' -Text $text -Path $risk.Target -Severity $tlSev
        }
    }
}

# --- Microsoft Defender (5001, 5007, 1116-1119) ------------------------------------
function Get-DefenderThreatPath([string]$Raw) {
    if (-not $Raw) { return $null }
    $first = ($Raw -split ';')[0]
    return ($first -replace '^(file|containerfile|process|regkey|webfile):_', '').Trim()
}

function Test-DefenderEvents {
    param($Events)
    $events = @($Events | Sort-Object Time)
    $off = @($events | Where-Object { $_.Id -in 5001, 5010, 5012 })
    foreach ($ev in $off) { Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text 'Defender protection turned off' -Severity 'Medium' }
    if ($off) {
        $last = $off[-1].Time
        $n = $off.Count
        Add-Finding -Category $script:TimelineCategory -Severity 'Medium' -Title 'Defender protection turned off recently' `
            -Detail "$n times in the last $script:TimelineDays days, the last on $(Format-TimelineDate $last) (events 5001, 5010, 5012)" `
            -Mitre 'T1562.001' -Reasons 'Many cracks ask you to turn the antivirus off: while it is off, anything installed goes through unchecked' `
            -Recommendation 'If it was not you, or you turned it off to install a crack, run Microsoft Defender Offline and check what was installed on those days.'
    }

    foreach ($ev in @($events | Where-Object Id -eq 5007)) {
        $new = $ev.Data['New Value']; $old = $ev.Data['Old Value']
        if ($new -match '(?i)\\Exclusions\\(Paths|Extensions|Processes|IpAddresses)\\(.+?)\s*=' -and -not $old) {
            $kind = @{ Paths = 'folder or file'; Extensions = 'extension'; Processes = 'program'; IpAddresses = 'IP address' }[$Matches[1]]
            Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "Defender exclusion added ($kind)" -Path $Matches[2] -Severity 'Medium'
        } elseif ($new -match '(?i)\\(DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection)\s*=\s*0x1') {
            Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "Defender setting changed: $($Matches[1])" -Severity 'Medium'
        }
    }

    # Threats: one finding per threat and file, with the worst outcome
    $threats = [ordered]@{}
    foreach ($ev in @($events | Where-Object { $_.Id -in 1116, 1117, 1118, 1119 })) {
        $name = $ev.Data['Threat Name']; if (-not $name) { continue }
        $path = Get-DefenderThreatPath $ev.Data['Path']
        $key = "$name|$path".ToLowerInvariant()
        if (-not $threats.Contains($key)) { $threats[$key] = [pscustomobject]@{ Name = $name; Path = $path; First = $ev.Time; Failed = $false; Action = $null } }
        $t = $threats[$key]
        if ($ev.Id -in 1118, 1119) { $t.Failed = $true }
        if ($ev.Id -eq 1117 -and $ev.Data['Action Name']) { $t.Action = $ev.Data['Action Name'] }
        $what = @{ 1116 = 'Defender found'; 1117 = 'Defender blocked'; 1118 = 'Defender failed to block'; 1119 = 'Defender failed to block' }[$ev.Id]
        Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "$what $name" -Path $path -Severity $(if ($ev.Id -in 1118, 1119) { 'High' } else { 'Low' })
    }
    foreach ($t in $threats.Values) {
        $stillThere = $t.Path -and [IO.Path]::IsPathRooted($t.Path) -and (Test-Path -LiteralPath $t.Path -PathType Leaf)
        $reasons = @("Detected on $(Format-TimelineDate $t.First)")
        if ($t.Action) { $reasons += "Defender action: $($t.Action)" }
        if ($t.Failed) { $sev = 'High'; $reasons += 'Defender failed to remove it' }
        elseif ($stillThere) { $sev = 'Medium'; $reasons += 'The detected file still exists' }
        else { $sev = 'Low'; $reasons += 'The file is gone: Defender removed or quarantined it' }
        Add-Finding -Category $script:TimelineCategory -Severity $sev -Title "Threat found by Defender: $($t.Name)" -Path $t.Path `
            -Mitre 'T1204.002' -Reasons $reasons `
            -Recommendation 'Open Windows Security, Virus & threat protection, Protection history: check that the threat was removed. If it came from a crack, consider everything installed with it compromised.'
    }
}

# --- Accounts (4720, 4732) -------------------------------------------------------------
function Resolve-SidName([string]$Sid) {
    if (-not $Sid) { return $null }
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Test-AccountEvents {
    param($Events)
    foreach ($ev in @($Events)) {
        $by = $ev.Data['SubjectUserName']
        if ($ev.Id -eq 4720) {
            $name = $ev.Data['TargetUserName']
            Add-TimelineFinding -Time $ev.Time -Source 'Accounts' -Severity 'Medium' -Title "Account created: $name" `
                -Text "Account $name created" -Evidence "Created by $by on $(Format-TimelineDate $ev.Time)" -Detail 'Security event log, event 4720' `
                -Mitre 'T1136.001' -Reasons 'A backdoor can create an account to get back into the PC even after it is removed' `
                -Recommendation 'If you did not create this account, disable it from Computer Management, Local Users and Groups, and change your own password.'
        } elseif ($ev.Id -eq 4732 -and $ev.Data['TargetSid'] -eq 'S-1-5-32-544') {
            $member = $ev.Data['MemberName']
            if (-not $member -or $member -eq '-') { $member = Resolve-SidName $ev.Data['MemberSid'] }
            Add-TimelineFinding -Time $ev.Time -Source 'Accounts' -Severity 'Medium' -Title "Added to administrators: $member" `
                -Text "$member added to administrators" -Evidence "Added by $by on $(Format-TimelineDate $ev.Time)" -Detail 'Security event log, event 4732' `
                -Mitre 'T1098' -Reasons 'One more administrator account gives full control of the PC to whoever knows it' `
                -Recommendation 'If it was not you, remove the account from the Administrators group and change your passwords.'
        }
    }
}

# --- Suspicious PowerShell scripts (4104, Warning level) ---------------------------------
# Windows logs scripts with suspicious keywords on its own, even with no configuration.
# CheckBackdoor's own scripts are excluded: they contain those words in order to look for them.
$script:ScriptExtraPatterns = @(
    @{ Rx = '(?i)(amsiutils|amsiinitfailed|amsiscanbuffer)'; S = 60; R = 'Tries to turn off AMSI, the protection that lets the antivirus read scripts'; Hard = $true }
    @{ Rx = '(?i)\[(system\.)?reflection\.assembly\]::load'; S = 30; R = 'Loads a program straight into memory, without a file'; Hard = $false }
    @{ Rx = '(?i)virtualalloc|createremotethread|writeprocessmemory'; S = 40; R = 'Uses Windows functions to inject code into other processes'; Hard = $true }
)

function Get-OwnScriptText {
    if (-not $script:OwnScriptText) {
        # Engine folder, set by CheckBackdoor.ps1 before loading the modules
        $root = $script:EngineRoot
        $sb = New-Object System.Text.StringBuilder
        if ($root) {
            foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Include '*.ps1' -File -ErrorAction SilentlyContinue) {
                [void]$sb.Append([IO.File]::ReadAllText($f.FullName)).Append("`n")
            }
        }
        $script:OwnScriptText = $sb.ToString()
    }
    return $script:OwnScriptText
}

function Get-ScriptBlockRisk {
    param([string]$Text)
    $score = 0; $hard = $false
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($p in $script:SuspiciousPatterns) {
        if ($Text -match $p.Rx) {
            $score += $p.S; $reasons.Add($p.R)
            if ($p.S -ge 45) { $hard = $true }
        }
    }
    foreach ($p in $script:ScriptExtraPatterns) {
        if ($Text -match $p.Rx) { $score += $p.S; $reasons.Add($p.R); if ($p.Hard) { $hard = $true } }
    }
    $sev = ConvertTo-Severity $score
    # Download-and-run is also how many legitimate tools install themselves (winget,
    # Chocolatey, Scoop): it stays "to review" unless there is a stronger signal.
    if ($sev -eq 'High' -and -not $hard) { $sev = 'Medium' }
    return [pscustomobject]@{ Score = $score; Severity = $sev; Reasons = $reasons.ToArray() }
}

function Test-PowerShellEvents {
    param($Events, [string]$OwnText)
    # Same line endings on both sides: the scripts are CRLF on disk, but the event text comes
    # through the XML parser, which turns every CRLF into LF. Without this the engine would
    # report its own modules as suspicious scripts.
    $OwnText = $OwnText -replace "`r`n?", "`n"
    $seen = @{}
    foreach ($ev in @($Events)) {
        if ($ev.Data['MessageNumber'] -and $ev.Data['MessageNumber'] -ne '1') { continue }
        $text = $ev.Data['ScriptBlockText']
        if (-not $text) { continue }
        $trim = ($text -replace "`r`n?", "`n").Trim()
        if ($OwnText -and $trim.Length -gt 0 -and $OwnText.IndexOf($trim, [StringComparison]::Ordinal) -ge 0) { continue }
        # Modules Windows generates for CIM cmdlets (e.g. Defender's Get-MpPreference) and
        # scripts in C:\Windows: used by the system, not by whoever installed something.
        if ($trim -match "(?s)^#requires -version 3\.0.*\`$script:ClassName = 'root[\\/]") { continue }
        if ($ev.Data['Path'] -and $ev.Data['Path'].StartsWith($env:SystemRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $key = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($trim)))
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $risk = Get-ScriptBlockRisk $trim
        $path = $ev.Data['Path']
        $oneLine = ($trim -replace '\s+', ' ')
        if ($oneLine.Length -gt 300) { $oneLine = $oneLine.Substring(0, 300) + '...' }
        if ($risk.Severity -in 'High', 'Medium') {
            Add-TimelineFinding -Time $ev.Time -Source 'PowerShell' -Severity $risk.Severity -Title "Suspicious PowerShell script run on $(Format-TimelineDate $ev.Time)" `
                -Text 'Suspicious PowerShell script run' -Path $path -Evidence $oneLine -Detail 'PowerShell Operational log, event 4104' `
                -Mitre 'T1059.001' -Reasons $risk.Reasons `
                -Recommendation 'Read the script in Event Viewer (Applications and Services Logs, Microsoft, Windows, PowerShell, Operational, event 4104) and look for what it downloaded or ran.'
        } elseif ($risk.Severity -eq 'Low') {
            Add-TimelineEntry -Time $ev.Time -Source 'PowerShell' -Text 'PowerShell script flagged by Windows run' -Path $path -Severity 'Info'
        }
    }
}

# --- Programs started (BAM key) ----------------------------------------------------------
# Background Activity Moderator: for each user, the last time each program ran.
# Paths are in the \Device\HarddiskVolumeN\... format, to be translated into drive letters.
function Get-DeviceDriveMap {
    if (-not ('CheckBackdoor.DosDevice' -as [type])) {
        Add-Type -Namespace CheckBackdoor -Name DosDevice -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@
    }
    $map = @{}
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        $letter = $d.Name.Substring(0, 2)
        $sb = New-Object System.Text.StringBuilder 1024
        if ([CheckBackdoor.DosDevice]::QueryDosDevice($letter, $sb, 1024) -gt 0) { $map[$sb.ToString()] = $letter }
    }
    return $map
}

function ConvertFrom-BamValue {
    param([string]$Name, $Value, [hashtable]$DriveMap)
    if ($Value -isnot [byte[]] -or $Value.Length -lt 8) { return $null }
    $path = $Name
    $m = [regex]::Match($Name, '^(\\Device\\[^\\]+)(\\.*)$')
    if ($m.Success) {
        if ($DriveMap -and $DriveMap.ContainsKey($m.Groups[1].Value)) { $path = $DriveMap[$m.Groups[1].Value] + $m.Groups[2].Value }
        else { return $null }
    }
    $ft = [BitConverter]::ToInt64($Value, 0)
    if ($ft -le 0) { return $null }
    try { $time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime() } catch { return $null }
    return [pscustomobject]@{ Path = $path; Time = $time }
}

function Read-BamEntries {
    $out = @()
    $map = Get-DeviceDriveMap
    foreach ($base in 'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        $root = $null
        try { $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base) } catch { }
        if (-not $root) { continue }
        foreach ($sid in $root.GetSubKeyNames()) {
            $k = $root.OpenSubKey($sid)
            if (-not $k) { continue }
            $user = Resolve-SidName $sid
            foreach ($n in $k.GetValueNames()) {
                $e = ConvertFrom-BamValue -Name $n -Value $k.GetValue($n) -DriveMap $map
                if ($e) { $out += [pscustomobject]@{ Path = $e.Path; Time = $e.Time; User = $user } }
            }
        }
        break
    }
    return $out
}

function Test-BamEntries {
    param($Entries, [datetime]$Since)
    $known = @{}
    foreach ($f in $script:Findings) { if ($f.Path) { $known[$f.Path.ToLowerInvariant()] = $true } }
    foreach ($e in @($Entries | Where-Object { $_.Time -ge $Since } | Sort-Object Time)) {
        if (-not (Test-UserWritablePath $e.Path)) { continue }
        $name = [IO.Path]::GetFileName($e.Path)
        if (-not (Test-Path -LiteralPath $e.Path -PathType Leaf)) {
            Add-TimelineEntry -Time $e.Time -Source 'Programs' -Text "Started $name, which no longer exists" -Path $e.Path -Severity 'Info'
            continue
        }
        $risk = Get-CommandRisk "`"$($e.Path)`""
        $sev = ConvertTo-Severity $risk.Score
        if ($sev -in 'High', 'Medium' -and -not $known.ContainsKey($e.Path.ToLowerInvariant())) {
            $known[$e.Path.ToLowerInvariant()] = $true
            Add-TimelineFinding -Time $e.Time -Source 'Programs' -Severity $sev -Title "Program started from a user folder: $name" `
                -Text "Started $name" -Path $e.Path -Evidence "Last started on $(Format-TimelineDate $e.Time)$(if ($e.User) { " by $($e.User)" })" `
                -Detail 'BAM registry key (last run of each program)' -Mitre 'T1204.002' -Reasons $risk.Reasons `
                -Recommendation 'If you do not recognise this program, upload it to virustotal.com. If it is the crack or the installer of a game, check the other events of the same day in the timeline.'
        } else {
            Add-TimelineEntry -Time $e.Time -Source 'Programs' -Text "Started $name" -Path $e.Path -Severity $(if ($sev -in 'High', 'Medium') { $sev } else { 'Info' })
        }
    }
}

function Invoke-CheckTimeline {
    $script:TimelineRan = $true
    $since = (Get-Date).AddDays(-$script:TimelineDays)

    $svc = @(Read-WinEvents -LogName 'System' -Id 7045 -Since $since)
    $def = @(Read-WinEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Id 5001, 5007, 5010, 5012, 1116, 1117, 1118, 1119 -Since $since -Max 500)
    $acc = @()
    if ($script:IsAdmin) { $acc = @(Read-WinEvents -LogName 'Security' -Id 4720, 4732 -Since $since) }
    $ps = @(Read-WinEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -Since $since -Level 3 -Max 500)
    $bam = @(Read-BamEntries)
    $script:TimelineExamined = $svc.Count + $def.Count + $acc.Count + $ps.Count + @($bam | Where-Object { $_.Time -ge $since }).Count

    Test-ServiceInstallEvents $svc
    Test-DefenderEvents $def
    Test-AccountEvents $acc
    if ($ps) { Test-PowerShellEvents -Events $ps -OwnText (Get-OwnScriptText) }
    Test-BamEntries -Entries $bam -Since $since

    if (-not $script:IsAdmin) {
        Write-ScanWarning 'Timeline incomplete: without administrator rights the security log (accounts created) and the BAM key (programs started) cannot be read.'
    }
}
