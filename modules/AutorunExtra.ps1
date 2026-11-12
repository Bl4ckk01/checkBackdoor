# Lesser-known autostart locations that the classic checks (Run, tasks, services) miss.
# They are used mostly by APT groups and more careful malware, precisely because few
# people look at them. Part of the "Persistence" check: Invoke-CheckPersistence calls them.

# Profile path of every user, by SID (from the ProfileList registry key)
function Get-UserProfilePaths {
    $map = @{}
    $pl = Open-RegistryKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    if (-not $pl) { return $map }
    foreach ($sid in $pl.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-') { continue }
        $k = $pl.OpenSubKey($sid)
        $p = if ($k) { $k.GetValue('ProfileImagePath') }
        if ($p) { $map[$sid] = [Environment]::ExpandEnvironmentVariables([string]$p) }
    }
    return $map
}

# --- Moved Startup folder (T1547.001) ---------------------------------------------------
# Windows starts everything in the folder named in "User Shell Folders": moving it
# elsewhere hides the programs from anyone looking at the usual folder.
function Test-DefaultStartupFolder {
    param([string]$Raw, [string]$ProfilePath, [switch]$Common)
    if (-not $Raw) { return $true }
    if ($Common) {
        $exp = $Raw -ireplace '%ProgramData%', $env:ProgramData -ireplace '%ALLUSERSPROFILE%', $env:ProgramData
        return $exp.TrimEnd('\') -ieq "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    $exp = $Raw -ireplace '%USERPROFILE%', $ProfilePath -ireplace '%APPDATA%', "$ProfilePath\AppData\Roaming"
    return $exp.TrimEnd('\') -ieq "$ProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
}

function Test-StartupFolderRedirect {
    $cat = 'Autostart'
    $profiles = Get-UserProfilePaths
    $targets = @()
    foreach ($hu in Get-UserHives) {
        $sid = $hu.Root -replace '^HKU:\\', ''
        $prof = $profiles[$sid]
        if (-not $prof -and $hu.Root -eq 'HKCU:') { $prof = $env:USERPROFILE }
        if (-not $prof) { continue }
        $targets += [pscustomobject]@{ Key = "$($hu.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer"; Name = 'Startup'; Profile = $prof; Common = $false; User = $hu.User }
    }
    $targets += [pscustomobject]@{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Name = 'Common Startup'; Profile = $null; Common = $true; User = 'All users' }

    foreach ($t in $targets) {
        foreach ($sub in 'User Shell Folders', 'Shell Folders') {
            $key = Open-RegistryKey "$($t.Key)\$sub"
            if (-not $key) { continue }
            $raw = $key.GetValue($t.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if (-not $raw -or (Test-DefaultStartupFolder -Raw $raw -ProfilePath $t.Profile -Common:$t.Common)) { continue }
            $dir = [string]$raw
            if ($t.Profile) { $dir = $dir -ireplace '%USERPROFILE%', $t.Profile -ireplace '%APPDATA%', "$($t.Profile)\AppData\Roaming" }
            $dir = [Environment]::ExpandEnvironmentVariables($dir)
            Add-InventoryItem $cat "$($t.Key)\$sub | $($t.Name)" $raw
            Add-Finding -Category $cat -Severity 'High' -Title "Startup folder moved ($($t.User))" -Detail "$($t.Key)\$sub" `
                -Evidence "$($t.Name) = $raw" -Mitre 'T1547.001' `
                -Reasons 'Windows starts everything in this folder. Moving it elsewhere hides the programs that start at boot.' `
                -Recommendation "Set the $($t.Name) value back to the default path (...\Start Menu\Programs\Startup) and check the files in the folder it points to."
            foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $cmd = "`"$($f.FullName)`""
                if ($f.Extension -eq '.lnk') { $lnk = Resolve-Shortcut $f.FullName; if ($lnk -and $lnk.Target) { $cmd = "`"$($lnk.Target)`" $($lnk.Arguments)" } }
                Register-AutorunEntry -Category $cat -Location "Moved folder: $dir" -Name $f.Name -Command $cmd -Mitre 'T1547.001' `
                    -ExtraScore 30 -ExtraReasons 'Located in the moved Startup folder'
            }
        }
    }
}

# --- PowerShell profiles (T1546.013) -----------------------------------------------------
# A profile runs every time PowerShell starts, including when other programs use it.
function Get-PowerShellProfilePaths {
    $names = 'profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.PowerShellISE_profile.ps1', 'Microsoft.VSCode_profile.ps1'
    $dirs = New-Object System.Collections.Generic.List[string]
    foreach ($d in "$env:SystemRoot\System32\WindowsPowerShell\v1.0", "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0", "$env:ProgramFiles\PowerShell\7") { $dirs.Add($d) }
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        $docs = @(Join-Path $prof.FullName 'Documents') + @(Get-ChildItem -LiteralPath $prof.FullName -Directory -Filter 'OneDrive*' -Force -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'Documents' })
        foreach ($doc in $docs) { foreach ($sub in 'WindowsPowerShell', 'PowerShell') { $dirs.Add((Join-Path $doc $sub)) } }
    }
    foreach ($d in $dirs) {
        foreach ($n in $names) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p -PathType Leaf) { $p }
        }
    }
}

function Get-PowerShellProfileRisk {
    param([string]$Path, [string]$Content)
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $evidence = $null
    foreach ($p in @($script:SuspiciousPatterns) + @($script:ScriptExtraPatterns)) {
        if (-not $p) { continue }
        $m = [regex]::Match($Content, "(?m)^.*(?:$($p.Rx -replace '^\(\?i\)', '')).*$", 'IgnoreCase')
        if ($m.Success) {
            $score += $p.S; $reasons.Add($p.R)
            if (-not $evidence) { $evidence = $m.Value.Trim() }
        }
    }
    if ($score -gt 0 -and $Path -match '(?i)\\(System32|SysWOW64)\\WindowsPowerShell\\') {
        $score += 15; $reasons.Add('It is the profile for all users: almost no program uses it')
    }
    if ($evidence -and $evidence.Length -gt 200) { $evidence = $evidence.Substring(0, 200) + '...' }
    return [pscustomobject]@{ Score = $score; Reasons = $reasons.ToArray(); Evidence = $evidence }
}

function Test-PowerShellProfiles {
    $cat = 'Autostart'
    foreach ($p in Get-PowerShellProfilePaths) {
        $content = ''
        try { $content = [IO.File]::ReadAllText($p) } catch { continue }
        if ($content.Length -gt 262144) { $content = $content.Substring(0, 262144) }
        Add-InventoryItem $cat "PowerShell profile | $p" (Get-FileSha256 $p)
        $risk = Get-PowerShellProfileRisk -Path $p -Content $content
        $sev = ConvertTo-Severity $risk.Score
        if ($sev -eq 'Info') { continue }
        Add-Finding -Category $cat -Severity $sev -Title "PowerShell profile: $([IO.Path]::GetFileName($p))" -Path $p -Evidence $risk.Evidence `
            -Mitre 'T1546.013' -Reasons (@('The profile runs every time PowerShell starts, including when other programs use it') + @($risk.Reasons)) `
            -Recommendation 'Open the file in Notepad. If you did not write those lines (and they do not come from a tool you use, such as oh-my-posh), delete them.'
    }
}

# --- BITS jobs with a notification command (T1197) ---------------------------------------
# A BITS download can run a program when it finishes, and BITS retries it on its own for
# days: persistence that does not show up among the autostart programs.
function ConvertFrom-BitsadminList {
    param([string]$Text)
    foreach ($job in ($Text -split '(?m)^(?=GUID: )')) {
        $g = [regex]::Match($job, "(?m)^GUID: (\{[^}]+\})\s+DISPLAY: '?([^'\r\n]*)'?")
        if (-not $g.Success) { continue }
        $n = [regex]::Match($job, '(?m)^NOTIFICATION COMMAND LINE: (.+?)\s*$')
        if (-not $n.Success -or $n.Groups[1].Value -match '^(?i)none$') { continue }
        $raw = $n.Groups[1].Value
        $cmd = $raw
        $q = [regex]::Match($raw, "^'([^']*)'\s*(?:'(.*)')?$")
        if ($q.Success) { $cmd = "`"$($q.Groups[1].Value)`" $($q.Groups[2].Value)".Trim() }
        # OWNER is on the same line as TYPE and STATE
        $owner = [regex]::Match($job, 'OWNER: (\S+)')
        [pscustomobject]@{ Guid = $g.Groups[1].Value; Name = $g.Groups[2].Value; Command = $cmd; Owner = $owner.Groups[1].Value }
    }
}

function Test-BitsJobs {
    $exe = "$env:SystemRoot\System32\bitsadmin.exe"
    if (-not (Test-Path -LiteralPath $exe)) { return }
    $bitsArgs = @('/list', '/verbose')
    if ($script:IsAdmin) { $bitsArgs = @('/list', '/allusers', '/verbose') }
    $text = ''
    try { $text = (& $exe @bitsArgs 2>$null) -join "`n" } catch { return }
    foreach ($j in ConvertFrom-BitsadminList $text) {
        Register-AutorunEntry -Category 'Autostart' -Location "BITS job $($j.Guid) ($($j.Owner))" -Name "BITS: $($j.Name)" -Command $j.Command `
            -Mitre 'T1197' -ExtraScore 30 -ExtraReasons 'BITS job that runs a command: legitimate programs almost never do this' `
            -Recommendation "If you do not recognise the command, cancel the job from an administrator prompt with: bitsadmin /cancel $($j.Guid)"
    }
}

# --- AppCertDlls (T1546.009) and shim databases (T1546.011) -------------------------------
function Test-AppCertAndShims {
    $cat = 'Autostart'
    $acd = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    foreach ($v in Get-RegValues $acd) {
        if ($v.Value -isnot [string] -or -not $v.Value) { continue }
        Register-AutorunEntry -Category $cat -Location $acd -Name $v.Name -Command "`"$($v.Value)`"" -Mitre 'T1546.009' `
            -ExtraScore 40 -ExtraReasons 'AppCertDlls loads the DLL into every program that starts other programs: no common software uses it'
    }
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags') {
        $k = Open-RegistryKey "$base\InstalledSDB"
        if (-not $k) { continue }
        foreach ($g in $k.GetSubKeyNames()) {
            $s = $k.OpenSubKey($g)
            $db = if ($s) { [string]$s.GetValue('DatabasePath') }
            if (-not $db) { continue }
            $desc = [string]$s.GetValue('DatabaseDescription')
            $title = if ($desc) { "Shim database: $desc" } else { "Shim database $g" }
            Add-InventoryItem $cat "$base\InstalledSDB | $g" $db
            # .sdb files cannot be signed: what matters is where they are. sdbinst puts them
            # in AppPatch and needs administrator rights (IIS Express installs two).
            $inAppPatch = $db -like "$env:SystemRoot\AppPatch\*"
            $sev = if ($inAppPatch) { 'Low' } else { 'High' }
            $why = @('Custom shim database: it can make other programs load a DLL')
            if (-not $inAppPatch) { $why += 'Located outside the Windows AppPatch folder, where sdbinst installs them' }
            Add-Finding -Category $cat -Severity $sev -Title $title -Detail "$base\InstalledSDB\$g" -Path $db -Mitre 'T1546.011' -Reasons $why `
                -Recommendation "If you recognise the program in the name (for example IIS Express or an old game) it is normal. Otherwise remove it from an administrator prompt with: sdbinst -u `"$db`""
        }
    }
}

# --- Office (T1137) ------------------------------------------------------------------------
function Get-ComServerPath {
    param([string]$ProgId)
    $classes = [Microsoft.Win32.Registry]::ClassesRoot
    $clsid = $null
    try { $c = $classes.OpenSubKey("$ProgId\CLSID"); if ($c) { $clsid = [string]$c.GetValue('') } } catch { }
    if (-not $clsid) { return $null }
    foreach ($view in "CLSID\$clsid\InprocServer32", "WOW6432Node\CLSID\$clsid\InprocServer32", "CLSID\$clsid\LocalServer32") {
        try { $s = $classes.OpenSubKey($view); if ($s -and $s.GetValue('')) { return [Environment]::ExpandEnvironmentVariables([string]$s.GetValue('')) } } catch { }
    }
    return $null
}

function Test-OfficePersistence {
    $cat = 'Autostart'
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'All users' }) + @(Get-UserHives)
    foreach ($r in $roots) {
        # "Office test": loads a DLL every time Office starts; it exists only for Microsoft's tests
        $ot = Open-RegistryKey "$($r.Root)\Software\Microsoft\Office test\Special\Perf"
        if ($ot -and $ot.GetValue('')) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Office test\Special\Perf" -Name 'Office test' `
                -Command "`"$($ot.GetValue(''))`"" -Mitre 'T1137.002' -ExtraScore 50 `
                -ExtraReasons 'The "Office test" key loads a DLL every time Office starts: it exists only for Microsoft tests and is used by APT groups'
        }
        # COM and VSTO add-ins
        foreach ($app in 'Word', 'Excel', 'PowerPoint', 'Outlook') {
            foreach ($wow in '', 'WOW6432Node\') {
                $ak = Open-RegistryKey "$($r.Root)\Software\$($wow)Microsoft\Office\$app\Addins"
                if (-not $ak) { continue }
                foreach ($id in $ak.GetSubKeyNames()) {
                    $s = $ak.OpenSubKey($id)
                    if (-not $s) { continue }
                    $load = $s.GetValue('LoadBehavior')
                    if ($load -ne 3) { continue }
                    $manifest = [string]$s.GetValue('Manifest')
                    $loc = "$($r.Root)\Software\$($wow)Microsoft\Office\$app\Addins"
                    if ($manifest) {
                        # VSTO manifests cannot be signed as files: inventory only
                        Add-InventoryItem $cat "$loc | $id" $manifest
                    } else {
                        $srv = Get-ComServerPath $id
                        if ($srv) { Register-AutorunEntry -Category $cat -Location $loc -Name "$app add-in: $id" -Command "`"$srv`"" -Mitre 'T1137.006' }
                        else { Add-InventoryItem $cat "$loc | $id" '(COM server not found)' }
                    }
                }
            }
        }
        if ($r.Root -eq 'HKLM:') { continue }
        # Excel add-ins loaded at startup (OPEN, OPEN1...)
        $off = Open-RegistryKey "$($r.Root)\Software\Microsoft\Office"
        if (-not $off) { continue }
        foreach ($ver in $off.GetSubKeyNames() | Where-Object { $_ -match '^\d+\.\d+$' }) {
            $opt = $off.OpenSubKey("$ver\Excel\Options")
            if (-not $opt) { continue }
            foreach ($n in $opt.GetValueNames() | Where-Object { $_ -match '^OPEN\d*$' }) {
                $path = ([string]$opt.GetValue($n) -replace '^/[A-Za-z]\s+', '').Trim('"', ' ')
                Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Office\$ver\Excel\Options" -Name "Excel $n" `
                    -Command "`"$path`"" -Mitre 'T1137.006' -ExtraScore 10 -ExtraReasons 'Add-in loaded every time Excel starts'
            }
        }
    }
    # Files that Word and Excel open on their own at startup (templates and add-ins with macros)
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        foreach ($sub in 'Microsoft\Word\STARTUP', 'Microsoft\Excel\XLSTART') {
            $dir = Join-Path $prof.FullName "AppData\Roaming\$sub"
            foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
                Register-AutorunEntry -Category $cat -Location $dir -Name $f.Name -Command "`"$($f.FullName)`"" -Mitre 'T1137.001' `
                    -ExtraReasons 'Office opens this file on its own at every start: it may contain macros'
            }
        }
    }
}

# --- Winsock providers (T1547) ---------------------------------------------------------------
# A DLL registered as a network provider is loaded by every program that uses the internet
# and sees its traffic.
function ConvertFrom-PackedCatalogItem {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }
    $len = [Math]::Min(260, $Bytes.Length)
    $s = [Text.Encoding]::Default.GetString($Bytes, 0, $len).Split([char]0)[0]
    if ($s) { return [Environment]::ExpandEnvironmentVariables($s) }
    return $null
}

function Test-WinsockProviders {
    $base = 'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
    $paths = @{}
    foreach ($catalog in 'Protocol_Catalog9', 'NameSpace_Catalog5') {
        foreach ($ce in 'Catalog_Entries', 'Catalog_Entries64') {
            $k = $null
            try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$base\$catalog\$ce") } catch { }
            if (-not $k) { continue }
            foreach ($n in $k.GetSubKeyNames()) {
                $s = $k.OpenSubKey($n)
                if (-not $s) { continue }
                $p = $null
                if ($catalog -eq 'NameSpace_Catalog5') {
                    $lp = $s.GetValue('LibraryPath')
                    if ($lp) { $p = [Environment]::ExpandEnvironmentVariables([string]$lp) }
                } else {
                    $p = ConvertFrom-PackedCatalogItem $s.GetValue('PackedCatalogItem')
                }
                if ($p) { $paths[$p.ToLowerInvariant()] = $p }
            }
        }
    }
    foreach ($p in $paths.Values) {
        $info = Get-FileInfo $p
        $extra = 0; $why = @()
        if ($info.Exists -and -not $info.IsMicrosoft) { $extra = 15; $why = @('Non-Microsoft network provider: it is loaded by every program that uses the internet') }
        Register-AutorunEntry -Category 'Autostart' -Location 'Winsock provider' -Name ([IO.Path]::GetFileName($p)) -Command "`"$p`"" `
            -Mitre 'T1547' -ExtraScore $extra -ExtraReasons $why `
            -Recommendation 'If the DLL does not belong to a VPN, firewall or antivirus you installed, reset Winsock with "netsh winsock reset" from an administrator prompt.'
    }
}

function Invoke-ExtraAutorunPoints {
    Test-StartupFolderRedirect
    Test-PowerShellProfiles
    Test-BitsJobs
    Test-AppCertAndShims
    Test-OfficePersistence
    Test-WinsockProviders
}
