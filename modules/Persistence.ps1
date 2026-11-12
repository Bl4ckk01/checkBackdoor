# Autostart locations in the registry and the Startup folders.
# They are the most common way a backdoor survives a reboot (MITRE TA0003).

function Invoke-CheckPersistence {
    $cat = 'Autostart'

    # --- Run / RunOnce keys (T1547.001) -------------------------------------------
    $runSubKeys = @(
        'Software\Microsoft\Windows\CurrentVersion\Run'
        'Software\Microsoft\Windows\CurrentVersion\RunOnce'
        'Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        'Software\Microsoft\Windows\CurrentVersion\RunServices'
        'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'All users' }) + @(Get-UserHives)
    foreach ($r in $roots) {
        foreach ($sub in $runSubKeys) {
            $path = "$($r.Root)\$sub"
            foreach ($v in Get-RegValues $path) {
                if ($v.Value -isnot [string] -or -not $v.Value) { continue }
                Register-AutorunEntry -Category $cat -Location "$path ($($r.User))" -Name $v.Name -Command $v.Value -Mitre 'T1547.001' `
                    -Remedy (New-RegistryRemedy -Key $path -Name $v.Name)
            }
        }
        # Legacy "Load" and "Run" values of Windows NT\Windows
        $legacy = "$($r.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        foreach ($n in 'Load', 'Run') {
            $val = Get-RegValue $legacy $n
            if ($val) {
                Register-AutorunEntry -Category $cat -Location $legacy -Name $n -Command $val -Mitre 'T1547.001' `
                    -ExtraScore 30 -ExtraReasons 'Legacy autostart location almost never used by legitimate software'
            }
        }
        # Per-user logon script (T1037.001)
        $logon = Get-RegValue "$($r.Root)\Environment" 'UserInitMprLogonScript'
        if ($logon) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Environment" -Name 'UserInitMprLogonScript' -Command $logon `
                -Mitre 'T1037.001' -ExtraScore 40 -ExtraReasons 'Hidden logon script: home PCs never use it'
        }
        # Command prompt AutoRun: runs every time cmd.exe opens
        $car = Get-RegValue "$($r.Root)\Software\Microsoft\Command Processor" 'AutoRun'
        if ($car) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Command Processor" -Name 'AutoRun' -Command $car `
                -Mitre 'T1546' -ExtraScore 35 -ExtraReasons 'Command run every time cmd.exe starts'
        }
        # Screensaver (T1546.002)
        $scr = Get-RegValue "$($r.Root)\Control Panel\Desktop" 'SCRNSAVE.EXE'
        if ($scr) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Control Panel\Desktop" -Name 'SCRNSAVE.EXE' -Command $scr -Mitre 'T1546.002'
        }
    }

    $cpHklm = Get-RegValue 'HKLM:\Software\Microsoft\Command Processor' 'AutoRun'
    if ($cpHklm) {
        Register-AutorunEntry -Category $cat -Location 'HKLM:\Software\Microsoft\Command Processor' -Name 'AutoRun' -Command $cpHklm `
            -Mitre 'T1546' -ExtraScore 35 -ExtraReasons 'Command run every time cmd.exe starts'
    }

    # --- Winlogon Shell / Userinit (T1547.004) -----------------------------------
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = Get-RegValue $wl 'Shell'
    Add-InventoryItem $cat "$wl | Shell" $shell
    if ($shell -and $shell.Trim().ToLower() -notin @('explorer.exe', "$env:SystemRoot\explorer.exe".ToLower())) {
        Add-Finding -Category $cat -Severity 'High' -Title 'Winlogon Shell changed' -Detail $wl -Evidence "Shell = $shell" `
            -Mitre 'T1547.004' -Reasons 'The normal value is "explorer.exe". Anything added runs at every sign-in.' `
            -Recommendation 'Set the Shell value back to "explorer.exe" after identifying the program that was added.'
    }
    $userinit = Get-RegValue $wl 'Userinit'
    Add-InventoryItem $cat "$wl | Userinit" $userinit
    $okUserinit = @("$env:SystemRoot\system32\userinit.exe,", "$env:SystemRoot\system32\userinit.exe") | ForEach-Object { $_.ToLower() }
    if ($userinit -and $userinit.Trim().ToLower() -notin $okUserinit) {
        Add-Finding -Category $cat -Severity 'High' -Title 'Winlogon Userinit changed' -Detail $wl -Evidence "Userinit = $userinit" `
            -Mitre 'T1547.004' -Reasons 'The normal value is "C:\Windows\system32\userinit.exe,". Programs added here start at every sign-in.' `
            -Recommendation 'Set Userinit back to "C:\Windows\system32\userinit.exe," after identifying the program that was added.'
    }
    foreach ($hu in Get-UserHives) {
        $us = Get-RegValue "$($hu.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ($us) {
            Add-Finding -Category $cat -Severity 'High' -Title "Custom shell for user $($hu.User)" -Evidence "Shell = $us" `
                -Detail "$($hu.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Mitre 'T1547.004' `
                -Reasons 'A per-user shell replaces File Explorer: a technique used to start malware at sign-in.'
        }
    }
    # Winlogon Notify / authentication packages
    foreach ($k in Get-ChildItem -LiteralPath "$wl\Notify" -ErrorAction SilentlyContinue) {
        $dll = Get-RegValue $k.PSPath 'DLLName'
        if ($dll) { Register-AutorunEntry -Category $cat -Location "$wl\Notify" -Name $k.PSChildName -Command $dll -Mitre 'T1547.004' }
    }

    # --- AppInit_DLLs (T1546.010) ------------------------------------------------
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $dlls = Get-RegValue $p 'AppInit_DLLs'
        $load = Get-RegValue $p 'LoadAppInit_DLLs'
        if ($dlls) {
            Add-InventoryItem $cat "$p | AppInit_DLLs" $dlls
            $sev = 'Medium'; if ($load -eq 1) { $sev = 'High' }
            Add-Finding -Category $cat -Severity $sev -Title 'AppInit_DLLs is set' -Detail $p -Evidence "AppInit_DLLs = $dlls ; LoadAppInit_DLLs = $load" `
                -Mitre 'T1546.010' -Reasons 'The listed DLLs are loaded into almost every program that uses user32.dll: a classic rootkit/spyware technique.' `
                -Recommendation 'Check the DLL; if it does not belong to software you know, empty the AppInit_DLLs value.'
        }
    }

    # --- Image File Execution Options: Debugger and SilentProcessExit (T1546.012)
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $accessibility = 'sethc.exe|utilman.exe|osk.exe|magnify.exe|narrator.exe|displayswitch.exe|atbroker.exe'
    $security = 'msmpeng.exe|mpcmdrun.exe|msascui.exe|securityhealth\w*.exe|taskmgr.exe|procexp\w*.exe|autoruns\w*.exe|mbam\w*.exe|avast\w*.exe|avg\w*.exe|ekrn.exe|egui.exe|avp.exe|bdagent.exe|regedit.exe|cmd.exe|powershell.exe'
    foreach ($ifeoRoot in $ifeo, 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($k in Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction SilentlyContinue) {
            $dbg = Get-RegValue $k.PSPath 'Debugger'
            if ($dbg) {
                $extra = 45; $why = 'An IFEO "Debugger" starts another program instead of the one requested.'
                if ($k.PSChildName -match "^($accessibility)$") { $extra = 80; $why = 'Accessibility backdoor: pressing SHIFT 5 times (or the Accessibility button) on the sign-in screen opens an arbitrary program with SYSTEM rights.' }
                elseif ($k.PSChildName -match "^($security)$") { $extra = 70; $why = 'Blocks or hijacks a security/diagnostic program: typical of malware that prevents its own removal.' }
                elseif ($dbg -match '(?i)vsjitdebugger|windbg|devenv|procexp') { $extra = 0 }
                Register-AutorunEntry -Category $cat -Location $ifeoRoot -Name "IFEO Debugger for $($k.PSChildName)" -Command $dbg `
                    -Mitre 'T1546.012' -ExtraScore $extra -ExtraReasons $why `
                    -Recommendation "Delete the Debugger value from $($k.PSPath -replace '^.*::','')"
            }
            $gf = Get-RegValue $k.PSPath 'GlobalFlag'
            if ($gf -and ($gf -band 0x200)) {
                $spe = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($k.PSChildName)"
                $mon = Get-RegValue $spe 'MonitorProcess'
                if ($mon) {
                    Register-AutorunEntry -Category $cat -Location $spe -Name "SilentProcessExit for $($k.PSChildName)" -Command $mon `
                        -Mitre 'T1546.012' -ExtraScore 50 -ExtraReasons 'A program starts every time this process exits.'
                }
            }
        }
    }

    # --- Session Manager BootExecute (T1547.001) ---------------------------------
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    foreach ($n in 'BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand') {
        $vals = @(Get-RegValue $sm $n) | Where-Object { $_ }
        foreach ($v in $vals) {
            Add-InventoryItem $cat "$sm | $n" $v
            # poqexec.exe applies pending Windows updates
            $known = $v -match '^(?i)autocheck autochk (/q /v )?\*$' -or $v -match "^(?i)$([regex]::Escape($env:SystemRoot))\\System32\\poqexec\.exe /display_progress"
            if (-not $known) {
                Add-Finding -Category $cat -Severity 'Medium' -Title "Non-standard Session Manager $n" -Detail $sm -Evidence $v -Mitre 'T1547.001' `
                    -Reasons 'The normal BootExecute value is "autocheck autochk *". Other values run even before Windows (some antivirus and defrag tools use it legitimately).'
            }
        }
    }

    # --- LSA: security / password notification packages (T1547.002/.005, T1556.002)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownLsa = '^(?i)(|""|msv1_0|kerberos|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|livessp|scecli|rassfm|msoidssp)$'
    foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
        foreach ($p in @(Get-RegValue $lsa $n) + @(Get-RegValue "$lsa\OSConfig" $n)) {
            if (-not $p) { continue }
            Add-InventoryItem $cat "$lsa | $n" $p
            if ($p -notmatch $knownLsa) {
                $dll = Join-Path "$env:SystemRoot\System32" ($p -replace '\.dll$', '')
                Register-AutorunEntry -Category $cat -Location "$lsa ($n)" -Name $p -Command "$dll.dll" -Mitre 'T1547.005' `
                    -ExtraScore 25 -ExtraReasons 'DLL loaded by the LSASS process: it can steal plain-text passwords at every sign-in.'
            }
        }
    }

    # --- Print monitors and Netsh helpers (T1547.010, T1546.007) -----------------
    foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue) {
        $drv = Get-RegValue $k.PSPath 'Driver'
        if ($drv) {
            $full = $drv; if (-not [IO.Path]::IsPathRooted($drv)) { $full = Join-Path "$env:SystemRoot\System32" $drv }
            Register-AutorunEntry -Category $cat -Location 'Print Monitors' -Name $k.PSChildName -Command $full -Mitre 'T1547.010'
        }
    }
    foreach ($v in Get-RegValues 'HKLM:\SOFTWARE\Microsoft\NetSh') {
        $full = $v.Value; if (-not [IO.Path]::IsPathRooted($full)) { $full = Join-Path "$env:SystemRoot\System32" $full }
        Register-AutorunEntry -Category $cat -Location 'Netsh helper DLL' -Name $v.Name -Command $full -Mitre 'T1546.007'
    }

    # --- Active Setup (T1547.014) ------------------------------------------------
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($k in Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue) {
            $stub = Get-RegValue $k.PSPath 'StubPath'
            if ($stub) {
                $name = Get-RegValue $k.PSPath '(default)'; if (-not $name) { $name = $k.PSChildName }
                Register-AutorunEntry -Category $cat -Location 'Active Setup' -Name $name -Command $stub -Mitre 'T1547.014'
            }
        }
    }

    # --- Terminal Server / RDP wrapper -------------------------------------------
    $ip = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'InitialProgram'
    if ($ip) {
        Register-AutorunEntry -Category $cat -Location 'RDP InitialProgram' -Name 'InitialProgram' -Command $ip -Mitre 'T1547' -ExtraScore 30 `
            -ExtraReasons 'Program run automatically at every Remote Desktop connection'
    }

    # --- Startup folders (T1547.001) -----------------------------------------------
    $startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        $startupDirs += Join-Path $prof.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($dir in $startupDirs | Sort-Object -Unique) {
        foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $cmd = "`"$($f.FullName)`""
            $extraScore = 0; $extraReasons = @()
            if ($f.Extension -eq '.lnk') {
                $lnk = Resolve-Shortcut $f.FullName
                if ($lnk -and $lnk.Target) { $cmd = "`"$($lnk.Target)`" $($lnk.Arguments)" }
            } elseif ($f.Extension -match '^(?i)\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1|exe|scr|pif)$') {
                $extraScore = 20; $extraReasons = @('Executable or script copied straight into the Startup folder (normally there are only .lnk shortcuts)')
            }
            if ($f.Attributes -band [IO.FileAttributes]::Hidden) { $extraScore += 20; $extraReasons += 'The file in the Startup folder is hidden' }
            Register-AutorunEntry -Category $cat -Location $dir -Name $f.Name -Command $cmd -Mitre 'T1547.001' `
                -ExtraScore $extraScore -ExtraReasons $extraReasons `
                -Remedy @{ Kind = 'File'; Path = $f.FullName; Admin = -not ($f.FullName -like "$env:USERPROFILE\*") }
        }
    }

    # --- Per-user COM hijacking (T1546.015) -----------------------------------------
    # A CLSID registered in HKCU with the same ID as a system one in HKLM "wins" over
    # the system one: the malware gets loaded by Explorer and others.
    # The .NET API is used: with thousands of CLSIDs the registry cmdlets take minutes.
    # A program often registers dozens of CLSIDs with the same DLL: grouped by DLL.
    $hklmClsid = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Classes\CLSID')
    $byServer = @{}
    foreach ($hu in Get-UserHives) {
        $clsidRoot = "$($hu.Root)\Software\Classes\CLSID"
        $userKey = Open-RegistryKey $clsidRoot
        if (-not $userKey) { continue }
        foreach ($id in $userKey.GetSubKeyNames()) {
            foreach ($srv in 'InprocServer32', 'LocalServer32') {
                $sk = $userKey.OpenSubKey("$id\$srv")
                if (-not $sk) { continue }
                $val = $sk.GetValue('')
                $sk.Close()
                if (-not $val) { continue }
                Add-InventoryItem 'COM hijacking' "$clsidRoot\$id\$srv" $val
                $overrides = $false
                if ($hklmClsid) {
                    $sys = $hklmClsid.OpenSubKey($id)
                    if ($sys) { $overrides = $true; $sys.Close() }
                }
                $k = "$val".ToLowerInvariant()
                if (-not $byServer.ContainsKey($k)) {
                    $byServer[$k] = [pscustomobject]@{ Command = $val; Root = $clsidRoot; Ids = New-Object System.Collections.Generic.List[string]; Overrides = 0 }
                }
                $byServer[$k].Ids.Add($id)
                if ($overrides) { $byServer[$k].Overrides++ }
            }
        }
        $userKey.Close()
    }
    if ($hklmClsid) { $hklmClsid.Close() }

    foreach ($g in $byServer.Values) {
        $risk = Get-CommandRisk $g.Command
        $info = $null; if ($risk.Target) { $info = Get-FileInfo $risk.Target }
        if ($info -and $info.IsMicrosoft) { continue }
        $score = $risk.Score; $why = @($risk.Reasons)
        if ($g.Overrides -gt 0 -and -not ($info -and $info.SignatureStatus -eq 'Valid')) {
            $score += 25; $why = @("$($g.Overrides) CLSIDs also exist system-wide: the per-user version overrides them (COM hijacking)") + $why
        }
        $sev = ConvertTo-Severity $score
        if ($sev -eq 'Info') { continue }
        $ids = ($g.Ids | Select-Object -First 5) -join ', '
        if ($g.Ids.Count -gt 5) { $ids += " and $($g.Ids.Count - 5) more" }
        Add-Finding -Category 'COM hijacking' -Severity $sev -Title "Per-user COM object: $([IO.Path]::GetFileName($risk.Target))" `
            -Detail "$($g.Root) - CLSID: $ids" -Path $risk.Target -Evidence $g.Command -Mitre 'T1546.015' -Reasons $why `
            -Recommendation 'If the DLL does not belong to a program you installed (OneDrive, Teams, Dropbox... are normal), delete the listed CLSID keys in HKCU.'
    }

    # --- Lesser-known autostart locations (PowerShell profiles, BITS, Office, Winsock...)
    Invoke-ExtraAutorunPoints
}
