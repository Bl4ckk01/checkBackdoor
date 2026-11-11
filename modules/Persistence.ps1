# Punti di avvio automatico nel registro e nelle cartelle Esecuzione automatica.
# Sono il modo piu' comune con cui una backdoor sopravvive al riavvio (MITRE TA0003).

function Invoke-CheckPersistence {
    $cat = 'Avvio automatico'

    # --- Chiavi Run / RunOnce (T1547.001) -----------------------------------
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
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'Tutti gli utenti' }) + @(Get-UserHives)
    foreach ($r in $roots) {
        foreach ($sub in $runSubKeys) {
            $path = "$($r.Root)\$sub"
            foreach ($v in Get-RegValues $path) {
                if ($v.Value -isnot [string] -or -not $v.Value) { continue }
                Register-AutorunEntry -Category $cat -Location "$path ($($r.User))" -Name $v.Name -Command $v.Value -Mitre 'T1547.001' `
                    -Remedy (New-RegistryRemedy -Key $path -Name $v.Name)
            }
        }
        # Valori "Load" e "Run" legacy di Windows NT\Windows
        $legacy = "$($r.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"
        foreach ($n in 'Load', 'Run') {
            $val = Get-RegValue $legacy $n
            if ($val) {
                Register-AutorunEntry -Category $cat -Location $legacy -Name $n -Command $val -Mitre 'T1547.001' `
                    -ExtraScore 30 -ExtraReasons 'Punto di avvio "legacy" quasi mai usato da software legittimo'
            }
        }
        # Script di logon per utente (T1037.001)
        $logon = Get-RegValue "$($r.Root)\Environment" 'UserInitMprLogonScript'
        if ($logon) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Environment" -Name 'UserInitMprLogonScript' -Command $logon `
                -Mitre 'T1037.001' -ExtraScore 40 -ExtraReasons 'Script di logon nascosto: sui PC di casa non viene mai usato'
        }
        # AutoRun del prompt dei comandi: viene eseguito a ogni apertura di cmd.exe
        $car = Get-RegValue "$($r.Root)\Software\Microsoft\Command Processor" 'AutoRun'
        if ($car) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Command Processor" -Name 'AutoRun' -Command $car `
                -Mitre 'T1546' -ExtraScore 35 -ExtraReasons 'Comando eseguito ad ogni avvio di cmd.exe'
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
            -Mitre 'T1546' -ExtraScore 35 -ExtraReasons 'Comando eseguito ad ogni avvio di cmd.exe'
    }

    # --- Winlogon Shell / Userinit (T1547.004) ------------------------------
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = Get-RegValue $wl 'Shell'
    Add-InventoryItem $cat "$wl | Shell" $shell
    if ($shell -and $shell.Trim().ToLower() -notin @('explorer.exe', "$env:SystemRoot\explorer.exe".ToLower())) {
        Add-Finding -Category $cat -Severity 'Alto' -Title 'Winlogon Shell modificato' -Detail $wl -Evidence "Shell = $shell" `
            -Mitre 'T1547.004' -Reasons 'Il valore normale e'' "explorer.exe". Qualsiasi aggiunta viene eseguita ad ogni accesso.' `
            -Recommendation 'Ripristina il valore Shell a "explorer.exe" dopo aver identificato il programma aggiunto.'
    }
    $userinit = Get-RegValue $wl 'Userinit'
    Add-InventoryItem $cat "$wl | Userinit" $userinit
    $okUserinit = @("$env:SystemRoot\system32\userinit.exe,", "$env:SystemRoot\system32\userinit.exe") | ForEach-Object { $_.ToLower() }
    if ($userinit -and $userinit.Trim().ToLower() -notin $okUserinit) {
        Add-Finding -Category $cat -Severity 'Alto' -Title 'Winlogon Userinit modificato' -Detail $wl -Evidence "Userinit = $userinit" `
            -Mitre 'T1547.004' -Reasons 'Il valore normale e'' "C:\Windows\system32\userinit.exe,". Programmi aggiunti qui partono ad ogni accesso.' `
            -Recommendation 'Ripristina Userinit a "C:\Windows\system32\userinit.exe," dopo aver identificato il programma aggiunto.'
    }
    foreach ($hu in Get-UserHives) {
        $us = Get-RegValue "$($hu.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ($us) {
            Add-Finding -Category $cat -Severity 'Alto' -Title "Shell personalizzata per l'utente $($hu.User)" -Evidence "Shell = $us" `
                -Detail "$($hu.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Mitre 'T1547.004' `
                -Reasons 'Una shell per-utente sostituisce Esplora risorse: tecnica usata per avviare malware al logon.'
        }
    }
    # Winlogon Notify / pacchetti di autenticazione
    foreach ($k in Get-ChildItem -LiteralPath "$wl\Notify" -ErrorAction SilentlyContinue) {
        $dll = Get-RegValue $k.PSPath 'DLLName'
        if ($dll) { Register-AutorunEntry -Category $cat -Location "$wl\Notify" -Name $k.PSChildName -Command $dll -Mitre 'T1547.004' }
    }

    # --- AppInit_DLLs (T1546.010) -------------------------------------------
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $dlls = Get-RegValue $p 'AppInit_DLLs'
        $load = Get-RegValue $p 'LoadAppInit_DLLs'
        if ($dlls) {
            Add-InventoryItem $cat "$p | AppInit_DLLs" $dlls
            $sev = 'Medio'; if ($load -eq 1) { $sev = 'Alto' }
            Add-Finding -Category $cat -Severity $sev -Title 'AppInit_DLLs impostato' -Detail $p -Evidence "AppInit_DLLs = $dlls ; LoadAppInit_DLLs = $load" `
                -Mitre 'T1546.010' -Reasons 'Le DLL elencate vengono caricate in quasi ogni programma che usa user32.dll: tecnica classica di rootkit/spyware.' `
                -Recommendation 'Verifica la DLL indicata; se non appartiene a un software che conosci, svuota il valore AppInit_DLLs.'
        }
    }

    # --- Image File Execution Options: Debugger e SilentProcessExit (T1546.012)
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $accessibility = 'sethc.exe|utilman.exe|osk.exe|magnify.exe|narrator.exe|displayswitch.exe|atbroker.exe'
    $security = 'msmpeng.exe|mpcmdrun.exe|msascui.exe|securityhealth\w*.exe|taskmgr.exe|procexp\w*.exe|autoruns\w*.exe|mbam\w*.exe|avast\w*.exe|avg\w*.exe|ekrn.exe|egui.exe|avp.exe|bdagent.exe|regedit.exe|cmd.exe|powershell.exe'
    foreach ($ifeoRoot in $ifeo, 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($k in Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction SilentlyContinue) {
            $dbg = Get-RegValue $k.PSPath 'Debugger'
            if ($dbg) {
                $extra = 45; $why = 'Un "Debugger" IFEO fa partire un altro programma al posto di quello richiesto.'
                if ($k.PSChildName -match "^($accessibility)$") { $extra = 80; $why = "Backdoor di accessibilita': premendo 5 volte MAIUSC (o il tasto Accessibilita') nella schermata di login si apre un programma arbitrario con privilegi SYSTEM." }
                elseif ($k.PSChildName -match "^($security)$") { $extra = 70; $why = 'Blocca o dirotta un programma di sicurezza/diagnostica: tipico dei malware che impediscono la propria rimozione.' }
                elseif ($dbg -match '(?i)vsjitdebugger|windbg|devenv|procexp') { $extra = 0 }
                Register-AutorunEntry -Category $cat -Location $ifeoRoot -Name "IFEO Debugger per $($k.PSChildName)" -Command $dbg `
                    -Mitre 'T1546.012' -ExtraScore $extra -ExtraReasons $why `
                    -Recommendation "Elimina il valore Debugger da $($k.PSPath -replace '^.*::','')"
            }
            $gf = Get-RegValue $k.PSPath 'GlobalFlag'
            if ($gf -and ($gf -band 0x200)) {
                $spe = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($k.PSChildName)"
                $mon = Get-RegValue $spe 'MonitorProcess'
                if ($mon) {
                    Register-AutorunEntry -Category $cat -Location $spe -Name "SilentProcessExit per $($k.PSChildName)" -Command $mon `
                        -Mitre 'T1546.012' -ExtraScore 50 -ExtraReasons 'Un programma viene avviato ogni volta che questo processo si chiude.'
                }
            }
        }
    }

    # --- Session Manager BootExecute (T1547.001) ----------------------------
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    foreach ($n in 'BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand') {
        $vals = @(Get-RegValue $sm $n) | Where-Object { $_ }
        foreach ($v in $vals) {
            Add-InventoryItem $cat "$sm | $n" $v
            # poqexec.exe applica gli aggiornamenti di Windows in sospeso
            $known = $v -match '^(?i)autocheck autochk (/q /v )?\*$' -or $v -match "^(?i)$([regex]::Escape($env:SystemRoot))\\System32\\poqexec\.exe /display_progress"
            if (-not $known) {
                Add-Finding -Category $cat -Severity 'Medio' -Title "Session Manager $n non standard" -Detail $sm -Evidence $v -Mitre 'T1547.001' `
                    -Reasons 'Il valore normale di BootExecute e'' "autocheck autochk *". Altri valori vengono eseguiti prima ancora di Windows (alcuni antivirus e tool di deframmentazione lo usano legittimamente).'
            }
        }
    }

    # --- LSA: pacchetti di sicurezza / notifica password (T1547.002/.005, T1556.002)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownLsa = '^(?i)(|""|msv1_0|kerberos|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|livessp|scecli|rassfm|msoidssp)$'
    foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
        foreach ($p in @(Get-RegValue $lsa $n) + @(Get-RegValue "$lsa\OSConfig" $n)) {
            if (-not $p) { continue }
            Add-InventoryItem $cat "$lsa | $n" $p
            if ($p -notmatch $knownLsa) {
                $dll = Join-Path "$env:SystemRoot\System32" ($p -replace '\.dll$', '')
                Register-AutorunEntry -Category $cat -Location "$lsa ($n)" -Name $p -Command "$dll.dll" -Mitre 'T1547.005' `
                    -ExtraScore 25 -ExtraReasons 'DLL caricata dal processo LSASS: puo'' rubare le password in chiaro ad ogni accesso.'
            }
        }
    }

    # --- Print monitors e Netsh helper (T1547.010, T1546.007) ---------------
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

    # --- Active Setup (T1547.014) -------------------------------------------
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($k in Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue) {
            $stub = Get-RegValue $k.PSPath 'StubPath'
            if ($stub) {
                $name = Get-RegValue $k.PSPath '(default)'; if (-not $name) { $name = $k.PSChildName }
                Register-AutorunEntry -Category $cat -Location 'Active Setup' -Name $name -Command $stub -Mitre 'T1547.014'
            }
        }
    }

    # --- Terminal Server / RDP wrapper -------------------------------------
    $ip = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'InitialProgram'
    if ($ip) {
        Register-AutorunEntry -Category $cat -Location 'RDP InitialProgram' -Name 'InitialProgram' -Command $ip -Mitre 'T1547' -ExtraScore 30 `
            -ExtraReasons 'Programma eseguito automaticamente ad ogni connessione Desktop remoto'
    }

    # --- Cartelle Esecuzione automatica (T1547.001) -------------------------
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
                $extraScore = 20; $extraReasons = @("File eseguibile/script copiato direttamente nella cartella Esecuzione automatica (di solito ci sono solo collegamenti .lnk)")
            }
            if ($f.Attributes -band [IO.FileAttributes]::Hidden) { $extraScore += 20; $extraReasons += 'Il file nella cartella Esecuzione automatica e'' nascosto' }
            Register-AutorunEntry -Category $cat -Location $dir -Name $f.Name -Command $cmd -Mitre 'T1547.001' `
                -ExtraScore $extraScore -ExtraReasons $extraReasons `
                -Remedy @{ Kind = 'File'; Path = $f.FullName; Admin = -not ($f.FullName -like "$env:USERPROFILE\*") }
        }
    }

    # --- Dirottamento COM per utente (T1546.015) ----------------------------
    # Una CLSID registrata in HKCU con lo stesso ID di una di sistema in HKLM
    # "vince" su quella di sistema: il malware viene caricato da Explorer & co.
    # Si usa l'API .NET: con migliaia di CLSID i cmdlet del registro impiegano minuti.
    # Un programma registra spesso decine di CLSID con la stessa DLL: raggruppiamo per DLL.
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
                Add-InventoryItem 'Dirottamento COM' "$clsidRoot\$id\$srv" $val
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
            $score += 25; $why = @("$($g.Overrides) CLSID esistono anche a livello di sistema: la versione per-utente le sovrascrive (dirottamento COM)") + $why
        }
        $sev = ConvertTo-Severity $score
        if ($sev -eq 'Info') { continue }
        $ids = ($g.Ids | Select-Object -First 5) -join ', '
        if ($g.Ids.Count -gt 5) { $ids += " e altre $($g.Ids.Count - 5)" }
        Add-Finding -Category 'Dirottamento COM' -Severity $sev -Title "Oggetto COM per-utente: $([IO.Path]::GetFileName($risk.Target))" `
            -Detail "$($g.Root) - CLSID: $ids" -Path $risk.Target -Evidence $g.Command -Mitre 'T1546.015' -Reasons $why `
            -Recommendation 'Se la DLL non appartiene a un programma che hai installato (OneDrive, Teams, Dropbox... sono normali), elimina le chiavi CLSID indicate in HKCU.'
    }

    # --- Punti di avvio meno noti (profili PowerShell, BITS, Office, Winsock...) ---
    Invoke-ExtraAutorunPoints
}
