# Punti di avvio meno noti, che i controlli classici (Run, attivita', servizi) non vedono.
# Li usano soprattutto gruppi APT e malware piu' curati, proprio perche' pochi li guardano.
# Fanno parte del controllo "Persistence": li chiama Invoke-CheckPersistence.

# Percorso del profilo di ogni utente, per SID (dal registro ProfileList)
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

# --- Cartella Esecuzione automatica spostata (T1547.001) ---------------------------
# Windows avvia tutto cio' che trova nella cartella indicata in "User Shell Folders":
# spostarla altrove nasconde i programmi a chi guarda la cartella solita.
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
    $cat = 'Avvio automatico'
    $profiles = Get-UserProfilePaths
    $targets = @()
    foreach ($hu in Get-UserHives) {
        $sid = $hu.Root -replace '^HKU:\\', ''
        $prof = $profiles[$sid]
        if (-not $prof -and $hu.Root -eq 'HKCU:') { $prof = $env:USERPROFILE }
        if (-not $prof) { continue }
        $targets += [pscustomobject]@{ Key = "$($hu.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer"; Name = 'Startup'; Profile = $prof; Common = $false; User = $hu.User }
    }
    $targets += [pscustomobject]@{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Name = 'Common Startup'; Profile = $null; Common = $true; User = 'Tutti gli utenti' }

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
            Add-Finding -Category $cat -Severity 'Alto' -Title "Cartella Esecuzione automatica spostata ($($t.User))" -Detail "$($t.Key)\$sub" `
                -Evidence "$($t.Name) = $raw" -Mitre 'T1547.001' `
                -Reasons "Windows avvia tutto cio' che si trova in questa cartella. Spostarla altrove nasconde i programmi che partono all'accensione." `
                -Recommendation "Riporta il valore $($t.Name) al percorso predefinito (...\Start Menu\Programs\Startup) e controlla i file nella cartella indicata."
            foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $cmd = "`"$($f.FullName)`""
                if ($f.Extension -eq '.lnk') { $lnk = Resolve-Shortcut $f.FullName; if ($lnk -and $lnk.Target) { $cmd = "`"$($lnk.Target)`" $($lnk.Arguments)" } }
                Register-AutorunEntry -Category $cat -Location "Cartella spostata: $dir" -Name $f.Name -Command $cmd -Mitre 'T1547.001' `
                    -ExtraScore 30 -ExtraReasons 'Si trova nella cartella Esecuzione automatica spostata'
            }
        }
    }
}

# --- Profili PowerShell (T1546.013) --------------------------------------------------
# Un profilo viene eseguito a ogni avvio di PowerShell, anche da parte di altri programmi.
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
        $score += 15; $reasons.Add('E'' il profilo valido per tutti gli utenti: quasi nessun programma lo usa')
    }
    if ($evidence -and $evidence.Length -gt 200) { $evidence = $evidence.Substring(0, 200) + '...' }
    return [pscustomobject]@{ Score = $score; Reasons = $reasons.ToArray(); Evidence = $evidence }
}

function Test-PowerShellProfiles {
    $cat = 'Avvio automatico'
    foreach ($p in Get-PowerShellProfilePaths) {
        $content = ''
        try { $content = [IO.File]::ReadAllText($p) } catch { continue }
        if ($content.Length -gt 262144) { $content = $content.Substring(0, 262144) }
        Add-InventoryItem $cat "Profilo PowerShell | $p" (Get-FileSha256 $p)
        $risk = Get-PowerShellProfileRisk -Path $p -Content $content
        $sev = ConvertTo-Severity $risk.Score
        if ($sev -eq 'Info') { continue }
        Add-Finding -Category $cat -Severity $sev -Title "Profilo PowerShell: $([IO.Path]::GetFileName($p))" -Path $p -Evidence $risk.Evidence `
            -Mitre 'T1546.013' -Reasons (@('Il profilo viene eseguito a ogni avvio di PowerShell, anche quando lo usano altri programmi') + @($risk.Reasons)) `
            -Recommendation "Apri il file con il Blocco note. Se non hai scritto tu quelle righe (o non vengono da uno strumento che usi, come oh-my-posh), cancellale."
    }
}

# --- Processi BITS con comando di notifica (T1197) ----------------------------------
# Un download BITS puo' eseguire un programma quando termina, e BITS lo riprova da solo
# per giorni: una persistenza che non compare tra i programmi in avvio automatico.
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
        # OWNER sta sulla stessa riga di TYPE e STATE
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
        Register-AutorunEntry -Category 'Avvio automatico' -Location "Processo BITS $($j.Guid) ($($j.Owner))" -Name "BITS: $($j.Name)" -Command $j.Command `
            -Mitre 'T1197' -ExtraScore 30 -ExtraReasons 'Processo BITS che esegue un comando: i programmi legittimi non lo fanno quasi mai' `
            -Recommendation "Se non riconosci il comando, annulla il processo da un prompt amministratore con: bitsadmin /cancel $($j.Guid)"
    }
}

# --- AppCertDlls (T1546.009) e database di compatibilita' (T1546.011) ----------------
function Test-AppCertAndShims {
    $cat = 'Avvio automatico'
    $acd = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    foreach ($v in Get-RegValues $acd) {
        if ($v.Value -isnot [string] -or -not $v.Value) { continue }
        Register-AutorunEntry -Category $cat -Location $acd -Name $v.Name -Command "`"$($v.Value)`"" -Mitre 'T1546.009' `
            -ExtraScore 40 -ExtraReasons 'AppCertDlls carica la DLL in ogni programma che avvia altri programmi: nessun software comune la usa'
    }
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags') {
        $k = Open-RegistryKey "$base\InstalledSDB"
        if (-not $k) { continue }
        foreach ($g in $k.GetSubKeyNames()) {
            $s = $k.OpenSubKey($g)
            $db = if ($s) { [string]$s.GetValue('DatabasePath') }
            if (-not $db) { continue }
            $desc = [string]$s.GetValue('DatabaseDescription')
            $title = if ($desc) { "Database di compatibilita': $desc" } else { "Database di compatibilita' $g" }
            Add-InventoryItem $cat "$base\InstalledSDB | $g" $db
            # I file .sdb non si possono firmare: conta dove si trovano. In AppPatch li mette
            # sdbinst, che richiede l'amministratore (anche IIS Express ne installa due).
            $inAppPatch = $db -like "$env:SystemRoot\AppPatch\*"
            $sev = if ($inAppPatch) { 'Basso' } else { 'Alto' }
            $why = @("Database di compatibilita' installato a parte: puo' far caricare una DLL dentro altri programmi")
            if (-not $inAppPatch) { $why += "Si trova fuori dalla cartella AppPatch di Windows, dove sdbinst li installa" }
            Add-Finding -Category $cat -Severity $sev -Title $title -Detail "$base\InstalledSDB\$g" -Path $db -Mitre 'T1546.011' -Reasons $why `
                -Recommendation "Se riconosci il programma nel nome (ad esempio IIS Express o un gioco vecchio) e' normale. Altrimenti rimuovilo da un prompt amministratore con: sdbinst -u `"$db`""
        }
    }
}

# --- Office (T1137) -----------------------------------------------------------------------
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
    $cat = 'Avvio automatico'
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'Tutti gli utenti' }) + @(Get-UserHives)
    foreach ($r in $roots) {
        # "Office test": carica una DLL a ogni avvio di Office, esiste solo per i test di Microsoft
        $ot = Open-RegistryKey "$($r.Root)\Software\Microsoft\Office test\Special\Perf"
        if ($ot -and $ot.GetValue('')) {
            Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Office test\Special\Perf" -Name 'Office test' `
                -Command "`"$($ot.GetValue(''))`"" -Mitre 'T1137.002' -ExtraScore 50 `
                -ExtraReasons "La chiave 'Office test' carica una DLL a ogni avvio di Office: serve solo ai test di Microsoft ed e' usata da gruppi APT"
        }
        # Componenti aggiuntivi COM e VSTO
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
                        # I manifest VSTO non sono firmabili come file: solo inventario
                        Add-InventoryItem $cat "$loc | $id" $manifest
                    } else {
                        $srv = Get-ComServerPath $id
                        if ($srv) { Register-AutorunEntry -Category $cat -Location $loc -Name "Componente di $($app): $id" -Command "`"$srv`"" -Mitre 'T1137.006' }
                        else { Add-InventoryItem $cat "$loc | $id" '(server COM non trovato)' }
                    }
                }
            }
        }
        if ($r.Root -eq 'HKLM:') { continue }
        # Componenti aggiuntivi di Excel caricati all'avvio (OPEN, OPEN1...)
        $off = Open-RegistryKey "$($r.Root)\Software\Microsoft\Office"
        if (-not $off) { continue }
        foreach ($ver in $off.GetSubKeyNames() | Where-Object { $_ -match '^\d+\.\d+$' }) {
            $opt = $off.OpenSubKey("$ver\Excel\Options")
            if (-not $opt) { continue }
            foreach ($n in $opt.GetValueNames() | Where-Object { $_ -match '^OPEN\d*$' }) {
                $path = ([string]$opt.GetValue($n) -replace '^/[A-Za-z]\s+', '').Trim('"', ' ')
                Register-AutorunEntry -Category $cat -Location "$($r.Root)\Software\Microsoft\Office\$ver\Excel\Options" -Name "Excel $n" `
                    -Command "`"$path`"" -Mitre 'T1137.006' -ExtraScore 10 -ExtraReasons 'Componente aggiuntivo caricato a ogni avvio di Excel'
            }
        }
    }
    # File aperti da soli all'avvio di Word ed Excel (modelli e componenti con macro)
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        foreach ($sub in 'Microsoft\Word\STARTUP', 'Microsoft\Excel\XLSTART') {
            $dir = Join-Path $prof.FullName "AppData\Roaming\$sub"
            foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
                Register-AutorunEntry -Category $cat -Location $dir -Name $f.Name -Command "`"$($f.FullName)`"" -Mitre 'T1137.001' `
                    -ExtraReasons "Office apre questo file da solo a ogni avvio: puo' contenere macro"
            }
        }
    }
}

# --- Provider Winsock (T1547) ------------------------------------------------------------
# Una DLL registrata come provider di rete viene caricata da ogni programma che usa
# internet e ne vede il traffico.
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
        if ($info.Exists -and -not $info.IsMicrosoft) { $extra = 15; $why = @('Provider di rete non Microsoft: viene caricato da ogni programma che usa internet') }
        Register-AutorunEntry -Category 'Avvio automatico' -Location 'Provider Winsock' -Name ([IO.Path]::GetFileName($p)) -Command "`"$p`"" `
            -Mitre 'T1547' -ExtraScore $extra -ExtraReasons $why `
            -Recommendation 'Se la DLL non appartiene a una VPN, a un firewall o a un antivirus che hai installato, ripristina Winsock con "netsh winsock reset" da un prompt amministratore.'
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
