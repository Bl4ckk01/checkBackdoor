# Rete: porte in ascolto (backdoor "bind"), connessioni verso server di comando
# (C2), file hosts, proxy, regole del firewall, software di controllo remoto.

function Test-PublicIp {
    param([string]$Ip)
    if (-not $Ip -or $Ip -in '0.0.0.0', '::', '::1', '127.0.0.1') { return $false }
    if ($Ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|22[4-9]\.|23\d\.|255\.)') { return $false }
    if ($Ip -match '^(?i)(fe80:|fc|fd|ff|::ffff:(10|127|192\.168)\.)') { return $false }
    return $true
}

function Invoke-CheckNetwork {
    $cat = 'Rete'
    $procs = Get-ProcessTable

    # Porte usate di default da RAT noti e dai pool di mining
    $badPorts = @{
        4444 = 'Metasploit/Meterpreter'; 1604 = 'DarkComet'; 5552 = 'njRAT'; 1177 = 'njRAT'; 6606 = 'AsyncRAT'; 7707 = 'AsyncRAT'; 8808 = 'AsyncRAT'
        2404 = 'Remcos'; 3460 = 'Poison Ivy'; 54984 = 'QuasarRAT'; 4782 = 'QuasarRAT'; 1960 = 'NanoCore'; 3333 = 'pool di mining (stratum)'
        5555 = 'pool di mining / ADB'; 7777 = 'pool di mining'; 14444 = 'pool di mining Monero'; 45700 = 'pool di mining Monero'; 9999 = 'pool di mining'
        6666 = 'IRC botnet'; 6667 = 'IRC botnet'; 31337 = 'Back Orifice'; 12345 = 'NetBus'; 20000 = 'Millennium/RAT'
    }

    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Listen', 'Established' })
    $reported = @{}
    foreach ($c in $conns) {
        $p = $procs[[int]$c.OwningProcess]
        $path = $null; if ($p) { $path = $p.ExecutablePath }
        $pname = if ($p) { $p.Name } else { "PID $($c.OwningProcess)" }
        Add-InventoryItem $cat "$($c.State) | $pname | $($c.LocalPort)" "$($c.RemoteAddress):$($c.RemotePort) $path"
        if ($c.OwningProcess -le 4) { continue }   # System / Idle

        $info = $null; if ($path) { $info = Get-FileInfo $path }
        $isMs = $info -and $info.IsMicrosoft
        $unsigned = $info -and $info.Exists -and $info.SignatureStatus -ne 'Valid'
        # Molte app firmate (Discord, Roblox, Spotify...) vivono in AppData: conta solo se non firmato
        $userDir = $unsigned -and (Test-UserWritablePath $path)

        if ($c.State -eq 'Listen' -and $c.LocalAddress -notin '127.0.0.1', '::1') {
            if ($isMs) { continue }
            $score = 10; $why = @("Accetta connessioni dalla rete sulla porta $($c.LocalPort)")
            if ($unsigned) { $score += 25; $why += 'Programma non firmato' }
            if ($userDir) { $score += 20; $why += 'Programma in una cartella utente' }
            if ($badPorts.ContainsKey([int]$c.LocalPort)) { $score += 30; $why += "Porta usata di default da $($badPorts[[int]$c.LocalPort])" }
            $key = "L|$path|$($c.LocalPort)"
            if ($reported.ContainsKey($key)) { continue }; $reported[$key] = 1
            $sev = ConvertTo-Severity $score
            if ($sev -ne 'Info') {
                Add-Finding -Category $cat -Severity $sev -Title "$pname in ascolto sulla porta $($c.LocalPort)" -Path $path `
                    -Evidence "$($c.LocalAddress):$($c.LocalPort) (PID $($c.OwningProcess))" -Mitre 'T1571' -Reasons $why -Sha256 $info.Sha256 -Signer $info.Signer `
                    -Recommendation "Una backdoor 'bind' apre una porta e aspetta l'attaccante. Se non riconosci il programma, bloccalo nel firewall e analizzalo."
            }
        }
        elseif ($c.State -eq 'Established' -and (Test-PublicIp $c.RemoteAddress)) {
            if ($isMs) { continue }
            $score = 0; $why = @("Connesso a $($c.RemoteAddress):$($c.RemotePort)")
            if ($unsigned) { $score += 25; $why += 'Programma non firmato' }
            if ($userDir) { $score += 15; $why += 'Programma in una cartella utente' }
            if ($badPorts.ContainsKey([int]$c.RemotePort)) { $score += 35; $why += "Porta remota usata di default da $($badPorts[[int]$c.RemotePort])" }
            if ($p -and $p.Name -match '^(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$') {
                $score += 35; $why += "$($p.Name) non dovrebbe mantenere connessioni aperte verso internet"
            }
            $key = "E|$path|$($c.RemoteAddress)|$($c.RemotePort)"
            if ($reported.ContainsKey($key)) { continue }; $reported[$key] = 1
            $sev = ConvertTo-Severity $score
            if ($sev -ne 'Info') {
                Add-Finding -Category $cat -Severity $sev -Title "$pname connesso a $($c.RemoteAddress):$($c.RemotePort)" -Path $path `
                    -Evidence "PID $($c.OwningProcess) - $($p.CommandLine)" -Mitre 'T1071' -Reasons $why -Sha256 $info.Sha256 -Signer $info.Signer `
                    -Recommendation "Cerca l'indirizzo IP su abuseipdb.com o virustotal.com per capire a chi appartiene."
            }
        }
    }

    # --- File hosts (T1565.001): i malware bloccano siti di antivirus/update
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    $avDomains = '(?i)(microsoft|windowsupdate|virustotal|malwarebytes|kaspersky|eset|avast|avg|bitdefender|norton|mcafee|sophos|trendmicro|avira|f-secure|drweb|gridinsoft|hitmanpro|emsisoft|google|bing)'
    foreach ($line in Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        $parts = $l -split '\s+'
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0]; $names = $parts[1..($parts.Count - 1)]
        if ($names -contains 'localhost' -and $ip -in '127.0.0.1', '::1') { continue }
        Add-InventoryItem $cat "hosts | $($names -join ' ')" $ip
        $joined = $names -join ' '
        if ($joined -match $avDomains) {
            Add-Finding -Category $cat -Severity 'Alto' -Title "File hosts: reindirizza $joined" -Path $hosts -Evidence $l -Mitre 'T1565.001' `
                -Reasons "Redirigere domini di antivirus, Microsoft o motori di ricerca serve a impedire aggiornamenti e rimozione del malware (oppure a fare phishing). Attenzione: alcuni crack bloccano qui i server di attivazione." `
                -Recommendation 'Apri Blocco note come amministratore e rimuovi la riga dal file hosts.'
        } else {
            Add-Finding -Category $cat -Severity 'Basso' -Title "File hosts: voce personalizzata per $joined" -Path $hosts -Evidence $l -Mitre 'T1565.001' `
                -Reasons 'Voce aggiunta al file hosts. Spesso la aggiungono i crack per bloccare il controllo della licenza; verifica che sia voluta.'
        }
    }

    # --- Proxy: tutto il traffico web passerebbe da un server dell'attaccante
    foreach ($hu in Get-UserHives) {
        $is = "$($hu.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $en = Get-RegValue $is 'ProxyEnable'; $srv = Get-RegValue $is 'ProxyServer'; $pac = Get-RegValue $is 'AutoConfigURL'
        if ($en -eq 1 -and $srv) {
            Add-InventoryItem $cat "Proxy | $($hu.User)" $srv
            Add-Finding -Category $cat -Severity 'Medio' -Title "Proxy attivo per $($hu.User): $srv" -Detail $is -Evidence $srv -Mitre 'T1090' `
                -Reasons 'Un proxy impostato a tua insaputa permette di spiare o modificare il traffico web.' `
                -Recommendation 'Impostazioni > Rete e Internet > Proxy: disattivalo se non l''hai configurato tu (o il tuo antivirus/VPN).'
        }
        if ($pac) {
            Add-InventoryItem $cat "PAC | $($hu.User)" $pac
            Add-Finding -Category $cat -Severity 'Medio' -Title "Script di configurazione proxy (PAC) per $($hu.User)" -Detail $is -Evidence $pac -Mitre 'T1090' `
                -Reasons 'Un file PAC decide quali siti passano da un proxy: usato dai banking trojan per intercettare solo certi siti.'
        }
    }
    $winhttp = (netsh winhttp show proxy 2>$null) -join ' '
    if ($winhttp -match '(?i)Proxy Server\(s\)\s*:\s*(\S+)' -and $winhttp -notmatch '(?i)Direct access|Accesso diretto') {
        Add-Finding -Category $cat -Severity 'Medio' -Title "Proxy di sistema WinHTTP impostato: $($Matches[1])" -Evidence $winhttp -Mitre 'T1090' `
            -Reasons 'Il proxy WinHTTP e'' usato dai servizi di sistema (Windows Update, Defender).'
    }

    # --- Firewall: profili disattivati e regole in entrata per cartelle utente
    foreach ($prof in Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        if (-not $prof.Enabled) {
            Add-Finding -Category $cat -Severity 'Medio' -Title "Firewall disattivato per il profilo $($prof.Name)" -Mitre 'T1562.004' `
                -Reasons 'Molti malware disattivano il firewall per ricevere connessioni in entrata. (Normale solo se usi un firewall di terze parti.)' `
                -Recommendation 'Riattivalo da Sicurezza di Windows > Firewall e protezione rete.'
        }
    }
    $rulesKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    $rulesByApp = @{}
    foreach ($v in Get-RegValues $rulesKey) {
        $r = "$($v.Value)"
        if ($r -notmatch '\|Action=Allow\|' -or $r -notmatch '\|Active=TRUE\|' -or $r -notmatch '\|Dir=In\|') { continue }
        $app = ([regex]::Match($r, '\|App=([^|]+)')).Groups[1].Value
        if (-not $app) { continue }
        $appPath = [Environment]::ExpandEnvironmentVariables($app)
        $rname = ([regex]::Match($r, '\|Name=([^|]+)')).Groups[1].Value
        Add-InventoryItem $cat "Firewall | $rname" $appPath
        if (-not (Test-UserWritablePath $appPath)) { continue }
        $k = $appPath.ToLowerInvariant()
        if (-not $rulesByApp.ContainsKey($k)) { $rulesByApp[$k] = [pscustomobject]@{ Path = $appPath; Names = @() } }
        $rulesByApp[$k].Names += $rname
    }
    foreach ($g in $rulesByApp.Values) {
        $info = Get-FileInfo $g.Path
        # Regole orfane (programma disinstallato) o di programmi firmati: normali
        if (-not $info.Exists -or $info.SignatureStatus -eq 'Valid') { continue }
        Add-Finding -Category $cat -Severity 'Medio' -Title "Firewall: ingresso consentito a $([IO.Path]::GetFileName($g.Path))" -Path $g.Path `
            -Evidence (($g.Names | Sort-Object -Unique) -join ' ; ') -Mitre 'T1562.004' -Signer $info.Signer `
            -Reasons @('Regola che consente connessioni in entrata verso un programma in una cartella utente', "Programma non firmato ($($info.SignatureStatus))") `
            -Recommendation 'Molti giochi e server di gioco creano regole simili: rimuovi solo quelle di programmi che non riconosci (wf.msc > Regole connessioni in entrata).'
    }

    # --- Software di accesso remoto: legittimi, ma molto usati come RAT ------
    $remoteTools = '(?i)^(anydesk|teamviewer\w*|tv_[wx]\d+|rustdesk|screenconnect\.\w+|connectwisecontrol\.\w+|ngrok|radmin\w*|rserver3|winvnc\w*|tvnserver|vncserver|uvnc_service|ateraagent|splashtop\w*|srservice|remoting_host|meshagent\w*|client32|ammyy\w*|aa_v3|supremo\w*|dwagent|zohoassist\w*|simplehelp\w*|level\w*agent|tacticalrmm|netsupport\w*|parsec\w*|chrome_remote_desktop_host|remcos\w*)\.exe$'
    $seen = @{}
    foreach ($p in $procs.Values) {
        if ($p.Name -match $remoteTools -and -not $seen.ContainsKey($p.Name.ToLower())) {
            $seen[$p.Name.ToLower()] = 1
            $info = Get-FileInfo $p.ExecutablePath
            $sev = 'Medio'; if ($p.Name -match '(?i)client32|remcos') { $sev = 'Alto' }
            Add-Finding -Category $cat -Severity $sev -Title "Software di controllo remoto in esecuzione: $($p.Name)" -Path $p.ExecutablePath `
                -Evidence $p.CommandLine -Mitre 'T1219' -Sha256 $info.Sha256 -Signer $info.Signer `
                -Reasons @('Programmi legittimi di assistenza remota vengono spesso installati di nascosto per controllare il PC.', $(if ($p.Name -match '(?i)client32') { 'client32.exe e'' il client NetSupport, distribuito come RAT in molte campagne' })) `
                -Recommendation 'Se non l''hai installato tu consapevolmente, disinstallalo subito e cambia le password da un altro dispositivo.'
        }
    }
    foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if ($s.Name -match '(?i)^sshd$|^OpenSSH') {
            Add-Finding -Category $cat -Severity 'Medio' -Title "Server SSH installato ($($s.Name), $($s.State))" -Evidence $s.PathName -Mitre 'T1021.004' `
                -Reasons 'Un server SSH permette accesso remoto a riga di comando. Va bene solo se l''hai installato tu.'
        }
    }
}
