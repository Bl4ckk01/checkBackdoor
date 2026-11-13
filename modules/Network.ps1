# Network: listening ports ("bind" backdoors), connections to command servers (C2),
# hosts file, proxy, firewall rules, remote-control software.

function Test-PublicIp {
    param([string]$Ip)
    if (-not $Ip -or $Ip -in '0.0.0.0', '::', '::1', '127.0.0.1') { return $false }
    if ($Ip -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|22[4-9]\.|23\d\.|255\.)') { return $false }
    if ($Ip -match '^(?i)(fe80:|fc|fd|ff|::ffff:(10|127|192\.168)\.)') { return $false }
    return $true
}

function Invoke-CheckNetwork {
    $cat = 'Network'
    $procs = Get-ProcessTable

    # Ports used by default by well-known RATs and by mining pools
    $badPorts = @{
        4444 = 'Metasploit/Meterpreter'; 1604 = 'DarkComet'; 5552 = 'njRAT'; 1177 = 'njRAT'; 6606 = 'AsyncRAT'; 7707 = 'AsyncRAT'; 8808 = 'AsyncRAT'
        2404 = 'Remcos'; 3460 = 'Poison Ivy'; 54984 = 'QuasarRAT'; 4782 = 'QuasarRAT'; 1960 = 'NanoCore'; 3333 = 'mining pool (stratum)'
        5555 = 'mining pool / ADB'; 7777 = 'mining pool'; 14444 = 'Monero mining pool'; 45700 = 'Monero mining pool'; 9999 = 'mining pool'
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
        # Many signed apps (Discord, Roblox, Spotify...) live in AppData: it only counts when unsigned
        $userDir = $unsigned -and (Test-UserWritablePath $path)

        if ($c.State -eq 'Listen' -and $c.LocalAddress -notin '127.0.0.1', '::1') {
            if ($isMs) { continue }
            $score = 10; $why = @("Accepts connections from the network on port $($c.LocalPort)")
            if ($unsigned) { $score += 25; $why += 'Unsigned program' }
            if ($userDir) { $score += 20; $why += 'Program in a user folder' }
            if ($badPorts.ContainsKey([int]$c.LocalPort)) { $score += 30; $why += "Port used by default by $($badPorts[[int]$c.LocalPort])" }
            $key = "L|$path|$($c.LocalPort)"
            if ($reported.ContainsKey($key)) { continue }; $reported[$key] = 1
            $sev = ConvertTo-Severity $score
            if ($sev -ne 'Info') {
                Add-Finding -Category $cat -Severity $sev -Title "$pname listening on port $($c.LocalPort)" -Path $path `
                    -Evidence "$($c.LocalAddress):$($c.LocalPort) (PID $($c.OwningProcess))" -Mitre 'T1571' -Reasons $why -Sha256 $info.Sha256 -Signer $info.Signer `
                    -Recommendation "A 'bind' backdoor opens a port and waits for the attacker. If you do not recognise the program, block it in the firewall and analyse it."
            }
        }
        elseif ($c.State -eq 'Established' -and (Test-PublicIp $c.RemoteAddress)) {
            if ($isMs) { continue }
            $score = 0; $why = @("Connected to $($c.RemoteAddress):$($c.RemotePort)")
            if ($unsigned) { $score += 25; $why += 'Unsigned program' }
            if ($userDir) { $score += 15; $why += 'Program in a user folder' }
            if ($badPorts.ContainsKey([int]$c.RemotePort)) { $score += 35; $why += "Remote port used by default by $($badPorts[[int]$c.RemotePort])" }
            if ($p -and $p.Name -match '^(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$') {
                $score += 35; $why += "$($p.Name) should not keep connections open to the internet"
            }
            $key = "E|$path|$($c.RemoteAddress)|$($c.RemotePort)"
            if ($reported.ContainsKey($key)) { continue }; $reported[$key] = 1
            $sev = ConvertTo-Severity $score
            if ($sev -ne 'Info') {
                Add-Finding -Category $cat -Severity $sev -Title "$pname connected to $($c.RemoteAddress):$($c.RemotePort)" -Path $path `
                    -Evidence "PID $($c.OwningProcess) - $($p.CommandLine)" -Mitre 'T1071' -Reasons $why -Sha256 $info.Sha256 -Signer $info.Signer `
                    -Recommendation 'Look the IP address up on abuseipdb.com or virustotal.com to see who it belongs to.'
            }
        }
    }

    # --- hosts file (T1565.001): malware blocks antivirus and update sites
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
            Add-Finding -Category $cat -Severity 'High' -Title "hosts file: redirects $joined" -Path $hosts -Evidence $l -Mitre 'T1565.001' `
                -Reasons 'Redirecting antivirus, Microsoft or search engine domains prevents updates and removal of the malware (or enables phishing). Note: some cracks block activation servers here.' `
                -Recommendation 'Open Notepad as administrator and remove the line from the hosts file.'
        } else {
            Add-Finding -Category $cat -Severity 'Low' -Title "hosts file: custom entry for $joined" -Path $hosts -Evidence $l -Mitre 'T1565.001' `
                -Reasons 'Entry added to the hosts file. Cracks often add one to block the licence check; make sure it is intended.'
        }
    }

    # --- Proxy: all web traffic would go through an attacker's server
    foreach ($hu in Get-UserHives) {
        $is = "$($hu.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $en = Get-RegValue $is 'ProxyEnable'; $srv = Get-RegValue $is 'ProxyServer'; $pac = Get-RegValue $is 'AutoConfigURL'
        if ($en -eq 1 -and $srv) {
            Add-InventoryItem $cat "Proxy | $($hu.User)" $srv
            Add-Finding -Category $cat -Severity 'Medium' -Title "Proxy enabled for $($hu.User): $srv" -Detail $is -Evidence $srv -Mitre 'T1090' `
                -Reasons 'A proxy set without your knowledge allows spying on or altering web traffic.' `
                -Recommendation 'Settings > Network & internet > Proxy: turn it off if you (or your antivirus/VPN) did not set it.'
        }
        if ($pac) {
            Add-InventoryItem $cat "PAC | $($hu.User)" $pac
            Add-Finding -Category $cat -Severity 'Medium' -Title "Proxy auto-config script (PAC) for $($hu.User)" -Detail $is -Evidence $pac -Mitre 'T1090' `
                -Reasons 'A PAC file decides which sites go through a proxy: used by banking trojans to intercept only certain sites.'
        }
    }
    $winhttp = (netsh winhttp show proxy 2>$null) -join ' '
    if ($winhttp -match '(?i)Proxy Server\(s\)\s*:\s*(\S+)' -and $winhttp -notmatch '(?i)Direct access|Accesso diretto') {
        Add-Finding -Category $cat -Severity 'Medium' -Title "WinHTTP system proxy set: $($Matches[1])" -Evidence $winhttp -Mitre 'T1090' `
            -Reasons 'The WinHTTP proxy is used by system services (Windows Update, Defender).'
    }

    # --- Firewall: disabled profiles and inbound rules for user folders
    foreach ($prof in Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        if (-not $prof.Enabled) {
            Add-Finding -Category $cat -Severity 'Medium' -Title "Firewall disabled for the $($prof.Name) profile" -Mitre 'T1562.004' `
                -Reasons 'A lot of malware turns the firewall off to receive inbound connections. (Normal only if you use a third-party firewall.)' `
                -Recommendation 'Turn it back on from Windows Security > Firewall & network protection.'
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
        # Orphan rules (program uninstalled) or rules for signed programs: normal
        if (-not $info.Exists -or $info.SignatureStatus -eq 'Valid') { continue }
        Add-Finding -Category $cat -Severity 'Medium' -Title "Firewall: inbound allowed to $([IO.Path]::GetFileName($g.Path))" -Path $g.Path `
            -Evidence (($g.Names | Sort-Object -Unique) -join ' ; ') -Mitre 'T1562.004' -Signer $info.Signer `
            -Reasons @('Rule that allows inbound connections to a program in a user folder', "Unsigned program ($($info.SignatureStatus))") `
            -Recommendation 'Many games and game servers create similar rules: remove only those for programs you do not recognise (wf.msc > Inbound Rules).'
    }

    # --- Remote-access software: legitimate, but widely used as RATs ----------------
    $remoteTools = '(?i)^(anydesk|teamviewer\w*|tv_[wx]\d+|rustdesk|screenconnect\.\w+|connectwisecontrol\.\w+|ngrok|radmin\w*|rserver3|winvnc\w*|tvnserver|vncserver|uvnc_service|ateraagent|splashtop\w*|srservice|remoting_host|meshagent\w*|client32|ammyy\w*|aa_v3|supremo\w*|dwagent|zohoassist\w*|simplehelp\w*|level\w*agent|tacticalrmm|netsupport\w*|parsec\w*|chrome_remote_desktop_host|remcos\w*)\.exe$'
    $seen = @{}
    foreach ($p in $procs.Values) {
        if ($p.Name -match $remoteTools -and -not $seen.ContainsKey($p.Name.ToLower())) {
            $seen[$p.Name.ToLower()] = 1
            $info = Get-FileInfo $p.ExecutablePath
            $sev = 'Medium'; if ($p.Name -match '(?i)client32|remcos') { $sev = 'High' }
            Add-Finding -Category $cat -Severity $sev -Title "Remote-control software running: $($p.Name)" -Path $p.ExecutablePath `
                -Evidence $p.CommandLine -Mitre 'T1219' -Sha256 $info.Sha256 -Signer $info.Signer `
                -Reasons @('Legitimate remote-support programs are often installed secretly to control the PC.', $(if ($p.Name -match '(?i)client32') { 'client32.exe is the NetSupport client, distributed as a RAT in many campaigns' })) `
                -Recommendation 'If you did not knowingly install it, uninstall it right away and change your passwords from another device.'
        }
    }
    foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if ($s.Name -match '(?i)^sshd$|^OpenSSH') {
            Add-Finding -Category $cat -Severity 'Medium' -Title "SSH server installed ($($s.Name), $($s.State))" -Evidence $s.PathName -Mitre 'T1021.004' `
                -Reasons 'An SSH server allows remote command-line access. Fine only if you installed it yourself.'
        }
    }
}
