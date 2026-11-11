# Browser (T1176): estensioni installate, criteri che le forzano o dirottano la
# ricerca, collegamenti e processi del browser avviati con parametri da malware.
# Molti stealer e adware dei crack installano un'estensione e la "bloccano" con un
# criterio di Windows, cosi' non si puo' rimuovere dal browser.
# Si leggono solo i metadati delle estensioni: mai cronologia, cookie o password.

$script:ChromiumBrowsers = @(
    @{ Name = 'Google Chrome'; Local = 'Google\Chrome\User Data'; Page = 'chrome://extensions' }
    @{ Name = 'Microsoft Edge'; Local = 'Microsoft\Edge\User Data'; Page = 'edge://extensions' }
    @{ Name = 'Brave'; Local = 'BraveSoftware\Brave-Browser\User Data'; Page = 'brave://extensions' }
    @{ Name = 'Vivaldi'; Local = 'Vivaldi\User Data'; Page = 'vivaldi://extensions' }
    @{ Name = 'Chromium'; Local = 'Chromium\User Data'; Page = 'chrome://extensions' }
    @{ Name = 'Yandex'; Local = 'Yandex\YandexBrowser\User Data'; Page = 'browser://extensions' }
    @{ Name = 'Opera'; Roaming = 'Opera Software\Opera Stable'; Page = 'opera://extensions' }
    @{ Name = 'Opera GX'; Roaming = 'Opera Software\Opera GX Stable'; Page = 'opera://extensions' }
)

# Codici "location" di Chromium: come e' arrivata l'estensione
$script:ExtLocation = @{
    1 = @{ T = 'installata da te'; S = 0 }
    2 = @{ T = 'installata da un altro programma'; S = 20 }
    3 = @{ T = 'installata da un altro programma (registro)'; S = 20 }
    4 = @{ T = 'caricata da una cartella (modalita'' sviluppatore)'; S = 45 }
    6 = @{ T = 'installata da un altro programma'; S = 20 }
    7 = @{ T = 'imposta da un criterio di Windows'; S = 35 }
    8 = @{ T = 'caricata dalla riga di comando'; S = 60 }
    9 = @{ T = 'imposta da un criterio di Windows'; S = 35 }
}
$script:OfficialUpdate = '(?i)^https://(clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase/v1/crx|extension-updates\.opera\.com/|chromewebstore\.googleapis\.com/)'

# ConvertFrom-Json di PowerShell 5.1 non regge i file Preferences piu' grandi:
# JavaScriptSerializer senza limite di dimensione restituisce dizionari.
function Get-JsonSerializer {
    if (-not $script:JsonSerializer) {
        Add-Type -AssemblyName System.Web.Extensions
        $script:JsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $script:JsonSerializer.MaxJsonLength = [int]::MaxValue
    }
    return $script:JsonSerializer
}

function Read-JsonFile {
    param([string]$Path)
    try {
        # FileShare.ReadWrite: il browser puo' tenere il file aperto
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
        return (Get-JsonSerializer).DeserializeObject($text)
    } catch { return $null }
}

function Get-JsonNode {
    param($Node, [string[]]$Keys)
    foreach ($k in $Keys) {
        if ($Node -isnot [System.Collections.IDictionary] -or -not $Node.ContainsKey($k)) { return $null }
        $Node = $Node[$k]
    }
    return $Node
}

# Nome leggibile dal manifest, anche quando e' tradotto (__MSG_nome__)
function Get-ExtensionName {
    param($Manifest, [string]$Dir, [string]$Fallback)
    $name = $null
    if ($Manifest) { $name = [string]$Manifest['name'] }
    if ($name -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        $locales = @('it', [string]$Manifest['default_locale'], 'en', 'en_US') | Where-Object { $_ } | Select-Object -Unique
        foreach ($loc in $locales) {
            $msgs = Read-JsonFile (Join-Path $Dir "_locales\$loc\messages.json")
            if ($msgs) {
                $hit = $msgs.Keys | Where-Object { $_ -ieq $key } | Select-Object -First 1
                if ($hit) { $name = [string]$msgs[$hit]['message']; break }
            }
        }
    }
    if (-not $name -or $name -match '^__MSG_') { $name = $Fallback }
    return $name
}

function Get-PermissionRisk {
    param([string[]]$Permissions)
    $score = 0; $why = @()
    $p = @($Permissions | Where-Object { $_ })
    $allSites = @($p | Where-Object { $_ -match '^(<all_urls>|\*://\*/\*?|https?://\*/\*?|\*://\*\.?[^/]*/\*)$' }).Count -gt 0
    if ($allSites) {
        $score += 10; $why += 'Puo'' leggere e modificare tutte le pagine che visiti'
        if ($p -match '^(cookies|webRequest|webRequestBlocking|scripting|debugger)$') { $score += 10; $why += 'Ha accesso ai cookie o al traffico delle pagine: i cookie di sessione permettono di entrare nei tuoi account senza password' }
    }
    if ($p -contains 'debugger') { $score += 20; $why += 'Usa il permesso "debugger": puo'' controllare completamente le schede' }
    if ($p -contains 'nativeMessaging') { $score += 10; $why += 'Comunica con un programma installato sul PC' }
    if ($p -contains 'proxy') { $score += 15; $why += 'Puo'' deviare il traffico verso un proxy' }
    if ($p -contains 'management') { $score += 10; $why += 'Puo'' gestire e disattivare le altre estensioni (anche quelle di sicurezza)' }
    return @{ Score = $score; Reasons = $why }
}

function Get-ProfileRoots {
    # Tutti i profili utente se siamo amministratori, altrimenti solo il proprio
    $users = @()
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        if ($prof.Name -in 'Default', 'Default User', 'All Users', 'Public') { continue }
        $local = Join-Path $prof.FullName 'AppData\Local'
        if (Test-Path -LiteralPath $local -ErrorAction SilentlyContinue) { $users += [pscustomobject]@{ User = $prof.Name; Local = $local; Roaming = (Join-Path $prof.FullName 'AppData\Roaming') } }
    }
    if (-not $users) { $users += [pscustomobject]@{ User = $env:USERNAME; Local = $env:LOCALAPPDATA; Roaming = $env:APPDATA } }
    return $users
}

function Test-ChromiumProfile {
    param([string]$Browser, [string]$Page, [string]$ProfileDir, [string]$User)
    $cat = 'Browser'
    $settings = @{}
    foreach ($file in 'Preferences', 'Secure Preferences') {
        $s = Get-JsonNode (Read-JsonFile (Join-Path $ProfileDir $file)) 'extensions', 'settings'
        if ($s -is [System.Collections.IDictionary]) { foreach ($k in $s.Keys) { $settings[$k] = $s[$k] } }
    }
    $profileName = Split-Path $ProfileDir -Leaf
    foreach ($id in $settings.Keys) {
        $e = $settings[$id]
        if ($e -isnot [System.Collections.IDictionary] -or -not $e.ContainsKey('location')) { continue }   # residui di estensioni rimosse
        $loc = [int]$e['location']
        if ($loc -in 5, 10) { continue }   # componenti interni del browser

        # Cartella e manifest dell'estensione
        $rel = [string]$e['path']
        $dir = if ($rel -and [IO.Path]::IsPathRooted($rel)) { $rel } elseif ($rel) { Join-Path $ProfileDir "Extensions\$rel" } else { $null }
        $manifest = $null
        if ($dir) { $manifest = Read-JsonFile (Join-Path $dir 'manifest.json') }
        if (-not $manifest) { $manifest = $e['manifest'] }
        $name = Get-ExtensionName $manifest $dir $id
        $version = if ($manifest) { [string]$manifest['version'] } else { '' }

        $locInfo = $script:ExtLocation[$loc]
        $locText = if ($locInfo) { $locInfo.T } else { "origine $loc" }
        Add-InventoryItem $cat "$Browser | $User | $profileName | $id" "$name | $locText"

        $score = 0; $why = @()
        if ($locInfo -and $locInfo.S) { $score += $locInfo.S; $why += "Origine: $locText" }
        $update = if ($manifest) { [string]$manifest['update_url'] } else { '' }
        # from_webstore vale solo per il Chrome Web Store: le estensioni dello store di
        # Edge o Opera si riconoscono dal server di aggiornamento ufficiale.
        $fromStore = $e['from_webstore'] -or ($update -match $script:OfficialUpdate)
        $flagged = $e['blacklist_state'] -ge 1 -or (Get-JsonNode $e 'omaha_attributes', '_malware')
        $oddOrigin = ($loc -in 4, 7, 8, 9) -or -not $fromStore -or ($update -and $update -notmatch $script:OfficialUpdate)
        # Le estensioni da uno store ufficiale (anche se installate da un antivirus o una
        # VPN) restano solo in inventario: chiedere accesso ai siti e' normale per loro.
        if (-not $flagged -and -not $oddOrigin) { continue }
        if ($fromStore -and $loc -in 2, 3, 6) { $score -= 10 }
        if ($loc -eq 1 -and -not $fromStore) { $score += 30; $why += 'Non proviene da uno store ufficiale delle estensioni' }
        if ($loc -eq 4 -and $dir -and (Test-UserWritablePath "$dir\")) { $score += 10; $why += "Il codice sta in una cartella modificabile: $dir" }
        if ($update -and $update -notmatch $script:OfficialUpdate) { $score += 25; $why += "Si aggiorna da un server che non e' lo store: $update" }
        if ($flagged) { $score += 70; $why += 'Il browser l''ha segnalata come dannosa: e'' stata ritirata dallo store per malware' }

        # Permessi realmente concessi (active_permissions), o in mancanza quelli del manifest
        $perms = @()
        $ap = $e['active_permissions']
        if ($ap -is [System.Collections.IDictionary]) {
            foreach ($k in 'api', 'explicit_host', 'scriptable_host') { $perms += @($ap[$k] | Where-Object { $_ -is [string] }) }
        } elseif ($manifest) {
            $perms += @($manifest['permissions'] | Where-Object { $_ -is [string] })
            $perms += @($manifest['host_permissions'] | Where-Object { $_ -is [string] })
        }
        $pr = Get-PermissionRisk $perms
        $score += $pr.Score; $why += $pr.Reasons

        # disable_reasons: 1 = disattivata da te; altri valori = disattivata dal browser
        $reasons = @(@($e['disable_reasons']) | Where-Object { $_ -and [int]$_ -ne 0 } | ForEach-Object { [int]$_ })
        $disabled = ($e['state'] -eq 0) -or $reasons
        $byUser = $disabled -and (-not $reasons -or -not ($reasons | Where-Object { $_ -ne 1 }))
        if ($byUser) { $score -= 20; $why += "L'hai disattivata tu: non e' in funzione, ma e' ancora installata" }
        elseif ($disabled) { $score -= 10; $why += "Il browser l'ha disattivata: non e' in funzione, ma e' ancora installata. Se l'hai usata in passato, i dati a cui aveva accesso possono essere stati letti" }
        $installed = $null
        foreach ($t in $e['first_install_time'], $e['install_time']) {
            if ($t) { try { $installed = [DateTime]::FromFileTimeUtc([long]$t * 10).ToLocalTime(); break } catch { } }
        }
        if ($installed -and $installed -gt (Get-Date).AddDays(-30) -and $score -gt 0) { $score += 5; $why += "Installata il $($installed.ToString('dd/MM/yyyy'))" }

        # Un'estensione normale dallo store con accesso ai siti (AdBlock, password manager)
        # resta solo in inventario: si segnala da "da verificare" in su.
        $sev = ConvertTo-Severity $score
        if ($sev -in 'Info', 'Basso') { continue }
        $evidence = "ID $id" + $(if ($version) { " · versione $version" }) + " · $locText" + $(if ($installed) { " · installata il $($installed.ToString('dd/MM/yyyy'))" })
        Add-Finding -Category $cat -Severity $sev -Title "Estensione di $($Browser): $name" -Detail "Profilo $profileName di $User" `
            -Path $dir -Evidence $evidence -Mitre 'T1176' -Reasons $why `
            -Recommendation "Apri $Page nel browser e controlla l'estensione (l'ID si vede attivando la modalita' sviluppatore). Se non l'hai installata tu, rimuovila; se il pulsante Rimuovi e' bloccato, prima elimina il criterio che la impone (vedi le altre segnalazioni del browser). Poi cambia le password dei siti in cui eri connesso."
    }
}

function Test-FirefoxProfiles {
    param($Users)
    $cat = 'Browser'
    foreach ($u in $Users) {
        foreach ($prof in Get-ChildItem -LiteralPath (Join-Path $u.Roaming 'Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue) {
            $data = Read-JsonFile (Join-Path $prof.FullName 'extensions.json')
            if ($data -isnot [System.Collections.IDictionary]) { continue }
            foreach ($a in @($data['addons'])) {
                if ($a -isnot [System.Collections.IDictionary] -or $a['type'] -ne 'extension') { continue }
                $loc = [string]$a['location']
                if ($loc -in 'app-builtin', 'app-system-defaults', 'app-system-addons') { continue }
                $name = [string](Get-JsonNode $a 'defaultLocale', 'name'); if (-not $name) { $name = [string]$a['id'] }
                Add-InventoryItem $cat "Firefox | $($u.User) | $($prof.Name) | $($a['id'])" "$name | $loc"
                $score = 0; $why = @()
                if ([int]$a['signedState'] -le 0) { $score += 45; $why += 'Non firmata da Mozilla: Firefox normalmente le rifiuta' }
                if ($loc -in 'app-system-share', 'app-system-local', 'app-global') { $score += 30; $why += "Installata fuori dal profilo da un altro programma ($loc)" }
                $src = [string]$a['sourceURI']
                if ($src -and $src -notmatch '(?i)^https://addons\.(mozilla\.org|cdn\.mozilla\.net)/') { $score += 20; $why += "Scaricata da $src invece che da addons.mozilla.org" }
                $perms = @(Get-JsonNode $a 'userPermissions', 'permissions') + @(Get-JsonNode $a 'userPermissions', 'origins')
                $pr = Get-PermissionRisk $perms
                $score += $pr.Score; $why += $pr.Reasons
                if ($a['userDisabled'] -or -not $a['active']) { $score -= 20; $why += "E' disattivata" }
                $sev = ConvertTo-Severity $score
                if ($sev -in 'Info', 'Basso') { continue }
                Add-Finding -Category $cat -Severity $sev -Title "Estensione di Firefox: $name" -Detail "Profilo $($prof.Name) di $($u.User)" `
                    -Path $a['path'] -Evidence "ID $($a['id']) · versione $($a['version'])" -Mitre 'T1176' -Reasons $why `
                    -Recommendation 'Apri about:addons in Firefox e rimuovi l''estensione se non l''hai installata tu, poi cambia le password dei siti in cui eri connesso.'
            }
        }
    }
}

# Criteri di gruppo dei browser: estensioni forzate, ricerca e pagina iniziale
# imposte, proxy, strumenti per sviluppatori bloccati.
function Test-BrowserPolicies {
    $cat = 'Browser'
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'Tutti gli utenti' }) + @(Get-UserHives)
    $products = @(
        @{ Browser = 'Google Chrome'; Key = 'SOFTWARE\Policies\Google\Chrome' }
        @{ Browser = 'Microsoft Edge'; Key = 'SOFTWARE\Policies\Microsoft\Edge' }
        @{ Browser = 'Brave'; Key = 'SOFTWARE\Policies\BraveSoftware\Brave' }
        @{ Browser = 'Chromium'; Key = 'SOFTWARE\Policies\Chromium' }
    )
    foreach ($r in $roots) {
        foreach ($p in $products) {
            $base = "$($r.Root)\$($p.Key)"
            if (-not (Test-Path -LiteralPath $base)) { continue }
            $where = "$base ($($r.User))"

            # Estensioni imposte: ExtensionInstallForcelist ("id;url") ed ExtensionSettings (JSON)
            $forced = @()
            foreach ($v in Get-RegValues "$base\ExtensionInstallForcelist") {
                $parts = "$($v.Value)" -split ';', 2
                $forced += [pscustomobject]@{ Id = $parts[0].Trim(); Url = $(if ($parts.Count -gt 1) { $parts[1].Trim() }); Source = 'ExtensionInstallForcelist' }
            }
            $es = Get-RegValue $base 'ExtensionSettings'
            if ($es) {
                try {
                    $obj = (Get-JsonSerializer).DeserializeObject([string]$es)
                    foreach ($k in $obj.Keys) {
                        $s = $obj[$k]
                        if ($s -is [System.Collections.IDictionary] -and $s['installation_mode'] -in 'force_installed', 'normal_installed') {
                            $forced += [pscustomobject]@{ Id = $k; Url = [string]$s['update_url']; Source = 'ExtensionSettings' }
                        }
                    }
                } catch { }
            }
            foreach ($f in $forced) {
                Add-InventoryItem $cat "Criterio | $($p.Browser) | estensione $($f.Id)" "$($f.Url)"
                $official = (-not $f.Url) -or ($f.Url -match $script:OfficialUpdate)
                $sev = 'Medio'
                $why = @("L'estensione $($f.Id) e' installata d'obbligo da un criterio ($($f.Source)) e non si puo' rimuovere dal browser. Su un PC di casa non dovrebbe esserci nessun criterio del genere.")
                if (-not $official) { $sev = 'Alto'; $why += "Viene scaricata da un server che non e' lo store ufficiale: $($f.Url)" }
                Add-Finding -Category $cat -Severity $sev -Title "$($p.Browser): estensione imposta da un criterio" -Detail $where `
                    -Evidence "$($f.Id)$(if ($f.Url) { ';' + $f.Url })" -Mitre 'T1176' -Reasons $why `
                    -Recommendation "Cerca l'ID sullo store per capire cos'e'. Se non la riconosci, elimina il valore dalla chiave $base\ExtensionInstallForcelist (o da ExtensionSettings) con l'Editor del Registro, riavvia il browser e rimuovi l'estensione."
            }

            # Ricerca, pagina iniziale e nuova scheda imposte: dirottamento del browser
            $hijack = @()
            foreach ($n in 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderNewTabURL', 'HomepageLocation', 'NewTabPageLocation') {
                $val = Get-RegValue $base $n
                if ($val) { $hijack += "$n = $val" }
            }
            foreach ($v in Get-RegValues "$base\RestoreOnStartupURLs") { $hijack += "RestoreOnStartupURLs = $($v.Value)" }
            if ($hijack) {
                Add-InventoryItem $cat "Criterio | $($p.Browser) | ricerca e pagina iniziale" ($hijack -join ' ; ')
                Add-Finding -Category $cat -Severity 'Medio' -Title "$($p.Browser): ricerca o pagina iniziale imposte da un criterio" -Detail $where `
                    -Evidence ($hijack -join ' ; ') -Mitre 'T1176' `
                    -Reasons 'Un criterio impone motore di ricerca o pagine di avvio: e'' il modo con cui gli adware dirottano il browser e impediscono di cambiare le impostazioni.' `
                    -Recommendation "Se non l'hai impostato tu, elimina questi valori da $base e riavvia il browser."
            }

            # Proxy imposto e strumenti per sviluppatori bloccati
            $proxy = @('ProxyMode', 'ProxyServer', 'ProxyPacUrl', 'ProxySettings') | ForEach-Object { $v = Get-RegValue $base $_; if ($v) { "$_ = $v" } }
            if ($proxy -and ($proxy -notmatch 'ProxyMode = (direct|system)$' -or $proxy.Count -gt 1)) {
                Add-Finding -Category $cat -Severity 'Medio' -Title "$($p.Browser): proxy imposto da un criterio" -Detail $where -Evidence ($proxy -join ' ; ') -Mitre 'T1090' `
                    -Reasons 'Tutto il traffico del browser passa da un server deciso dal criterio: permette di spiarlo o modificarlo.'
            }
            $dev = Get-RegValue $base 'DeveloperToolsAvailability'
            if ($dev -eq 2) {
                Add-Finding -Category $cat -Severity 'Medio' -Title "$($p.Browser): strumenti per sviluppatori bloccati" -Detail $where -Evidence 'DeveloperToolsAvailability = 2' -Mitre 'T1562' `
                    -Reasons 'Alcuni malware bloccano gli strumenti per sviluppatori per impedire di vedere cosa fa la loro estensione.'
            }
        }
    }

    # Firefox: criteri nel registro o in distribution\policies.json
    $ffPolicy = @()
    foreach ($r in $roots) {
        foreach ($k in 'Extensions\Install', 'Extensions\Locked') {
            foreach ($v in Get-RegValues "$($r.Root)\SOFTWARE\Policies\Mozilla\Firefox\$k") { $ffPolicy += "$k = $($v.Value)" }
        }
    }
    foreach ($dir in "$env:ProgramFiles\Mozilla Firefox", "${env:ProgramFiles(x86)}\Mozilla Firefox") {
        $pj = Join-Path $dir 'distribution\policies.json'
        if (Test-Path -LiteralPath $pj) {
            $pol = Read-JsonFile $pj
            $ext = Get-JsonNode $pol 'policies', 'Extensions'
            $set = Get-JsonNode $pol 'policies', 'ExtensionSettings'
            if ($ext -or $set) { $ffPolicy += "policies.json: $pj" }
        }
    }
    if ($ffPolicy) {
        Add-InventoryItem $cat 'Criterio | Firefox | estensioni' ($ffPolicy -join ' ; ')
        Add-Finding -Category $cat -Severity 'Medio' -Title 'Firefox: estensioni imposte da un criterio' -Evidence ($ffPolicy -join ' ; ') -Mitre 'T1176' `
            -Reasons 'Un criterio installa o blocca estensioni in Firefox: su un PC di casa non dovrebbe esserci.' `
            -Recommendation 'Controlla about:policies in Firefox per vedere cosa impone il criterio.'
    }
}

# Collegamenti e processi del browser con parametri usati dal malware
$script:BrowserExe = '(?i)\\(chrome|msedge|brave|opera|launcher|vivaldi|firefox|browser)\.exe$'
$script:BrowserArgs = @(
    @{ Rx = '(?i)--load-extension'; S = 60; R = 'Carica un''estensione da una cartella a ogni avvio (--load-extension): tecnica tipica degli stealer' }
    @{ Rx = '(?i)--remote-debugging-(port|pipe)'; S = 50; R = 'Apre il controllo remoto del browser (--remote-debugging): permette a un altro programma di leggere cookie e pagine' }
    @{ Rx = '(?i)--headless'; S = 30; R = 'Browser senza finestra (--headless): lavora di nascosto' }
    @{ Rx = '(?i)--disable-extensions-except'; S = 30; R = 'Disattiva tutte le estensioni tranne una' }
    @{ Rx = '(?i)(?<!--app=)(?<!--app-url=)\bhttps?://'; S = 35; R = 'Apre un sito a ogni avvio: tecnica usata per dirottare la pagina iniziale' }
)

function Test-BrowserShortcutsAndProcesses {
    $cat = 'Browser'
    $dirs = @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
    foreach ($u in Get-ProfileRoots) {
        $userHome = Split-Path $u.Local -Parent | Split-Path -Parent
        $dirs += Join-Path $userHome 'Desktop'
        $dirs += Join-Path $userHome 'OneDrive\Desktop'
        $dirs += Join-Path $u.Roaming 'Microsoft\Windows\Start Menu\Programs'
        $dirs += Join-Path $u.Roaming 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
    }
    foreach ($d in $dirs | Sort-Object -Unique) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $d -Filter *.lnk -Recurse -Depth 1 -File -ErrorAction SilentlyContinue) {
            $lnk = Resolve-Shortcut $f.FullName
            if (-not $lnk -or $lnk.Target -notmatch $script:BrowserExe) { continue }
            $score = 0; $why = @()
            foreach ($a in $script:BrowserArgs) { if ($lnk.Arguments -match $a.Rx) { $score += $a.S; $why += $a.R } }
            if ($score -eq 0) { continue }
            Add-InventoryItem $cat "Collegamento | $($f.FullName)" "$($lnk.Target) $($lnk.Arguments)"
            Add-Finding -Category $cat -Severity (ConvertTo-Severity $score) -Title "Collegamento del browser modificato: $($f.Name)" -Path $f.FullName `
                -Evidence "$($lnk.Target) $($lnk.Arguments)" -Mitre 'T1176' -Reasons $why `
                -Recommendation 'Elimina il collegamento e ricrealo dal menu Start: i parametri aggiunti vengono applicati a ogni apertura del browser.'
        }
    }

    $procs = Get-ProcessTable
    $seen = @{}
    foreach ($p in $procs.Values) {
        if (-not $p.ExecutablePath -or $p.ExecutablePath -notmatch $script:BrowserExe -or -not $p.CommandLine) { continue }
        $score = 0; $why = @()
        foreach ($a in $script:BrowserArgs[0..3]) { if ($p.CommandLine -match $a.Rx) { $score += $a.S; $why += $a.R } }
        if ($score -eq 0) { continue }
        $key = "$($p.ExecutablePath)|$($why -join '|')"
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = 1
        $parent = $procs[[int]$p.ParentProcessId]
        $why += "Avviato da: $(if ($parent) { $parent.ExecutablePath } else { 'processo non piu'' attivo' })"
        $why += 'E'' normale solo se stai usando strumenti di automazione o sviluppo (Playwright, Selenium, Puppeteer)'
        Add-Finding -Category $cat -Severity (ConvertTo-Severity $score) -Title "Browser in esecuzione con parametri sospetti: $($p.Name) (PID $($p.ProcessId))" `
            -Path $p.ExecutablePath -Evidence $p.CommandLine -Mitre 'T1185' -Reasons $why `
            -Recommendation 'Se non stai usando strumenti di sviluppo, chiudi il browser, controlla quale programma l''ha avviato (riga "Avviato da") e cambia le password da un altro dispositivo.'
    }
}

function Invoke-CheckBrowser {
    $users = Get-ProfileRoots
    foreach ($u in $users) {
        foreach ($b in $script:ChromiumBrowsers) {
            $root = if ($b.Local) { Join-Path $u.Local $b.Local } else { Join-Path $u.Roaming $b.Roaming }
            if (-not (Test-Path -LiteralPath $root)) { continue }
            # Opera tiene il profilo nella cartella principale; gli altri in Default, Profile 1...
            $profiles = @()
            if (Test-Path -LiteralPath (Join-Path $root 'Preferences')) { $profiles += $root }
            foreach ($d in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                if ($d.Name -in 'System Profile', 'Guest Profile') { continue }
                if (Test-Path -LiteralPath (Join-Path $d.FullName 'Preferences')) { $profiles += $d.FullName }
            }
            foreach ($pd in $profiles) { Test-ChromiumProfile -Browser $b.Name -Page $b.Page -ProfileDir $pd -User $u.User }
        }
    }
    Test-FirefoxProfiles $users
    Test-BrowserPolicies
    Test-BrowserShortcutsAndProcesses
}
