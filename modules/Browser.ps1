# Browsers (T1176): installed extensions, policies that force them or hijack search,
# browser shortcuts and processes started with malware-style parameters.
# Many stealers and adware bundled with cracks install an extension and "lock" it with a
# Windows policy, so it cannot be removed from the browser.
# Only extension metadata is read: never history, cookies or passwords.

$script:ChromiumBrowsers = @(
    # Exe: the process to close before removing one of its extensions from the app
    @{ Name = 'Google Chrome'; Local = 'Google\Chrome\User Data'; Page = 'chrome://extensions'; Exe = 'chrome' }
    @{ Name = 'Microsoft Edge'; Local = 'Microsoft\Edge\User Data'; Page = 'edge://extensions'; Exe = 'msedge' }
    @{ Name = 'Brave'; Local = 'BraveSoftware\Brave-Browser\User Data'; Page = 'brave://extensions'; Exe = 'brave' }
    @{ Name = 'Vivaldi'; Local = 'Vivaldi\User Data'; Page = 'vivaldi://extensions'; Exe = 'vivaldi' }
    @{ Name = 'Chromium'; Local = 'Chromium\User Data'; Page = 'chrome://extensions'; Exe = 'chrome' }
    @{ Name = 'Yandex'; Local = 'Yandex\YandexBrowser\User Data'; Page = 'browser://extensions'; Exe = 'browser' }
    @{ Name = 'Opera'; Roaming = 'Opera Software\Opera Stable'; Page = 'opera://extensions'; Exe = 'opera' }
    @{ Name = 'Opera GX'; Roaming = 'Opera Software\Opera GX Stable'; Page = 'opera://extensions'; Exe = 'opera' }
)

# Chromium "location" codes: how the extension got there
$script:ExtLocation = @{
    1 = @{ T = 'installed by you'; S = 0 }
    2 = @{ T = 'installed by another program'; S = 20 }
    3 = @{ T = 'installed by another program (registry)'; S = 20 }
    4 = @{ T = 'loaded from a folder (developer mode)'; S = 45 }
    6 = @{ T = 'installed by another program'; S = 20 }
    7 = @{ T = 'forced by a Windows policy'; S = 35 }
    8 = @{ T = 'loaded from the command line'; S = 60 }
    9 = @{ T = 'forced by a Windows policy'; S = 35 }
}
$script:OfficialUpdate = '(?i)^https://(clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase/v1/crx|extension-updates\.opera\.com/|chromewebstore\.googleapis\.com/)'

# PowerShell 5.1's ConvertFrom-Json cannot handle the larger Preferences files:
# JavaScriptSerializer with no size limit returns dictionaries.
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
        # FileShare.ReadWrite: the browser may keep the file open
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

# Readable name from the manifest, even when it is localised (__MSG_name__)
function Get-ExtensionName {
    param($Manifest, [string]$Dir, [string]$Fallback)
    $name = $null
    if ($Manifest) { $name = [string]$Manifest['name'] }
    if ($name -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        $locales = @('en', 'en_US', [string]$Manifest['default_locale']) | Where-Object { $_ } | Select-Object -Unique
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
        $score += 10; $why += 'Can read and change every page you visit'
        if ($p -match '^(cookies|webRequest|webRequestBlocking|scripting|debugger)$') { $score += 10; $why += 'Has access to cookies or page traffic: session cookies let someone into your accounts without a password' }
    }
    if ($p -contains 'debugger') { $score += 20; $why += 'Uses the "debugger" permission: it can fully control your tabs' }
    if ($p -contains 'nativeMessaging') { $score += 10; $why += 'Talks to a program installed on the PC' }
    if ($p -contains 'proxy') { $score += 15; $why += 'Can route traffic through a proxy' }
    if ($p -contains 'management') { $score += 10; $why += 'Can manage and turn off other extensions (security ones too)' }
    return @{ Score = $score; Reasons = $why }
}

function Get-ProfileRoots {
    # Every user profile when running as administrator, otherwise only your own
    $users = @()
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        if ($prof.Name -in 'Default', 'Default User', 'All Users', 'Public') { continue }
        $local = Join-Path $prof.FullName 'AppData\Local'
        if (Test-Path -LiteralPath $local -ErrorAction SilentlyContinue) { $users += [pscustomobject]@{ User = $prof.Name; Local = $local; Roaming = (Join-Path $prof.FullName 'AppData\Roaming') } }
    }
    if (-not $users) { $users += [pscustomobject]@{ User = $env:USERNAME; Local = $env:LOCALAPPDATA; Roaming = $env:APPDATA } }
    return $users
}

# "Remove extension" from the app: moves its folder (or .xpi) away, the browser must be closed
function New-ExtensionRemedy {
    param([string]$Path, [string]$Browser, [string]$Exe, [string]$Id)
    if (-not $Path -or -not $Exe -or -not [IO.Path]::IsPathRooted($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    return @{ Kind = 'BrowserExtension'; Path = $Path; Browser = $Browser; Exe = $Exe; Id = $Id; Admin = -not ($Path -like "$env:USERPROFILE\*") }
}

function Test-ChromiumProfile {
    param([string]$Browser, [string]$Page, [string]$ProfileDir, [string]$User, [string]$Exe)
    $cat = 'Browsers'
    $settings = @{}
    foreach ($file in 'Preferences', 'Secure Preferences') {
        $s = Get-JsonNode (Read-JsonFile (Join-Path $ProfileDir $file)) 'extensions', 'settings'
        if ($s -is [System.Collections.IDictionary]) { foreach ($k in $s.Keys) { $settings[$k] = $s[$k] } }
    }
    $profileName = Split-Path $ProfileDir -Leaf
    foreach ($id in $settings.Keys) {
        $e = $settings[$id]
        if ($e -isnot [System.Collections.IDictionary] -or -not $e.ContainsKey('location')) { continue }   # leftovers of removed extensions
        $loc = [int]$e['location']
        if ($loc -in 5, 10) { continue }   # internal browser components

        # Extension folder and manifest
        $rel = [string]$e['path']
        $dir = if ($rel -and [IO.Path]::IsPathRooted($rel)) { $rel } elseif ($rel) { Join-Path $ProfileDir "Extensions\$rel" } else { $null }
        $manifest = $null
        if ($dir) { $manifest = Read-JsonFile (Join-Path $dir 'manifest.json') }
        if (-not $manifest) { $manifest = $e['manifest'] }
        $name = Get-ExtensionName $manifest $dir $id
        $version = if ($manifest) { [string]$manifest['version'] } else { '' }

        $locInfo = $script:ExtLocation[$loc]
        $locText = if ($locInfo) { $locInfo.T } else { "origin $loc" }
        Add-InventoryItem $cat "$Browser | $User | $profileName | $id" "$name | $locText"

        $score = 0; $why = @()
        if ($locInfo -and $locInfo.S) { $score += $locInfo.S; $why += "Origin: $locText" }
        $update = if ($manifest) { [string]$manifest['update_url'] } else { '' }
        # from_webstore only applies to the Chrome Web Store: extensions from the Edge or
        # Opera stores are recognised by the official update server.
        $fromStore = $e['from_webstore'] -or ($update -match $script:OfficialUpdate)
        $flagged = $e['blacklist_state'] -ge 1 -or (Get-JsonNode $e 'omaha_attributes', '_malware')
        $oddOrigin = ($loc -in 4, 7, 8, 9) -or -not $fromStore -or ($update -and $update -notmatch $script:OfficialUpdate)
        # Extensions from an official store (even when installed by an antivirus or a VPN)
        # stay in the inventory only: asking for access to websites is normal for them.
        if (-not $flagged -and -not $oddOrigin) { continue }
        if ($fromStore -and $loc -in 2, 3, 6) { $score -= 10 }
        if ($loc -eq 1 -and -not $fromStore) { $score += 30; $why += 'Does not come from an official extension store' }
        if ($loc -eq 4 -and $dir -and (Test-UserWritablePath "$dir\")) { $score += 10; $why += "The code is in a writable folder: $dir" }
        if ($update -and $update -notmatch $script:OfficialUpdate) { $score += 25; $why += "Updates from a server that is not the store: $update" }
        if ($flagged) { $score += 70; $why += 'The browser flagged it as harmful: it was pulled from the store for malware' }

        # Permissions actually granted (active_permissions), or else those in the manifest
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

        # disable_reasons: 1 = turned off by you; other values = turned off by the browser
        $reasons = @(@($e['disable_reasons']) | Where-Object { $_ -and [int]$_ -ne 0 } | ForEach-Object { [int]$_ })
        $disabled = ($e['state'] -eq 0) -or $reasons
        $byUser = $disabled -and (-not $reasons -or -not ($reasons | Where-Object { $_ -ne 1 }))
        if ($byUser) { $score -= 20; $why += 'You turned it off: it is not running, but it is still installed' }
        elseif ($disabled) { $score -= 10; $why += 'The browser turned it off: it is not running, but it is still installed. If you used it in the past, the data it had access to may have been read' }
        $installed = $null
        foreach ($t in $e['first_install_time'], $e['install_time']) {
            if ($t) { try { $installed = [DateTime]::FromFileTimeUtc([long]$t * 10).ToLocalTime(); break } catch { } }
        }
        if ($installed -and $installed -gt (Get-Date).AddDays(-30) -and $score -gt 0) { $score += 5; $why += "Installed on $($installed.ToString('yyyy-MM-dd'))" }

        # A normal store extension with access to websites (AdBlock, password managers)
        # stays in the inventory only: it is reported from "to review" upwards.
        $sev = ConvertTo-Severity $score
        if ($sev -in 'Info', 'Low') { continue }
        $evidence = "ID $id" + $(if ($version) { " · version $version" }) + " · $locText" + $(if ($installed) { " · installed on $($installed.ToString('yyyy-MM-dd'))" })
        Add-Finding -Category $cat -Severity $sev -Title "$Browser extension: $name" -Detail "Profile $profileName of $User" `
            -Path $dir -Evidence $evidence -Mitre 'T1176' -Reasons $why -Remedy (New-ExtensionRemedy $dir $Browser $Exe $id) `
            -Recommendation "Open $Page in the browser and check the extension (the ID shows up once you turn on developer mode). If you did not install it, remove it; if the Remove button is locked, first delete the policy that forces it (see the other browser findings). Then change the passwords of the sites you were signed in to."
    }
}

function Test-FirefoxProfiles {
    param($Users)
    $cat = 'Browsers'
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
                if ([int]$a['signedState'] -le 0) { $score += 45; $why += 'Not signed by Mozilla: Firefox normally refuses these' }
                if ($loc -in 'app-system-share', 'app-system-local', 'app-global') { $score += 30; $why += "Installed outside the profile by another program ($loc)" }
                $src = [string]$a['sourceURI']
                if ($src -and $src -notmatch '(?i)^https://addons\.(mozilla\.org|cdn\.mozilla\.net)/') { $score += 20; $why += "Downloaded from $src instead of addons.mozilla.org" }
                $perms = @(Get-JsonNode $a 'userPermissions', 'permissions') + @(Get-JsonNode $a 'userPermissions', 'origins')
                $pr = Get-PermissionRisk $perms
                $score += $pr.Score; $why += $pr.Reasons
                if ($a['userDisabled'] -or -not $a['active']) { $score -= 20; $why += 'It is turned off' }
                $sev = ConvertTo-Severity $score
                if ($sev -in 'Info', 'Low') { continue }
                Add-Finding -Category $cat -Severity $sev -Title "Firefox extension: $name" -Detail "Profile $($prof.Name) of $($u.User)" `
                    -Path $a['path'] -Evidence "ID $($a['id']) · version $($a['version'])" -Mitre 'T1176' -Reasons $why `
                    -Remedy (New-ExtensionRemedy ([string]$a['path']) 'Firefox' 'firefox' ([string]$a['id'])) `
                    -Recommendation 'Open about:addons in Firefox and remove the extension if you did not install it, then change the passwords of the sites you were signed in to.'
            }
        }
    }
}

# Browser group policies: forced extensions, imposed search and home page, proxy,
# blocked developer tools.
function Test-BrowserPolicies {
    $cat = 'Browsers'
    $roots = @([pscustomobject]@{ Root = 'HKLM:'; User = 'All users' }) + @(Get-UserHives)
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

            # Forced extensions: ExtensionInstallForcelist ("id;url") and ExtensionSettings (JSON)
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
                Add-InventoryItem $cat "Policy | $($p.Browser) | extension $($f.Id)" "$($f.Url)"
                $official = (-not $f.Url) -or ($f.Url -match $script:OfficialUpdate)
                $sev = 'Medium'
                $why = @("The extension $($f.Id) is force-installed by a policy ($($f.Source)) and cannot be removed from the browser. A home PC should have no such policy.")
                if (-not $official) { $sev = 'High'; $why += "It is downloaded from a server that is not the official store: $($f.Url)" }
                Add-Finding -Category $cat -Severity $sev -Title "$($p.Browser): extension forced by a policy" -Detail $where `
                    -Evidence "$($f.Id)$(if ($f.Url) { ';' + $f.Url })" -Mitre 'T1176' -Reasons $why `
                    -Recommendation "Search the ID on the store to see what it is. If you do not recognise it, delete the value from $base\ExtensionInstallForcelist (or from ExtensionSettings) with Registry Editor, restart the browser and remove the extension."
            }

            # Imposed search, home page and new tab: browser hijacking
            $hijack = @()
            foreach ($n in 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderNewTabURL', 'HomepageLocation', 'NewTabPageLocation') {
                $val = Get-RegValue $base $n
                if ($val) { $hijack += "$n = $val" }
            }
            foreach ($v in Get-RegValues "$base\RestoreOnStartupURLs") { $hijack += "RestoreOnStartupURLs = $($v.Value)" }
            if ($hijack) {
                Add-InventoryItem $cat "Policy | $($p.Browser) | search and home page" ($hijack -join ' ; ')
                Add-Finding -Category $cat -Severity 'Medium' -Title "$($p.Browser): search or home page forced by a policy" -Detail $where `
                    -Evidence ($hijack -join ' ; ') -Mitre 'T1176' `
                    -Reasons 'A policy imposes the search engine or start pages: this is how adware hijacks the browser and stops you from changing the settings.' `
                    -Recommendation "If you did not set it, delete these values from $base and restart the browser."
            }

            # Imposed proxy and blocked developer tools
            $proxy = @('ProxyMode', 'ProxyServer', 'ProxyPacUrl', 'ProxySettings') | ForEach-Object { $v = Get-RegValue $base $_; if ($v) { "$_ = $v" } }
            if ($proxy -and ($proxy -notmatch 'ProxyMode = (direct|system)$' -or $proxy.Count -gt 1)) {
                Add-Finding -Category $cat -Severity 'Medium' -Title "$($p.Browser): proxy forced by a policy" -Detail $where -Evidence ($proxy -join ' ; ') -Mitre 'T1090' `
                    -Reasons 'All browser traffic goes through a server chosen by the policy: it can be spied on or changed.'
            }
            $dev = Get-RegValue $base 'DeveloperToolsAvailability'
            if ($dev -eq 2) {
                Add-Finding -Category $cat -Severity 'Medium' -Title "$($p.Browser): developer tools blocked" -Detail $where -Evidence 'DeveloperToolsAvailability = 2' -Mitre 'T1562' `
                    -Reasons 'Some malware blocks the developer tools so nobody can see what its extension does.'
            }
        }
    }

    # Firefox: policies in the registry or in distribution\policies.json
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
        Add-InventoryItem $cat 'Policy | Firefox | extensions' ($ffPolicy -join ' ; ')
        Add-Finding -Category $cat -Severity 'Medium' -Title 'Firefox: extensions forced by a policy' -Evidence ($ffPolicy -join ' ; ') -Mitre 'T1176' `
            -Reasons 'A policy installs or locks extensions in Firefox: a home PC should not have one.' `
            -Recommendation 'Check about:policies in Firefox to see what the policy imposes.'
    }
}

# Browser shortcuts and processes with parameters used by malware
$script:BrowserExe = '(?i)\\(chrome|msedge|brave|opera|launcher|vivaldi|firefox|browser)\.exe$'
$script:BrowserArgs = @(
    @{ Rx = '(?i)--load-extension'; S = 60; R = 'Loads an extension from a folder at every start (--load-extension): a typical stealer technique' }
    @{ Rx = '(?i)--remote-debugging-(port|pipe)'; S = 50; R = 'Opens remote control of the browser (--remote-debugging): another program can read cookies and pages' }
    @{ Rx = '(?i)--headless'; S = 30; R = 'Browser without a window (--headless): it works hidden' }
    @{ Rx = '(?i)--disable-extensions-except'; S = 30; R = 'Turns off every extension except one' }
    @{ Rx = '(?i)(?<!--app=)(?<!--app-url=)\bhttps?://'; S = 35; R = 'Opens a website at every start: a technique used to hijack the home page' }
)

function Test-BrowserShortcutsAndProcesses {
    $cat = 'Browsers'
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
            Add-InventoryItem $cat "Shortcut | $($f.FullName)" "$($lnk.Target) $($lnk.Arguments)"
            Add-Finding -Category $cat -Severity (ConvertTo-Severity $score) -Title "Browser shortcut modified: $($f.Name)" -Path $f.FullName `
                -Evidence "$($lnk.Target) $($lnk.Arguments)" -Mitre 'T1176' -Reasons $why `
                -Recommendation 'Delete the shortcut and create it again from the Start menu: the added parameters apply every time the browser opens.'
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
        $why += "Started by: $(if ($parent) { $parent.ExecutablePath } else { 'a process that is no longer running' })"
        $why += 'Normal only if you are using automation or development tools (Playwright, Selenium, Puppeteer)'
        Add-Finding -Category $cat -Severity (ConvertTo-Severity $score) -Title "Browser running with suspicious parameters: $($p.Name) (PID $($p.ProcessId))" `
            -Path $p.ExecutablePath -Evidence $p.CommandLine -Mitre 'T1185' -Reasons $why `
            -Recommendation 'If you are not using development tools, close the browser, check which program started it (the "Started by" line) and change your passwords from another device.'
    }
}

function Invoke-CheckBrowser {
    $users = Get-ProfileRoots
    foreach ($u in $users) {
        foreach ($b in $script:ChromiumBrowsers) {
            $root = if ($b.Local) { Join-Path $u.Local $b.Local } else { Join-Path $u.Roaming $b.Roaming }
            if (-not (Test-Path -LiteralPath $root)) { continue }
            # Opera keeps the profile in the main folder; the others in Default, Profile 1...
            $profiles = @()
            if (Test-Path -LiteralPath (Join-Path $root 'Preferences')) { $profiles += $root }
            foreach ($d in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                if ($d.Name -in 'System Profile', 'Guest Profile') { continue }
                if (Test-Path -LiteralPath (Join-Path $d.FullName 'Preferences')) { $profiles += $d.FullName }
            }
            foreach ($pd in $profiles) { Test-ChromiumProfile -Browser $b.Name -Page $b.Page -ProfileDir $pd -User $u.User -Exe $b.Exe }
        }
    }
    Test-FirefoxProfiles $users
    Test-BrowserPolicies
    Test-BrowserShortcutsAndProcesses
}
