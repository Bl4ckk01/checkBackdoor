# Command-line analysis: which program an autostart entry or process really runs,
# and how suspicious its command line is (the risk score used by every check).


$script:ExecExtensions = 'exe|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|dll|scr|cpl|msc|hta|lnk|sys|jar|pif|ocx'

function Resolve-CommandPath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $cmd = $cmd -replace '^\\\?\?\\', ''
    $cmd = $cmd -replace '^(?i)\\SystemRoot\\', "$env:SystemRoot\"
    if ($cmd -match '^(?i)system32\\') { $cmd = Join-Path $env:SystemRoot $cmd }

    $candidate = $null
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { $candidate = $cmd.Substring(1, $end - 1) } else { $candidate = $cmd.Trim('"') }
    } else {
        $m = [regex]::Match($cmd, "^(?i)(.+?\.($script:ExecExtensions))(?=\s|,|`"|$)")
        if ($m.Success) { $candidate = $m.Groups[1].Value } else { $candidate = ($cmd -split '\s+')[0] }
    }
    if (-not $candidate) { return $null }

    if (-not [IO.Path]::IsPathRooted($candidate)) {
        foreach ($dir in @("$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\System32\wbem", "$env:SystemRoot\System32\WindowsPowerShell\v1.0")) {
            $p = Join-Path $dir $candidate
            if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
            if (-not [IO.Path]::HasExtension($candidate) -and (Test-Path -LiteralPath "$p.exe" -PathType Leaf)) { return "$p.exe" }
        }
        $c = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    return $candidate
}

# Returns the files named in the arguments (e.g. the DLL passed to rundll32 or the
# script passed to wscript), which are the real "payload" to analyse.
function Get-EmbeddedPaths {
    param([string]$CommandLine)
    if (-not $CommandLine) { return @() }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine)
    $found = New-Object System.Collections.Generic.List[string]
    $rx = "(?i)([A-Z]:\\[^`"*?<>|,]+?\.($script:ExecExtensions))(?=[\s,`"']|$)"
    foreach ($m in [regex]::Matches($cmd, $rx)) { $found.Add($m.Groups[1].Value) }
    return $found
}

$script:SuspiciousPatterns = @(
    @{ Rx = '(?i)\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}'; S = 45; R = 'PowerShell with a command hidden in Base64 (-EncodedCommand)' }
    @{ Rx = '(?i)-w(indowstyle)?\s+h(idden)?\b'; S = 20; R = 'Runs in a hidden window' }
    @{ Rx = '(?i)\b(iex|invoke-expression)\b'; S = 30; R = 'Runs code generated on the fly (Invoke-Expression)' }
    @{ Rx = '(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b)'; S = 35; R = 'Downloads content from the internet' }
    @{ Rx = '(?i)frombase64string'; S = 25; R = 'Decodes Base64 data' }
    @{ Rx = '(?i)-(nop|noprofile)\b.*-(ep|executionpolicy)\s+bypass|-(ep|executionpolicy)\s+bypass'; S = 15; R = 'Bypasses the PowerShell execution policy' }
    @{ Rx = '(?i)mshta(\.exe)?["'']?\s+["'']?(https?|javascript|vbscript|about):'; S = 50; R = 'mshta runs a remote or inline script (LOLBin technique)' }
    @{ Rx = '(?i)regsvr32(\.exe)?.*/i:\s*["'']?https?'; S = 50; R = 'regsvr32 loads a remote scriptlet ("Squiblydoo" technique)' }
    @{ Rx = '(?i)rundll32(\.exe)?["'']?\s+.*(javascript:|vbscript:|mshtml,RunHTMLApplication)'; S = 50; R = 'rundll32 used to run a script (LOLBin technique)' }
    @{ Rx = '(?i)certutil(\.exe)?.*\s[-/](urlcache|decode|decodehex)'; S = 45; R = 'certutil used to download or decode files' }
    @{ Rx = '(?i)bitsadmin(\.exe)?.*/(transfer|addfile|SetNotifyCmdLine)'; S = 35; R = 'bitsadmin used to download files or run commands' }
    @{ Rx = '(?i)https?://\d{1,3}(\.\d{1,3}){3}'; S = 30; R = 'Contacts a bare IP address instead of a domain' }
    @{ Rx = '(?i)(pastebin\.com|paste\.ee|transfer\.sh|discord(app)?\.com/api/webhooks|cdn\.discordapp\.com/attachments|api\.telegram\.org/bot|ngrok\.(io|app)|trycloudflare\.com|anonfiles|gofile\.io|temp\.sh|file\.io)'; S = 30; R = 'Uses a service often abused by malware to fetch payloads or send data' }
    @{ Rx = '(?i)(stratum\+(tcp|ssl)|--donate-level|xmrig|nicehash|nanopool|moneroocean|--cpu-max-threads-hint|\s-o\s+\S+:\d{3,5}\s.*-u\s)'; S = 60; R = 'Typical cryptominer parameters (XMRig and similar)' }
    @{ Rx = '(?i)(wscript|cscript)(\.exe)?["'']?\s+.*\\(appdata|temp|programdata|users\\public)\\'; S = 25; R = 'VBS/JS script run from a user folder' }
    @{ Rx = '(?i)(add-mppreference|set-mppreference|DisableRealtimeMonitoring|ExclusionPath)'; S = 55; R = 'Changes Microsoft Defender settings' }
    @{ Rx = '(?i)schtasks(\.exe)?.*/create'; S = 20; R = 'Creates a scheduled task in turn' }
    @{ Rx = '(?i)(vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*(recoveryenabled|safeboot))'; S = 55; R = 'Deletes backups or changes how Windows boots' }
    @{ Rx = '(?i)\\(appdata|temp)\\[^\\]+\.(vbs|vbe|js|jse|wsf|hta)\b'; S = 20; R = 'Script directly in AppData/Temp' }
    @{ Rx = '(?i)(netsh.*firewall.*(add|set).*allow|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)'; S = 40; R = 'Changes the Windows firewall' }
)

function Get-CommandRisk {
    param([string]$CommandLine)
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $target = Resolve-CommandPath $CommandLine
    $sha = $null; $signer = $null

    # The program launched first, then the files named in the arguments (no duplicates)
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($target) + @(Get-EmbeddedPaths $CommandLine)) {
        if ($f -and -not ($files -contains $f)) { $files.Add($f) }
    }

    # When the program is a system "host" (rundll32, wscript...) the real payload is
    # the file passed as an argument.
    $hostNames = 'rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|mshta\.exe|powershell\.exe|pwsh\.exe|cmd\.exe|conhost\.exe|javaw?\.exe|msiexec\.exe'
    $payloadFound = $false

    $fileScoreMax = 0
    foreach ($f in $files) {
        $fs = 0
        if (-not [IO.Path]::IsPathRooted($f)) { continue }
        $info = Get-FileInfo $f
        if (-not $info.Exists) {
            $fs += 10
            $reasons.Add("The file no longer exists: $f (orphan entry, or the file was deleted after starting)")
        } else {
            $isHost = [IO.Path]::GetFileName($f) -match "^($hostNames)$"
            if (-not $isHost -and -not $payloadFound) {
                $payloadFound = $true
                $target = $f; $sha = $info.Sha256; $signer = $info.Signer
            } elseif (-not $sha) {
                $sha = $info.Sha256; $signer = $info.Signer
            }
            if ($info.IsMicrosoft) { continue }
            $isScript = $f -match '(?i)\.(vbs|vbe|js|jse|wsf|wsh|ps1|bat|cmd|hta)$'
            $userWritable = Test-UserWritablePath $f
            # A script in Program Files/Windows can only be changed by an administrator
            if ($isScript -and -not $userWritable) { continue }
            switch ($info.SignatureStatus) {
                'Valid' { }
                'NotSigned' { $fs += 25; $reasons.Add("Not digitally signed: $f") }
                'HashMismatch' { $fs += 50; $reasons.Add("Tampered digital signature (the file was changed after signing): $f") }
                default { $fs += 30; $reasons.Add("Invalid digital signature ($($info.SignatureStatus)): $f") }
            }
            if ($isScript) { $fs += 10; $reasons.Add("It is a script, not a signable program: $f") }
            if ($userWritable) {
                if ($info.SignatureStatus -eq 'Valid') { $fs += 5 }
                else { $fs += 20; $reasons.Add("Located in a user or temporary folder (AppData, Temp, ProgramData...): $f") }
            }
            if ($info.Hidden) { $fs += 15; $reasons.Add("The file has the hidden/system attribute: $f") }
            if ($info.SignatureStatus -ne 'Valid' -and (Test-RandomLookingName $f)) { $fs += 15; $reasons.Add("Random-looking file name: $f") }
            if ($info.SignatureStatus -ne 'Valid' -and $info.Created -and $info.Created -gt (Get-Date).AddDays(-30)) {
                $fs += 5; $reasons.Add("Created in the last 30 days ($($info.Created.ToString('yyyy-MM-dd')))")
            }
            if ($info.SignatureStatus -ne 'Valid' -and -not $info.Company -and -not $isScript) {
                $fs += 5; $reasons.Add('No publisher in the file properties')
            }
        }
        if ($fs -gt $fileScoreMax) { $fileScoreMax = $fs }
    }
    $score += $fileScoreMax

    foreach ($p in $script:SuspiciousPatterns) {
        if ($CommandLine -match $p.Rx) { $score += $p.S; $reasons.Add($p.R) }
    }

    return [pscustomobject]@{
        Score = $score; Reasons = $reasons.ToArray(); Target = $target; Sha256 = $sha; Signer = $signer
    }
}

