# Suspicious files in the folders where malware installs itself without needing
# privileges: AppData, Temp, ProgramData, Public. Looks for unsigned executables,
# scripts, hidden files and alternate data streams (ADS).

function Invoke-CheckFileSystem {
    param([switch]$Deep)
    $cat = 'Suspicious files'

    $roots = New-Object System.Collections.Generic.List[object]
    foreach ($prof in Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        if ($prof.Name -in 'Default', 'Default User', 'All Users') { continue }
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Roaming'; D = 3 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Local'; D = 2 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\Local\Temp'; D = 3 })
        $roots.Add(@{ P = Join-Path $prof.FullName 'AppData\LocalLow'; D = 3 })
    }
    $roots.Add(@{ P = $env:ProgramData; D = 2 })
    $roots.Add(@{ P = "$env:SystemDrive\Users\Public"; D = 3 })
    $roots.Add(@{ P = "$env:SystemRoot\Temp"; D = 3 })
    $roots.Add(@{ P = "$env:SystemDrive\PerfLogs"; D = 3 })
    $roots.Add(@{ P = "$env:SystemRoot\Tasks"; D = 1 })
    $roots.Add(@{ P = "$env:SystemDrive\Intel"; D = 2 })
    $roots.Add(@{ P = "$env:SystemDrive\`$Recycle.Bin"; D = 3 })

    # Caches, libraries and app resources: tens of thousands of legitimate .js/.exe files
    $skipDirs = '(?i)\\(Packages|Microsoft\\(Edge|WindowsApps|Teams|OneDrive|Windows\\(INetCache|WebCache|Explorer|Caches|WER))|Google\\Chrome|BraveSoftware|Mozilla\\Firefox\\Profiles|Opera Software|npm-cache|npm|pip|pnpm|yarn|NuGet|\.vscode|\.git|Code\\(Cache|CachedData)|htmlcache|CrashDumps|D3DSCache|DXCache|GLCache|Package Cache|assembly|Docker|JetBrains|Python\d*|node_modules|site-packages|resources\\app|Windows Defender|Windows\\Recent|Office\\Recent|cache|Cache|Code Cache|GPUCache|Service Worker|IndexedDB|Local Storage|dist|lib)$'
    $binExt = '(?i)\.(exe|scr|cpl|jar|lnk)$'
    $scriptExt = '(?i)\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)$'
    $scriptMaxDepth = 1
    if ($Deep) {
        $binExt = '(?i)\.(exe|dll|sys|scr|pif|com|cpl|ocx|jar|lnk)$'
        $scriptMaxDepth = 3
        foreach ($r in $roots) { $r.D = 8 }
    }

    $count = 0
    foreach ($r in $roots) {
        if (-not [IO.Directory]::Exists($r.P)) { continue }
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([pscustomobject]@{ Dir = $r.P; Depth = 0 })
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()
            if ($item.Dir -match $skipDirs) { continue }
            $entries = $null
            try { $entries = ([IO.DirectoryInfo]$item.Dir).GetFileSystemInfos() } catch { continue }
            foreach ($e in $entries) {
                if ($e -is [IO.DirectoryInfo]) {
                    if ($item.Depth -lt $r.D -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        $queue.Enqueue([pscustomobject]@{ Dir = $e.FullName; Depth = $item.Depth + 1 })
                    }
                    continue
                }
                $isBin = $e.Name -match $binExt
                $isScript = $item.Depth -le $scriptMaxDepth -and $e.Name -match $scriptExt
                if (-not ($isBin -or $isScript)) { continue }
                $count++
                Test-SuspiciousFile -File $e -Depth $item.Depth -Category $cat
            }
        }
    }
    Add-InventoryItem $cat 'Executable files examined' "$count"
}

function Test-SuspiciousFile {
    param($File, [int]$Depth, [string]$Category)
    $path = $File.FullName
    $ext = $File.Extension.ToLower()
    $score = 0; $why = @()

    if ($ext -eq '.lnk') {
        # Shortcuts in system folders that launch command interpreters
        $lnk = Resolve-Shortcut $path
        if ($lnk -and $lnk.Target) {
            $risk = Get-CommandRisk "`"$($lnk.Target)`" $($lnk.Arguments)"
            if ($risk.Score -ge 35 -and $risk.Reasons -match 'PowerShell|mshta|rundll32|regsvr32|Base64|internet|script') {
                Add-Finding -Category $Category -Severity (ConvertTo-Severity $risk.Score) -Title "Suspicious shortcut: $($File.Name)" -Path $path `
                    -Evidence "$($lnk.Target) $($lnk.Arguments)" -Mitre 'T1547.009' -Reasons $risk.Reasons
            }
        }
        return
    }

    $hidden = [bool]($File.Attributes -band ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
    $isScript = $ext -match '^\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)$'
    $recent = $File.CreationTime -gt (Get-Date).AddDays(-30)

    if ($isScript) {
        # Scripts in AppData/ProgramData are rare; in Temp they are often installer leftovers
        $score += 15; $why += 'Script in a user folder'
        if ($ext -match '^\.(vbs|vbe|js|jse|wsf|hta)$') { $score += 15; $why += 'VBScript/JScript/HTA: formats used almost only by malware nowadays' }
        if ($File.Length -lt 2MB) {
            $text = $null
            try { $text = [IO.File]::ReadAllText($path) } catch { }
            if ($text) {
                foreach ($p in $script:SuspiciousPatterns) {
                    if ($text -match $p.Rx) { $score += [int]($p.S / 2); $why += "Content: $($p.R)" }
                }
                if ($text -match '(?i)(chr\(\d+\)\s*&\s*){10,}|(\[char\]\d+\s*\+\s*){10,}|[A-Za-z0-9+/]{400,}={0,2}') {
                    $score += 25; $why += 'Obfuscated content (long Base64 strings or chains of characters)'
                }
            }
        }
    } else {
        $info = Get-FileInfo $path
        if ($info.IsMicrosoft -or $info.SignatureStatus -eq 'Valid') {
            # Signed: reported only when hidden in an odd location
            if ($hidden -and $Depth -eq 0) {
                $score += 15; $why += 'Signed executable but hidden in a user folder'
            }
        } else {
            $score += 15; $why += "Unsigned executable ($($info.SignatureStatus))"
            if ($info.SignatureStatus -eq 'HashMismatch') { $score += 40; $why += 'Tampered signature' }
            if ($Depth -eq 0) { $score += 15; $why += 'Located directly in the root of AppData/ProgramData/Temp instead of a program folder' }
            if (-not $info.Company -and -not $info.Description) { $score += 5; $why += 'No publisher information' }
            if (Test-RandomLookingName $path) { $score += 15; $why += 'Random name' }
            if ($path -match '(?i)\\(Microsoft|Windows|Intel|NVIDIA|Google|Adobe)\\[^\\]+$' -and $Depth -le 2) {
                $score += 10; $why += 'Unsigned but in a folder that imitates a well-known vendor'
            }
            if ($File.Name -match '^(?i)(svchost|csrss|lsass|winlogon|services|smss|explorer|dllhost|conhost|taskhostw|runtimebroker|spoolsv|wininit|ctfmon|dwm)\.exe$') {
                $score += 50; $why += 'Uses the name of a system process outside System32'
            }
            if ($path -match '(?i)\\\$Recycle\.Bin\\') { $score += 20; $why += 'Executable in the Recycle Bin (a location used to hide)' }
            if ($path -match '(?i)\\AppData\\Local\\Temp\\' -and $Depth -ge 1) { $score -= 10 }   # installer leftovers
        }
    }
    if ($hidden) { $score += 15; $why += 'Hidden/system attribute' }
    if ($recent -and $score -gt 0) { $score += 5; $why += "Created on $($File.CreationTime.ToString('yyyy-MM-dd'))" }

    # Alternate data streams: data hidden "inside" a file, invisible in File Explorer.
    # An expensive check: only for files in the root or already suspicious.
    if ($Depth -eq 0 -or $score -gt 0) { try {
        $streams = Get-Item -LiteralPath $path -Stream * -ErrorAction Stop |
            Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen', 'com.dropbox.attrs', 'Afp_AfpInfo', 'OECustomProperty' -and $_.Length -gt 0 }
        foreach ($s in $streams) { $score += 30; $why += "Contains a hidden data stream (ADS) '$($s.Stream)' of $($s.Length) bytes" }
    } catch { } }

    $sev = ConvertTo-Severity $score
    if ($sev -in 'High', 'Medium') {
        $info = Get-FileInfo $path
        # Quarantine (or delete, if asked) from the app: files outside your own profile need the administrator
        $remedy = @{ Kind = 'QuarantineFile'; Path = $path; Sha256 = $info.Sha256; Admin = -not ($path -like "$env:USERPROFILE\*") }
        Add-Finding -Category $Category -Severity $sev -Title $File.Name -Path $path -Mitre 'T1036 / T1564' -Reasons $why -Remedy $remedy `
            -Evidence "Size $([math]::Round($File.Length / 1KB)) KB; created $($File.CreationTime.ToString('yyyy-MM-dd HH:mm')); modified $($File.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" `
            -Sha256 $info.Sha256 -Signer $info.Signer `
            -Recommendation 'Upload the file to virustotal.com. If it is malicious, first remove the autostart entries that launch it, then delete the file.'
    }
}
