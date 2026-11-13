# Checking a file (or a folder) BEFORE opening it: digital signature, origin,
# executable structure, tricks to evade antivirus products, and DLLs that would be
# loaded instead of the system ones.
# The file is only read: it is never run.

$script:FileCategory = 'Checked file'

# Shannon entropy (0-8 bits per byte): close to 8 = compressed or encrypted, close to 0 =
# repeated data (e.g. zeros). Computed in C# because a PowerShell loop over millions of
# bytes would take minutes.
if (-not ('CheckBackdoor.Entropy' -as [type])) {
    Add-Type -TypeDefinition @'
namespace CheckBackdoor {
    public static class Entropy {
        public static double Of(byte[] data, int count) {
            if (count <= 0) return 0;
            int[] freq = new int[256];
            for (int i = 0; i < count; i++) freq[data[i]]++;
            double e = 0;
            for (int i = 0; i < 256; i++) {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / count;
                e -= p * System.Math.Log(p, 2);
            }
            return e;
        }
    }
}
'@
}

# Reads at most $Max bytes from a position in the file and computes their entropy
function Get-RegionEntropy {
    param([IO.FileStream]$Stream, [long]$Offset, [long]$Length, [int]$Max = 4MB)
    $n = [int][Math]::Min($Length, $Max)
    if ($n -le 0) { return 0 }
    $buf = New-Object byte[] $n
    [void]$Stream.Seek($Offset, 'Begin')
    $read = $Stream.Read($buf, 0, $n)
    return [Math]::Round([CheckBackdoor.Entropy]::Of($buf, $read), 2)
}

# Structure of a Windows executable (PE format): sections, entropy, data appended after
# the last section (overlay), .NET or native.
function Get-PeInfo {
    param([string]$Path)
    $fs = $null
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $br = New-Object IO.BinaryReader($fs)
        if ($fs.Length -lt 512 -or $br.ReadUInt16() -ne 0x5A4D) { return $null }   # "MZ"
        [void]$fs.Seek(0x3C, 'Begin'); $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt $fs.Length - 248) { return $null }
        [void]$fs.Seek($peOff, 'Begin')
        if ($br.ReadUInt32() -ne 0x4550) { return $null }                           # "PE\0\0"
        [void]$br.ReadUInt16()                                                       # machine
        $nSections = $br.ReadUInt16()
        [void]$fs.Seek($peOff + 20, 'Begin'); $optSize = $br.ReadUInt16()
        $optStart = $peOff + 24
        [void]$fs.Seek($optStart, 'Begin'); $magic = $br.ReadUInt16()
        $is64 = $magic -eq 0x20B
        # Directory 14 (CLR): present in .NET executables
        $ddStart = $optStart + $(if ($is64) { 112 } else { 96 })
        [void]$fs.Seek($ddStart + 14 * 8, 'Begin'); $clrRva = $br.ReadUInt32()
        # Directory 4 (certificate): where the signature starts, at the end of the file
        [void]$fs.Seek($ddStart + 4 * 8, 'Begin'); $certOff = $br.ReadUInt32(); $certSize = $br.ReadUInt32()

        $sections = @(); $endOfData = 0
        $secStart = $optStart + $optSize
        for ($i = 0; $i -lt [Math]::Min($nSections, 96); $i++) {
            [void]$fs.Seek($secStart + 40 * $i, 'Begin')
            $name = ([Text.Encoding]::ASCII.GetString($br.ReadBytes(8))).TrimEnd([char]0)
            [void]$fs.Seek($secStart + 40 * $i + 16, 'Begin')
            $rawSize = $br.ReadUInt32(); $rawPtr = $br.ReadUInt32()
            if ($rawPtr + $rawSize -gt $endOfData) { $endOfData = $rawPtr + $rawSize }
            $sections += [pscustomobject]@{ Name = $name; Offset = $rawPtr; Size = $rawSize; Entropy = (Get-RegionEntropy $fs $rawPtr $rawSize 2MB) }
        }
        # Data after the last section, excluding the digital signature
        $overlayEnd = $fs.Length
        if ($certOff -gt 0 -and $certOff -ge $endOfData -and $certOff + $certSize -le $fs.Length) { $overlayEnd = $certOff }
        $overlaySize = [Math]::Max(0, $overlayEnd - $endOfData)
        return [pscustomobject]@{
            Is64 = $is64; IsDotNet = $clrRva -ne 0; Sections = $sections
            OverlayOffset = $endOfData; OverlaySize = $overlaySize
            OverlayEntropy = $(if ($overlaySize -gt 0) { Get-RegionEntropy $fs $endOfData $overlaySize } else { 0 })
            Size = $fs.Length
        }
    } catch { return $null } finally { if ($fs) { $fs.Dispose() } }
}

# Origin recorded by Windows at download time (Zone.Identifier stream)
function Get-DownloadOrigin {
    param([string]$Path)
    try {
        $z = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction Stop
    } catch { return $null }
    $zone = ($z | Where-Object { $_ -match '^ZoneId=(\d)' } | ForEach-Object { [int]$Matches[1] }) | Select-Object -First 1
    $host_ = ($z | Where-Object { $_ -match '^HostUrl=(.+)$' } | ForEach-Object { $Matches[1] }) | Select-Object -First 1
    $ref = ($z | Where-Object { $_ -match '^ReferrerUrl=(.+)$' } | ForEach-Object { $Matches[1] }) | Select-Object -First 1
    return [pscustomobject]@{ Zone = $zone; HostUrl = $host_; Referrer = $ref; FromInternet = $zone -ge 3 }
}

$script:PackerSections = @{
    'UPX' = '^UPX\d?$|^\.UPX'; 'Themida/WinLicense' = '^\.themida$|^\.winlic'; 'VMProtect' = '^\.vmp\d'
    'Enigma' = '^\.enigma'; 'ASPack' = '^\.aspack$|^\.adata$'; 'MPRESS' = '^\.MPRESS'; 'PECompact' = '^PEC2|^pec\d'; 'Petite' = '^\.petite$'
}
# DLLs a program looks for in its own folder first: an unsigned copy next to the
# executable gets loaded instead of the Windows one.
$script:HijackableDlls = '^(?i)(version|winmm|dinput8|dxgi|d3d9|d3d11|winhttp|wininet|dbghelp|dbgcore|uxtheme|msimg32|cryptbase|cryptsp|profapi|userenv|wtsapi32|iphlpapi|dwmapi|winspool|mpr|netapi32|secur32|propsys|xinput1_3|xinput1_4|xinput9_1_0|ddraw|dsound|opengl32|wsock32|ws2_32|bcrypt|ncrypt|sspicli|textshaping|oleacc|hid|setupapi|mscoree|winsta|edputil|urlmon)\.dll$'
$script:CrackDlls = '^(?i)(steam_api(64)?|eossdk-win(32|64)-shipping|uplay_r[12](_loader)?(64)?|upc_r[12](_loader)?(64)?|galaxy(64)?|origin_api|socialclub)\.dll$'
$script:CheckableExt = '(?i)\.(exe|dll|scr|com|pif|cpl|sys|msi|ocx|lnk|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|jar|zip)$'

function Test-SingleFile {
    param([IO.FileInfo]$File)
    $path = $File.FullName
    $ext = $File.Extension.ToLowerInvariant()
    $score = 0; $why = @(); $facts = @()

    # Deceptive name: double extension or the character that reverses text (U+202E)
    if ($File.Name.IndexOf([char]0x202E) -ge 0) { $score += 70; $why += 'The name contains an invisible character that reverses the text: "photogpj.exe" shows up as "photoexe.jpg"' }
    if ($File.Name -match '(?i)\.(jpe?g|png|gif|bmp|pdf|docx?|xlsx?|pptx?|txt|rtf|mp[34]|avi|mkv|mov|wav|zip|rar|7z)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|jse|wsf|hta|lnk|cpl)$') {
        $score += 50; $why += 'Double extension: it looks like a document or an image but it is a program'
    }
    if ($File.Name -match '\s{5,}\.\w{2,4}$') { $score += 40; $why += 'Many spaces before the extension to hide it' }

    $origin = Get-DownloadOrigin $path
    if ($origin -and $origin.HostUrl) { $facts += "Downloaded from $($origin.HostUrl)$(if ($origin.Referrer) { " (page: $($origin.Referrer))" })" }
    elseif ($origin -and $origin.FromInternet) { $facts += 'Windows marks it as coming from the internet' }

    if ($ext -in '.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.msi', '.ocx') {
        $info = Get-FileInfo $path
        switch ($info.SignatureStatus) {
            'Valid' { $facts += "Signed by $($info.Signer) (valid signature)" }
            'NotSigned' { $score += 25; $why += 'Not digitally signed: nobody knows who made it' }
            'HashMismatch' { $score += 60; $why += 'Tampered signature: the file was changed after it was signed' }
            default { $score += 35; $why += "Invalid digital signature ($($info.SignatureStatus))" }
        }
        $signed = $info.SignatureStatus -eq 'Valid'
        if (-not $signed -and $origin -and $origin.FromInternet) { $score += 10; $why += 'Downloaded from the internet and unsigned' }
        $declared = @($info.Description, $info.Company) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
        if ($declared) { $facts += "Declares: $($declared -join ' - ')" }

        $pe = if ($ext -ne '.msi') { Get-PeInfo $path } else { $null }
        if ($pe) {
            $size = if ($pe.Size -ge 1MB) { "$([Math]::Round($pe.Size / 1MB, 1)) MB" } else { "$([Math]::Ceiling($pe.Size / 1KB)) KB" }
            $facts += "$(if ($pe.Is64) { '64-bit' } else { '32-bit' })$(if ($pe.IsDotNet) { ' .NET' }) executable, $size"
            foreach ($k in $script:PackerSections.Keys) {
                if ($pe.Sections | Where-Object { $_.Name -match $script:PackerSections[$k] }) {
                    $score += 20; $why += "Compressed or protected with $($k): it hides the code from antivirus products (some legitimate programs and almost every crack do this)"
                }
            }
            $code = $pe.Sections | Where-Object { $_.Name -in '.text', 'CODE', '.code' } | Select-Object -First 1
            if ($code -and $code.Entropy -gt 7.2 -and -not $signed) { $score += 15; $why += "The code is encrypted or compressed (entropy $($code.Entropy) out of 8)" }
            if ($pe.OverlaySize -gt 50MB -and $pe.OverlayEntropy -lt 1) {
                $score += 45; $why += "Inflated with $([Math]::Round($pe.OverlaySize / 1MB)) MB of empty data: a stealer trick to exceed the size limit of antivirus products and VirusTotal"
            } elseif ($pe.OverlaySize -gt 1MB -and $pe.OverlaySize -gt 0.3 * $pe.Size -and $pe.OverlayEntropy -gt 7.5 -and -not $signed) {
                $score += 15; $why += "Contains $([Math]::Round($pe.OverlaySize / 1MB, 1)) MB of compressed or encrypted data appended: it is an installer or a container for other files"
            }
        }
        if ($File.Length -gt 300MB -and -not $signed) { $score += 10; $why += 'A very large unsigned file: beyond the limits of many online scanners' }
    }
    elseif ($ext -in '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta') {
        $score += $(if ($ext -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta') { 20 } else { 5 })
        $why += 'It is a script: Windows runs it directly'
        if ($File.Length -lt 5MB) {
            $text = $null
            try { $text = [IO.File]::ReadAllText($path) } catch { }
            if ($text) {
                foreach ($p in $script:SuspiciousPatterns) { if ($text -match $p.Rx) { $score += $p.S; $why += "Content: $($p.R)" } }
                if ($text -match '(?i)(chr\(\d+\)\s*&\s*){10,}|(\[char\]\d+\s*\+\s*){10,}|[A-Za-z0-9+/]{400,}={0,2}') { $score += 25; $why += 'Obfuscated content (long Base64 strings or chains of characters)' }
            }
        }
    }
    elseif ($ext -eq '.lnk') {
        $lnk = Resolve-Shortcut $path
        if ($lnk) {
            $facts += "Opens: $($lnk.Target) $($lnk.Arguments)"
            $risk = Get-CommandRisk "`"$($lnk.Target)`" $($lnk.Arguments)"
            $score += $risk.Score; $why += $risk.Reasons
            if ($lnk.Target -match '(?i)\\(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)\.exe$') { $score += 25; $why += 'A shortcut that launches a command interpreter: a common trick in downloaded archives' }
        }
    }
    elseif ($ext -eq '.zip') {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($path)
            try {
                $entries = @($zip.Entries | Where-Object { $_.Name })
                $facts += "Archive with $($entries.Count) files"
                $danger = @($entries | Where-Object { $_.Name -match '(?i)\.(lnk|vbs|vbe|js|jse|wsf|hta|scr|pif|cpl)$' -or $_.Name -match '(?i)\.(jpe?g|png|pdf|docx?|txt|mp[34])\s*\.(exe|scr|com|bat|cmd|lnk)$' })
                if ($danger) { $score += 40; $why += "Contains files used to deceive: $(($danger | Select-Object -First 3).Name -join ', ')" }
                $exes = @($entries | Where-Object { $_.Name -match '(?i)\.(exe|dll|msi)$' })
                if ($exes) { $facts += "Contains $($exes.Count) executables: extract the archive and check the folder" }
            } finally { $zip.Dispose() }
        } catch { $facts += 'Archive cannot be read (password-protected or damaged): password-protected archives are often used to hide the content from antivirus products' }
    }

    $sev = ConvertTo-Severity $score
    Add-InventoryItem $script:FileCategory $path "$score"
    $reasons = @($why) + @($facts)
    if (-not $why) { $reasons = @('No clues in the file structure.') + @($facts) }
    Add-Finding -Category $script:FileCategory -Severity $sev -Title $File.Name -Path $path -Mitre 'T1204.002' -Reasons $reasons `
        -Evidence "$([Math]::Round($File.Length / 1KB)) KB; modified $($File.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" `
        -Recommendation $(if ($sev -in 'High', 'Medium') { 'Do not open it until you have checked the file on virustotal.com (link below). If it comes from a crack, keep in mind that whoever distributed it could have added anything.' } else { 'No clues does not mean safe: if it comes from an unofficial source, check it on virustotal.com too before opening it.' })
}

# DLLs next to an executable: those with system names get loaded instead of the
# originals (DLL side-loading), those of game clients are typical of cracks.
function Test-SideloadedDlls {
    param([string]$Directory)
    # In the Windows folder these DLLs are the originals
    if ($Directory -like "$env:SystemRoot*") { return }
    foreach ($dll in Get-ChildItem -LiteralPath $Directory -Filter '*.dll' -File -ErrorAction SilentlyContinue) {
        # The signature is checked only for DLLs with risky names: there are few
        if ($dll.Name -notmatch $script:HijackableDlls -and $dll.Name -notmatch $script:CrackDlls) { continue }
        $info = Get-FileInfo $dll.FullName
        if ($info.SignatureStatus -eq 'Valid') { continue }
        if ($dll.Name -match $script:HijackableDlls) {
            Add-Finding -Category $script:FileCategory -Severity 'High' -Title "Unsigned system DLL next to the program: $($dll.Name)" -Path $dll.FullName -Mitre 'T1574.002' `
                -Reasons @("$($dll.Name) is a Windows DLL: the program in the same folder will load this copy instead of the original", 'It is not signed: this is the classic way malware gets a legitimate program to run it (DLL side-loading)') `
                -Recommendation 'If the package does not say it includes this DLL (some game mods do), do not start the program and check the DLL on virustotal.com.'
        } elseif ($dll.Name -match $script:CrackDlls) {
            Add-Finding -Category $script:FileCategory -Severity 'Medium' -Title "Game client DLL replaced: $($dll.Name)" -Path $dll.FullName -Mitre 'T1574.002' `
                -Reasons @('The original DLL is signed by the game client; this one is not: the typical replacement made by a crack (emulator)', 'It runs at every game start with your permissions: if whoever modified it added other code, that runs too') `
                -Recommendation 'Check the DLL on virustotal.com: a few generic detections ("HackTool", "Crack") are expected for a crack, names like Trojan, Stealer or Backdoor are not.'
        }
    }
}

function Invoke-CheckFile {
    param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        Test-SingleFile $item
        if ($item.Extension -match '(?i)^\.(exe|scr|com)$') { Test-SideloadedDlls $item.DirectoryName }
        return
    }
    # Folder: every checkable file up to 3 levels deep, at most 500
    $files = New-Object System.Collections.Generic.List[IO.FileInfo]
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Dir = $item.FullName; Depth = 0 })
    $exeDirs = @{}
    while ($queue.Count -gt 0 -and $files.Count -lt 500) {
        $d = $queue.Dequeue()
        try { $entries = ([IO.DirectoryInfo]$d.Dir).GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if ($e -is [IO.DirectoryInfo]) { if ($d.Depth -lt 3) { $queue.Enqueue([pscustomobject]@{ Dir = $e.FullName; Depth = $d.Depth + 1 }) }; continue }
            if ($e.Name -notmatch $script:CheckableExt) { continue }
            if ($e.Extension -match '(?i)^\.(exe|scr|com)$') { $exeDirs[$e.DirectoryName] = $true }
            # DLLs are checked as side-loading candidates, not one by one
            if ($e.Extension -ieq '.dll') { continue }
            $files.Add($e)
            if ($files.Count -ge 500) { Write-ScanWarning 'Very large folder: only the first 500 files were checked.'; break }
        }
    }
    foreach ($f in $files) { Test-SingleFile $f }
    foreach ($dir in $exeDirs.Keys) { Test-SideloadedDlls $dir }
}
