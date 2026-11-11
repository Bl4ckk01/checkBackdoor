# Controllo di un file (o di una cartella) PRIMA di aprirlo: firma digitale,
# provenienza, struttura dell'eseguibile, trucchi per sfuggire agli antivirus e
# DLL che verrebbero caricate al posto di quelle di sistema.
# Il file viene solo letto: non viene mai eseguito.

$script:FileCategory = 'File analizzato'

# Entropia di Shannon (0-8 bit per byte): vicino a 8 = compresso o cifrato,
# vicino a 0 = dati ripetuti (es. zeri). Calcolata in C# perche' in PowerShell
# un ciclo su milioni di byte richiederebbe minuti.
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

# Legge al massimo $Max byte da una posizione del file e ne calcola l'entropia
function Get-RegionEntropy {
    param([IO.FileStream]$Stream, [long]$Offset, [long]$Length, [int]$Max = 4MB)
    $n = [int][Math]::Min($Length, $Max)
    if ($n -le 0) { return 0 }
    $buf = New-Object byte[] $n
    [void]$Stream.Seek($Offset, 'Begin')
    $read = $Stream.Read($buf, 0, $n)
    return [Math]::Round([CheckBackdoor.Entropy]::Of($buf, $read), 2)
}

# Struttura di un eseguibile Windows (formato PE): sezioni, entropia, dati
# accodati dopo l'ultima sezione (overlay), .NET o nativo.
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
        [void]$br.ReadUInt16()                                                       # macchina
        $nSections = $br.ReadUInt16()
        [void]$fs.Seek($peOff + 20, 'Begin'); $optSize = $br.ReadUInt16()
        $optStart = $peOff + 24
        [void]$fs.Seek($optStart, 'Begin'); $magic = $br.ReadUInt16()
        $is64 = $magic -eq 0x20B
        # Directory 14 (CLR): presente negli eseguibili .NET
        $ddStart = $optStart + $(if ($is64) { 112 } else { 96 })
        [void]$fs.Seek($ddStart + 14 * 8, 'Begin'); $clrRva = $br.ReadUInt32()
        # Directory 4 (certificato): dove inizia la firma, che sta in fondo al file
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
        # Dati dopo l'ultima sezione, esclusa la firma digitale
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

# Provenienza registrata da Windows al download (flusso Zone.Identifier)
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
# DLL che un programma cerca prima nella propria cartella: una copia non firmata
# accanto all'eseguibile viene caricata al posto di quella di Windows.
$script:HijackableDlls = '^(?i)(version|winmm|dinput8|dxgi|d3d9|d3d11|winhttp|wininet|dbghelp|dbgcore|uxtheme|msimg32|cryptbase|cryptsp|profapi|userenv|wtsapi32|iphlpapi|dwmapi|winspool|mpr|netapi32|secur32|propsys|xinput1_3|xinput1_4|xinput9_1_0|ddraw|dsound|opengl32|wsock32|ws2_32|bcrypt|ncrypt|sspicli|textshaping|oleacc|hid|setupapi|mscoree|winsta|edputil|urlmon)\.dll$'
$script:CrackDlls = '^(?i)(steam_api(64)?|eossdk-win(32|64)-shipping|uplay_r[12](_loader)?(64)?|upc_r[12](_loader)?(64)?|galaxy(64)?|origin_api|socialclub)\.dll$'
$script:CheckableExt = '(?i)\.(exe|dll|scr|com|pif|cpl|sys|msi|ocx|lnk|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|jar|zip)$'

function Test-SingleFile {
    param([IO.FileInfo]$File)
    $path = $File.FullName
    $ext = $File.Extension.ToLowerInvariant()
    $score = 0; $why = @(); $facts = @()

    # Nome ingannevole: doppia estensione o carattere che inverte il testo (U+202E)
    if ($File.Name.IndexOf([char]0x202E) -ge 0) { $score += 70; $why += 'Il nome contiene un carattere invisibile che inverte il testo: "fotogpj.exe" appare come "fotoexe.jpg"' }
    if ($File.Name -match '(?i)\.(jpe?g|png|gif|bmp|pdf|docx?|xlsx?|pptx?|txt|rtf|mp[34]|avi|mkv|mov|wav|zip|rar|7z)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|jse|wsf|hta|lnk|cpl)$') {
        $score += 50; $why += 'Doppia estensione: sembra un documento o un''immagine ma e'' un programma'
    }
    if ($File.Name -match '\s{5,}\.\w{2,4}$') { $score += 40; $why += 'Molti spazi prima dell''estensione per nasconderla' }

    $origin = Get-DownloadOrigin $path
    if ($origin -and $origin.HostUrl) { $facts += "Scaricato da $($origin.HostUrl)$(if ($origin.Referrer) { " (pagina: $($origin.Referrer))" })" }
    elseif ($origin -and $origin.FromInternet) { $facts += 'Windows lo segna come proveniente da internet' }

    if ($ext -in '.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.msi', '.ocx') {
        $info = Get-FileInfo $path
        switch ($info.SignatureStatus) {
            'Valid' { $facts += "Firmato da $($info.Signer) (firma valida)" }
            'NotSigned' { $score += 25; $why += 'Non firmato digitalmente: non si sa chi l''ha prodotto' }
            'HashMismatch' { $score += 60; $why += 'Firma manomessa: il file e'' stato modificato dopo essere stato firmato' }
            default { $score += 35; $why += "Firma digitale non valida ($($info.SignatureStatus))" }
        }
        $signed = $info.SignatureStatus -eq 'Valid'
        if (-not $signed -and $origin -and $origin.FromInternet) { $score += 10; $why += 'Scaricato da internet e senza firma' }
        $declared = @($info.Description, $info.Company) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
        if ($declared) { $facts += "Dichiara: $($declared -join ' - ')" }

        $pe = if ($ext -ne '.msi') { Get-PeInfo $path } else { $null }
        if ($pe) {
            $size = if ($pe.Size -ge 1MB) { "$([Math]::Round($pe.Size / 1MB, 1)) MB" } else { "$([Math]::Ceiling($pe.Size / 1KB)) KB" }
            $facts += "Eseguibile $(if ($pe.Is64) { '64 bit' } else { '32 bit' })$(if ($pe.IsDotNet) { ' .NET' }), $size"
            foreach ($k in $script:PackerSections.Keys) {
                if ($pe.Sections | Where-Object { $_.Name -match $script:PackerSections[$k] }) {
                    $score += 20; $why += "Compresso o protetto con $($k): nasconde il codice agli antivirus (lo fanno anche alcuni programmi legittimi e quasi tutti i crack)"
                }
            }
            $code = $pe.Sections | Where-Object { $_.Name -in '.text', 'CODE', '.code' } | Select-Object -First 1
            if ($code -and $code.Entropy -gt 7.2 -and -not $signed) { $score += 15; $why += "Il codice e' cifrato o compresso (entropia $($code.Entropy) su 8)" }
            if ($pe.OverlaySize -gt 50MB -and $pe.OverlayEntropy -lt 1) {
                $score += 45; $why += "Gonfiato con $([Math]::Round($pe.OverlaySize / 1MB)) MB di dati vuoti: trucco degli stealer per superare il limite di dimensione di antivirus e VirusTotal"
            } elseif ($pe.OverlaySize -gt 1MB -and $pe.OverlaySize -gt 0.3 * $pe.Size -and $pe.OverlayEntropy -gt 7.5 -and -not $signed) {
                $score += 15; $why += "Contiene $([Math]::Round($pe.OverlaySize / 1MB, 1)) MB di dati compressi o cifrati accodati: e' un installer o un contenitore di altri file"
            }
        }
        if ($File.Length -gt 300MB -and -not $signed) { $score += 10; $why += 'File molto grande e senza firma: oltre i limiti di molti antivirus online' }
    }
    elseif ($ext -in '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta') {
        $score += $(if ($ext -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta') { 20 } else { 5 })
        $why += 'E'' uno script: viene eseguito direttamente da Windows'
        if ($File.Length -lt 5MB) {
            $text = $null
            try { $text = [IO.File]::ReadAllText($path) } catch { }
            if ($text) {
                foreach ($p in $script:SuspiciousPatterns) { if ($text -match $p.Rx) { $score += $p.S; $why += "Contenuto: $($p.R)" } }
                if ($text -match '(?i)(chr\(\d+\)\s*&\s*){10,}|(\[char\]\d+\s*\+\s*){10,}|[A-Za-z0-9+/]{400,}={0,2}') { $score += 25; $why += 'Contenuto offuscato (lunghe stringhe Base64 o catene di caratteri)' }
            }
        }
    }
    elseif ($ext -eq '.lnk') {
        $lnk = Resolve-Shortcut $path
        if ($lnk) {
            $facts += "Apre: $($lnk.Target) $($lnk.Arguments)"
            $risk = Get-CommandRisk "`"$($lnk.Target)`" $($lnk.Arguments)"
            $score += $risk.Score; $why += $risk.Reasons
            if ($lnk.Target -match '(?i)\\(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)\.exe$') { $score += 25; $why += 'Un collegamento che lancia un interprete di comandi: trucco comune negli archivi scaricati' }
        }
    }
    elseif ($ext -eq '.zip') {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($path)
            try {
                $entries = @($zip.Entries | Where-Object { $_.Name })
                $facts += "Archivio con $($entries.Count) file"
                $danger = @($entries | Where-Object { $_.Name -match '(?i)\.(lnk|vbs|vbe|js|jse|wsf|hta|scr|pif|cpl)$' -or $_.Name -match '(?i)\.(jpe?g|png|pdf|docx?|txt|mp[34])\s*\.(exe|scr|com|bat|cmd|lnk)$' })
                if ($danger) { $score += 40; $why += "Contiene file usati per ingannare: $(($danger | Select-Object -First 3).Name -join ', ')" }
                $exes = @($entries | Where-Object { $_.Name -match '(?i)\.(exe|dll|msi)$' })
                if ($exes) { $facts += "Contiene $($exes.Count) eseguibili: estrai l'archivio e controlla la cartella" }
            } finally { $zip.Dispose() }
        } catch { $facts += 'Archivio non leggibile (protetto da password o danneggiato): gli archivi con password servono spesso a nascondere il contenuto agli antivirus' }
    }

    $sev = ConvertTo-Severity $score
    Add-InventoryItem $script:FileCategory $path "$score"
    $reasons = @($why) + @($facts)
    if (-not $why) { $reasons = @('Nessun indizio nella struttura del file.') + @($facts) }
    Add-Finding -Category $script:FileCategory -Severity $sev -Title $File.Name -Path $path -Mitre 'T1204.002' -Reasons $reasons `
        -Evidence "$([Math]::Round($File.Length / 1KB)) KB; modificato $($File.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))" `
        -Recommendation $(if ($sev -in 'Alto', 'Medio') { 'Non aprirlo finche'' non hai verificato il file su virustotal.com (link qui sotto). Se viene da un crack, considera che chi l''ha distribuito puo'' aver aggiunto qualsiasi cosa.' } else { 'Nessun indizio non vuol dire sicuro: se viene da una fonte non ufficiale, verificalo anche su virustotal.com prima di aprirlo.' })
}

# DLL accanto a un eseguibile: quelle con nomi di sistema vengono caricate al posto
# delle originali (DLL side-loading), quelle dei client di gioco sono tipiche dei crack.
function Test-SideloadedDlls {
    param([string]$Directory)
    # Nella cartella di Windows queste DLL sono proprio le originali
    if ($Directory -like "$env:SystemRoot*") { return }
    foreach ($dll in Get-ChildItem -LiteralPath $Directory -Filter '*.dll' -File -ErrorAction SilentlyContinue) {
        # Si verifica la firma solo delle DLL con i nomi a rischio: sono poche
        if ($dll.Name -notmatch $script:HijackableDlls -and $dll.Name -notmatch $script:CrackDlls) { continue }
        $info = Get-FileInfo $dll.FullName
        if ($info.SignatureStatus -eq 'Valid') { continue }
        if ($dll.Name -match $script:HijackableDlls) {
            Add-Finding -Category $script:FileCategory -Severity 'Alto' -Title "DLL di sistema non firmata accanto al programma: $($dll.Name)" -Path $dll.FullName -Mitre 'T1574.002' `
                -Reasons @("$($dll.Name) e' una DLL di Windows: il programma nella stessa cartella carichera' questa copia al posto dell'originale", 'Non e'' firmata: e'' il modo classico con cui un malware si fa eseguire da un programma legittimo (DLL side-loading)') `
                -Recommendation 'Se il pacchetto non dichiara di includere questa DLL (alcune mod di giochi lo fanno), non avviare il programma e verifica la DLL su virustotal.com.'
        } elseif ($dll.Name -match $script:CrackDlls) {
            Add-Finding -Category $script:FileCategory -Severity 'Medio' -Title "DLL del client di gioco sostituita: $($dll.Name)" -Path $dll.FullName -Mitre 'T1574.002' `
                -Reasons @('La DLL originale e'' firmata dal client di gioco; questa no: e'' la tipica sostituzione fatta da un crack (emulatore)', 'Viene eseguita a ogni avvio del gioco con i tuoi permessi: se chi l''ha modificata ha aggiunto altro codice, gira anche quello') `
                -Recommendation 'Verifica la DLL su virustotal.com: pochi rilevamenti generici ("HackTool", "Crack") sono attesi per un crack, nomi come Trojan, Stealer o Backdoor no.'
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
    # Cartella: tutti i file controllabili fino a 3 livelli, al massimo 500
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
            # Le DLL si controllano come candidate al side-loading, non una per una
            if ($e.Extension -ieq '.dll') { continue }
            $files.Add($e)
            if ($files.Count -ge 500) { Write-ScanWarning 'Cartella molto grande: controllati solo i primi 500 file.'; break }
        }
    }
    foreach ($f in $files) { Test-SingleFile $f }
    foreach ($dir in $exeDirs.Keys) { Test-SideloadedDlls $dir }
}
