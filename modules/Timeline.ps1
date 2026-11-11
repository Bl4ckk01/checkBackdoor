# Linea temporale: cosa e' successo negli ultimi 30 giorni secondo i registri di Windows.
# Una backdoor puo' cancellare i propri file, ma le tracce dell'installazione restano:
# servizi registrati (7045), Defender spento o con esclusioni (5001, 5007), minacce
# trovate (1116-1119), account creati (4720, 4732), script PowerShell sospetti (4104)
# e programmi avviati (chiave BAM).
#
# Ogni lettore restituisce oggetti semplici { Time, Id, Data }: le funzioni Test-* li
# valutano e si possono provare con eventi finti.

$script:Timeline = New-Object System.Collections.Generic.List[object]
$script:TimelineExamined = 0
$script:TimelineRan = $false
$script:TimelineDays = 30
$script:TimelineCategory = 'Linea temporale'

function Add-TimelineEntry {
    param([datetime]$Time, [string]$Source, [string]$Text, [string]$Path, [string]$Severity = 'Info', [string]$FindingId)
    $script:Timeline.Add([pscustomobject]@{
            Time = $Time.ToString('s'); Source = $Source; Text = $Text; Path = $Path; Severity = $Severity; FindingId = $FindingId
        })
}

# Registra la segnalazione e la voce della linea temporale collegata.
function Add-TimelineFinding {
    param([datetime]$Time, [string]$Source, [string]$Severity, [string]$Title, [string]$Text, [string]$Path, [string]$Evidence,
        [string]$Detail, [string]$Mitre, [string[]]$Reasons, [string]$Recommendation)
    Add-Finding -Category $script:TimelineCategory -Severity $Severity -Title $Title -Detail $Detail -Path $Path -Evidence $Evidence `
        -Mitre $Mitre -Reasons $Reasons -Recommendation $Recommendation
    Add-TimelineEntry -Time $Time -Source $Source -Text $Text -Path $Path -Severity $Severity `
        -FindingId (Get-FindingId $script:TimelineCategory $Title $Path $Evidence)
}

function Read-WinEvents {
    param([string]$LogName, [int[]]$Id, [datetime]$Since, [int]$Max = 300, [int]$Level)
    $filter = @{ LogName = $LogName; Id = $Id; StartTime = $Since }
    if ($Level) { $filter.Level = $Level }
    try { $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
    foreach ($ev in $events) {
        $data = @{}
        try {
            foreach ($d in ([xml]$ev.ToXml()).Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
            }
        } catch { }
        [pscustomobject]@{ Time = $ev.TimeCreated; Id = $ev.Id; Data = $data }
    }
}

function Format-TimelineDate([datetime]$Time) { $Time.ToString('dd/MM/yyyy HH:mm') }

# --- Servizi installati (7045) ----------------------------------------------------
function Test-ServiceExists([string]$Name) {
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name")
    if ($k) { $k.Close(); return $true }
    return $false
}

function Test-ServiceInstallEvents {
    param($Events)
    # Driver di VPN e anti-cheat si reinstallano a ogni avvio: una voce per servizio e
    # comando, con l'ultima data e il numero di volte.
    $groups = @(@($Events) | Where-Object { $_.Data['ServiceName'] } |
            Group-Object { "$($_.Data['ServiceName'])|$($_.Data['ImagePath'])".ToLowerInvariant() })
    foreach ($g in $groups) {
        $ev = @($g.Group | Sort-Object Time)[-1]
        $name = $ev.Data['ServiceName']; $image = $ev.Data['ImagePath']
        $exists = Test-ServiceExists $name
        $text = "Installato il servizio $name"
        if ($g.Count -gt 1) { $text += " ($($g.Count) volte)" }
        if (-not $exists) { $text += ", poi rimosso" }
        $risk = Get-CommandRisk $image
        $sev = ConvertTo-Severity $risk.Score
        # Un servizio ancora presente lo valuta gia' il controllo dei servizi; qui interessa
        # quello rimosso con un comando sospetto: tipico degli strumenti che si cancellano.
        if (-not $exists -and $sev -in 'Alto', 'Medio') {
            Add-TimelineFinding -Time $ev.Time -Source 'Servizi' -Severity $sev -Title "Servizio installato e poi rimosso: $name" `
                -Text $text -Path $risk.Target -Evidence $image -Detail "Registro eventi di sistema, evento 7045 del $(Format-TimelineDate $ev.Time)" `
                -Mitre 'T1543.003' -Reasons (@("Il servizio non esiste piu': e' stato installato, ha eseguito il comando ed e' stato rimosso") + @($risk.Reasons)) `
                -Recommendation "Un servizio che compare e sparisce con un comando del genere e' tipico degli strumenti di accesso remoto. Esegui Microsoft Defender Offline e controlla gli altri eventi della stessa data."
        } else {
            $tlSev = if ($sev -in 'Alto', 'Medio') { $sev } else { 'Info' }
            # Aggiornamenti di driver e servizi firmati (VPN, antivirus, anti-cheat): rumore
            if ($tlSev -eq 'Info' -and $risk.Target -and [IO.Path]::IsPathRooted($risk.Target)) {
                $info = Get-FileInfo $risk.Target
                if ($info.Exists -and $info.SignatureStatus -eq 'Valid') { continue }
            }
            Add-TimelineEntry -Time $ev.Time -Source 'Servizi' -Text $text -Path $risk.Target -Severity $tlSev
        }
    }
}

# --- Microsoft Defender (5001, 5007, 1116-1119) -----------------------------------
function Get-DefenderThreatPath([string]$Raw) {
    if (-not $Raw) { return $null }
    $first = ($Raw -split ';')[0]
    return ($first -replace '^(file|containerfile|process|regkey|webfile):_', '').Trim()
}

function Test-DefenderEvents {
    param($Events)
    $events = @($Events | Sort-Object Time)
    $off = @($events | Where-Object { $_.Id -in 5001, 5010, 5012 })
    foreach ($ev in $off) { Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text 'Protezione di Defender disattivata' -Severity 'Medio' }
    if ($off) {
        $last = $off[-1].Time
        $n = $off.Count
        Add-Finding -Category $script:TimelineCategory -Severity 'Medio' -Title 'Protezione di Defender disattivata di recente' `
            -Detail "$n volte negli ultimi $script:TimelineDays giorni, l'ultima il $(Format-TimelineDate $last) (eventi 5001, 5010, 5012)" `
            -Mitre 'T1562.001' -Reasons "Molti crack chiedono di spegnere l'antivirus: in quel momento qualsiasi cosa installata passa senza controlli" `
            -Recommendation "Se non sei stato tu, o se l'hai spenta per installare un crack, esegui Microsoft Defender Offline e controlla cosa e' stato installato in quei giorni."
    }

    foreach ($ev in @($events | Where-Object Id -eq 5007)) {
        $new = $ev.Data['New Value']; $old = $ev.Data['Old Value']
        if ($new -match '(?i)\\Exclusions\\(Paths|Extensions|Processes|IpAddresses)\\(.+?)\s*=' -and -not $old) {
            $kind = @{ Paths = 'cartella o file'; Extensions = 'estensione'; Processes = 'programma'; IpAddresses = 'indirizzo IP' }[$Matches[1]]
            Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "Aggiunta un'esclusione a Defender ($kind)" -Path $Matches[2] -Severity 'Medio'
        } elseif ($new -match '(?i)\\(DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAVProtection)\s*=\s*0x1') {
            Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "Impostazione di Defender cambiata: $($Matches[1])" -Severity 'Medio'
        }
    }

    # Minacce: una segnalazione per minaccia e file, con l'esito peggiore
    $threats = [ordered]@{}
    foreach ($ev in @($events | Where-Object { $_.Id -in 1116, 1117, 1118, 1119 })) {
        $name = $ev.Data['Threat Name']; if (-not $name) { continue }
        $path = Get-DefenderThreatPath $ev.Data['Path']
        $key = "$name|$path".ToLowerInvariant()
        if (-not $threats.Contains($key)) { $threats[$key] = [pscustomobject]@{ Name = $name; Path = $path; First = $ev.Time; Failed = $false; Action = $null } }
        $t = $threats[$key]
        if ($ev.Id -in 1118, 1119) { $t.Failed = $true }
        if ($ev.Id -eq 1117 -and $ev.Data['Action Name']) { $t.Action = $ev.Data['Action Name'] }
        $what = @{ 1116 = 'Defender ha trovato'; 1117 = 'Defender ha bloccato'; 1118 = "Defender non e' riuscito a bloccare"; 1119 = "Defender non e' riuscito a bloccare" }[$ev.Id]
        Add-TimelineEntry -Time $ev.Time -Source 'Defender' -Text "$what $name" -Path $path -Severity $(if ($ev.Id -in 1118, 1119) { 'Alto' } else { 'Basso' })
    }
    foreach ($t in $threats.Values) {
        $stillThere = $t.Path -and [IO.Path]::IsPathRooted($t.Path) -and (Test-Path -LiteralPath $t.Path -PathType Leaf)
        $reasons = @("Rilevata il $(Format-TimelineDate $t.First)")
        if ($t.Action) { $reasons += "Azione di Defender: $($t.Action)" }
        if ($t.Failed) { $sev = 'Alto'; $reasons += "Defender non e' riuscito a rimuoverla" }
        elseif ($stillThere) { $sev = 'Medio'; $reasons += "Il file rilevato esiste ancora" }
        else { $sev = 'Basso'; $reasons += "Il file non c'e' piu': Defender l'ha rimosso o messo in quarantena" }
        Add-Finding -Category $script:TimelineCategory -Severity $sev -Title "Minaccia trovata da Defender: $($t.Name)" -Path $t.Path `
            -Mitre 'T1204.002' -Reasons $reasons `
            -Recommendation "Apri Sicurezza di Windows, Protezione da virus e minacce, Cronologia protezione: verifica che la minaccia sia stata rimossa. Se veniva da un crack, considera compromesso tutto cio' che e' stato installato insieme."
    }
}

# --- Account (4720, 4732) ---------------------------------------------------------
function Resolve-SidName([string]$Sid) {
    if (-not $Sid) { return $null }
    try { return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $Sid }
}

function Test-AccountEvents {
    param($Events)
    foreach ($ev in @($Events)) {
        $by = $ev.Data['SubjectUserName']
        if ($ev.Id -eq 4720) {
            $name = $ev.Data['TargetUserName']
            Add-TimelineFinding -Time $ev.Time -Source 'Account' -Severity 'Medio' -Title "Account creato: $name" `
                -Text "Creato l'account $name" -Evidence "Creato da $by il $(Format-TimelineDate $ev.Time)" -Detail 'Registro eventi di sicurezza, evento 4720' `
                -Mitre 'T1136.001' -Reasons 'Una backdoor puo'' creare un account per rientrare nel PC anche se viene rimossa' `
                -Recommendation "Se non hai creato tu questo account, disattivalo da Gestione computer, Utenti e gruppi locali, e cambia la password del tuo."
        } elseif ($ev.Id -eq 4732 -and $ev.Data['TargetSid'] -eq 'S-1-5-32-544') {
            $member = $ev.Data['MemberName']
            if (-not $member -or $member -eq '-') { $member = Resolve-SidName $ev.Data['MemberSid'] }
            Add-TimelineFinding -Time $ev.Time -Source 'Account' -Severity 'Medio' -Title "Aggiunto agli amministratori: $member" `
                -Text "$member aggiunto agli amministratori" -Evidence "Aggiunto da $by il $(Format-TimelineDate $ev.Time)" -Detail 'Registro eventi di sicurezza, evento 4732' `
                -Mitre 'T1098' -Reasons 'Un account amministratore in piu'' da'' pieno controllo del PC a chi lo conosce' `
                -Recommendation "Se non sei stato tu, togli l'account dal gruppo Administrators e cambia le password."
        }
    }
}

# --- Script PowerShell sospetti (4104, livello Avviso) -------------------------------
# Windows registra da solo, anche senza configurazione, gli script con parole chiave
# sospette. Si escludono quelli di CheckBackdoor, che contiene quelle parole per cercarle.
$script:ScriptExtraPatterns = @(
    @{ Rx = '(?i)(amsiutils|amsiinitfailed|amsiscanbuffer)'; S = 60; R = 'Tenta di disattivare AMSI, la protezione che fa leggere gli script all''antivirus'; Hard = $true }
    @{ Rx = '(?i)\[(system\.)?reflection\.assembly\]::load'; S = 30; R = 'Carica un programma direttamente in memoria, senza file'; Hard = $false }
    @{ Rx = '(?i)virtualalloc|createremotethread|writeprocessmemory'; S = 40; R = 'Usa funzioni di Windows per iniettare codice in altri processi'; Hard = $true }
)

function Get-OwnScriptText {
    if (-not $script:OwnScriptText) {
        # Cartella del motore, impostata da CheckBackdoor.ps1 prima di caricare i moduli
        $root = $script:EngineRoot
        $sb = New-Object System.Text.StringBuilder
        if ($root) {
            foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Include '*.ps1' -File -ErrorAction SilentlyContinue) {
                [void]$sb.Append([IO.File]::ReadAllText($f.FullName)).Append("`n")
            }
        }
        $script:OwnScriptText = $sb.ToString()
    }
    return $script:OwnScriptText
}

function Get-ScriptBlockRisk {
    param([string]$Text)
    $score = 0; $hard = $false
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($p in $script:SuspiciousPatterns) {
        if ($Text -match $p.Rx) {
            $score += $p.S; $reasons.Add($p.R)
            if ($p.S -ge 45) { $hard = $true }
        }
    }
    foreach ($p in $script:ScriptExtraPatterns) {
        if ($Text -match $p.Rx) { $score += $p.S; $reasons.Add($p.R); if ($p.Hard) { $hard = $true } }
    }
    $sev = ConvertTo-Severity $score
    # Scaricare ed eseguire e' anche il modo in cui si installano molti strumenti legittimi
    # (winget, Chocolatey, Scoop): resta "da verificare" se manca un segnale piu' forte.
    if ($sev -eq 'Alto' -and -not $hard) { $sev = 'Medio' }
    return [pscustomobject]@{ Score = $score; Severity = $sev; Reasons = $reasons.ToArray() }
}

function Test-PowerShellEvents {
    param($Events, [string]$OwnText)
    $seen = @{}
    foreach ($ev in @($Events)) {
        if ($ev.Data['MessageNumber'] -and $ev.Data['MessageNumber'] -ne '1') { continue }
        $text = $ev.Data['ScriptBlockText']
        if (-not $text) { continue }
        $trim = $text.Trim()
        if ($OwnText -and $trim.Length -gt 0 -and $OwnText.IndexOf($trim, [StringComparison]::Ordinal) -ge 0) { continue }
        # Moduli generati da Windows per i cmdlet CIM (es. Get-MpPreference di Defender)
        # e script in C:\Windows: li usa il sistema, non chi ha installato qualcosa.
        if ($trim -match "(?s)^#requires -version 3\.0.*\`$script:ClassName = 'root[\\/]") { continue }
        if ($ev.Data['Path'] -and $ev.Data['Path'].StartsWith($env:SystemRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $key = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($trim)))
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $risk = Get-ScriptBlockRisk $trim
        $path = $ev.Data['Path']
        $oneLine = ($trim -replace '\s+', ' ')
        if ($oneLine.Length -gt 300) { $oneLine = $oneLine.Substring(0, 300) + '...' }
        if ($risk.Severity -in 'Alto', 'Medio') {
            Add-TimelineFinding -Time $ev.Time -Source 'PowerShell' -Severity $risk.Severity -Title "Script PowerShell sospetto eseguito il $(Format-TimelineDate $ev.Time)" `
                -Text 'Eseguito uno script PowerShell sospetto' -Path $path -Evidence $oneLine -Detail 'Registro PowerShell Operational, evento 4104' `
                -Mitre 'T1059.001' -Reasons $risk.Reasons `
                -Recommendation "Leggi lo script nel Visualizzatore eventi (Registri applicazioni e servizi, Microsoft, Windows, PowerShell, Operational, evento 4104) e cerca cosa ha scaricato o eseguito."
        } elseif ($risk.Severity -eq 'Basso') {
            Add-TimelineEntry -Time $ev.Time -Source 'PowerShell' -Text 'Eseguito uno script PowerShell segnalato da Windows' -Path $path -Severity 'Info'
        }
    }
}

# --- Programmi avviati (chiave BAM) --------------------------------------------------
# Background Activity Moderator: per ogni utente, l'ultima esecuzione di ogni programma.
# I percorsi sono nel formato \Device\HarddiskVolumeN\..., da tradurre in lettere di unita'.
function Get-DeviceDriveMap {
    if (-not ('CheckBackdoor.DosDevice' -as [type])) {
        Add-Type -Namespace CheckBackdoor -Name DosDevice -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@
    }
    $map = @{}
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        $letter = $d.Name.Substring(0, 2)
        $sb = New-Object System.Text.StringBuilder 1024
        if ([CheckBackdoor.DosDevice]::QueryDosDevice($letter, $sb, 1024) -gt 0) { $map[$sb.ToString()] = $letter }
    }
    return $map
}

function ConvertFrom-BamValue {
    param([string]$Name, $Value, [hashtable]$DriveMap)
    if ($Value -isnot [byte[]] -or $Value.Length -lt 8) { return $null }
    $path = $Name
    $m = [regex]::Match($Name, '^(\\Device\\[^\\]+)(\\.*)$')
    if ($m.Success) {
        if ($DriveMap -and $DriveMap.ContainsKey($m.Groups[1].Value)) { $path = $DriveMap[$m.Groups[1].Value] + $m.Groups[2].Value }
        else { return $null }
    }
    $ft = [BitConverter]::ToInt64($Value, 0)
    if ($ft -le 0) { return $null }
    try { $time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime() } catch { return $null }
    return [pscustomobject]@{ Path = $path; Time = $time }
}

function Read-BamEntries {
    $out = @()
    $map = Get-DeviceDriveMap
    foreach ($base in 'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        $root = $null
        try { $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base) } catch { }
        if (-not $root) { continue }
        foreach ($sid in $root.GetSubKeyNames()) {
            $k = $root.OpenSubKey($sid)
            if (-not $k) { continue }
            $user = Resolve-SidName $sid
            foreach ($n in $k.GetValueNames()) {
                $e = ConvertFrom-BamValue -Name $n -Value $k.GetValue($n) -DriveMap $map
                if ($e) { $out += [pscustomobject]@{ Path = $e.Path; Time = $e.Time; User = $user } }
            }
        }
        break
    }
    return $out
}

function Test-BamEntries {
    param($Entries, [datetime]$Since)
    $known = @{}
    foreach ($f in $script:Findings) { if ($f.Path) { $known[$f.Path.ToLowerInvariant()] = $true } }
    foreach ($e in @($Entries | Where-Object { $_.Time -ge $Since } | Sort-Object Time)) {
        if (-not (Test-UserWritablePath $e.Path)) { continue }
        $name = [IO.Path]::GetFileName($e.Path)
        if (-not (Test-Path -LiteralPath $e.Path -PathType Leaf)) {
            Add-TimelineEntry -Time $e.Time -Source 'Programmi' -Text "Avviato $name, che ora non esiste piu'" -Path $e.Path -Severity 'Info'
            continue
        }
        $risk = Get-CommandRisk "`"$($e.Path)`""
        $sev = ConvertTo-Severity $risk.Score
        if ($sev -in 'Alto', 'Medio' -and -not $known.ContainsKey($e.Path.ToLowerInvariant())) {
            $known[$e.Path.ToLowerInvariant()] = $true
            Add-TimelineFinding -Time $e.Time -Source 'Programmi' -Severity $sev -Title "Programma avviato da una cartella utente: $name" `
                -Text "Avviato $name" -Path $e.Path -Evidence "Ultimo avvio il $(Format-TimelineDate $e.Time)$(if ($e.User) { " da $($e.User)" })" `
                -Detail 'Chiave BAM del registro (ultima esecuzione dei programmi)' -Mitre 'T1204.002' -Reasons $risk.Reasons `
                -Recommendation "Se non riconosci questo programma, caricalo su virustotal.com. Se e' il crack o l'installer di un gioco, controlla gli altri eventi dello stesso giorno nella linea temporale."
        } else {
            Add-TimelineEntry -Time $e.Time -Source 'Programmi' -Text "Avviato $name" -Path $e.Path -Severity $(if ($sev -in 'Alto', 'Medio') { $sev } else { 'Info' })
        }
    }
}

function Invoke-CheckTimeline {
    $script:TimelineRan = $true
    $since = (Get-Date).AddDays(-$script:TimelineDays)

    $svc = @(Read-WinEvents -LogName 'System' -Id 7045 -Since $since)
    $def = @(Read-WinEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Id 5001, 5007, 5010, 5012, 1116, 1117, 1118, 1119 -Since $since -Max 500)
    $acc = @()
    if ($script:IsAdmin) { $acc = @(Read-WinEvents -LogName 'Security' -Id 4720, 4732 -Since $since) }
    $ps = @(Read-WinEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -Since $since -Level 3 -Max 500)
    $bam = @(Read-BamEntries)
    $script:TimelineExamined = $svc.Count + $def.Count + $acc.Count + $ps.Count + @($bam | Where-Object { $_.Time -ge $since }).Count

    Test-ServiceInstallEvents $svc
    Test-DefenderEvents $def
    Test-AccountEvents $acc
    if ($ps) { Test-PowerShellEvents -Events $ps -OwnText (Get-OwnScriptText) }
    Test-BamEntries -Entries $bam -Since $since

    if (-not $script:IsAdmin) {
        Write-ScanWarning "Linea temporale incompleta: senza privilegi di amministratore non si leggono il registro di sicurezza (account creati) e la chiave BAM (programmi avviati)."
    }
}
