# Servizi e driver (T1543.003, T1014): girano come SYSTEM o nel kernel, quindi
# sono la forma di persistenza piu' pericolosa.

function Invoke-CheckServices {
    $cat = 'Servizi'
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if (-not $s.PathName) { continue }
        $cmd = $s.PathName
        # I servizi ospitati da svchost caricano una DLL: e' quella da analizzare
        if ($cmd -match '(?i)\\svchost\.exe') {
            $dll = Get-RegValue "$svcKey\$($s.Name)\Parameters" 'ServiceDll'
            if (-not $dll) { $dll = Get-RegValue "$svcKey\$($s.Name)" 'ServiceDll' }
            if ($dll) { $cmd = "`"$([Environment]::ExpandEnvironmentVariables($dll))`"" }
        }
        $extra = 0; $why = @()
        # Molti servizi legittimi in Program Files non sono firmati: il rischio sale
        # solo se un servizio SYSTEM esegue un file che un utente qualsiasi puo' sostituire.
        if ($s.StartMode -eq 'Auto' -and $s.StartName -match '(?i)LocalSystem') {
            $target = Resolve-CommandPath $cmd
            if ($target -and (Test-UserWritablePath $target) -and -not (Get-FileInfo $target).IsMicrosoft) {
                $extra += 15; $why += 'Servizio con privilegi massimi (LocalSystem) che esegue un file da una cartella utente'
            }
        }
        # Percorso non quotato con spazi: vulnerabilita' sfruttabile per scalare privilegi
        if ($s.PathName -notmatch '^"' -and $s.PathName -match '^(?i)[A-Z]:\\[^"]*\s[^"]*\.exe') {
            $exePart = ([regex]::Match($s.PathName, '^(?i)(.+?\.exe)')).Groups[1].Value
            if ($exePart -match '\s') {
                Add-Finding -Category $cat -Severity 'Basso' -Title "Percorso del servizio senza virgolette: $($s.Name)" -Evidence $s.PathName `
                    -Mitre 'T1574.009' -Reasons 'Non e'' una backdoor, ma una debolezza che un malware puo'' sfruttare per ottenere privilegi SYSTEM.' `
                    -Recommendation 'Aggiorna il programma che ha installato il servizio o aggiungi le virgolette al percorso (ImagePath nel registro).'
            }
        }
        # Solo il tipo di avvio nella chiave: lo stato (in esecuzione/fermo) cambia da solo
        # e renderebbe rumoroso il confronto tra scansioni.
        Register-AutorunEntry -Category $cat -Location "Servizio: $($s.Name) [avvio $($s.StartMode)]" -Name "$($s.DisplayName) ($($s.Name))" `
            -Command $cmd -Mitre 'T1543.003' -ExtraScore $extra -ExtraReasons $why `
            -Remedy @{ Kind = 'Service'; Name = $s.Name; Admin = $true } `
            -Recommendation "Apri services.msc, imposta il servizio '$($s.Name)' su Disabilitato e fermalo; poi analizza il file. Elimina il servizio (sc.exe delete $($s.Name)) solo quando sei sicuro."
    }

    # --- Driver del kernel: un driver malevolo e' di fatto un rootkit -------
    foreach ($d in Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue) {
        if (-not $d.PathName) { continue }
        # Tutti i driver non disabilitati, non solo quelli in esecuzione in questo momento:
        # cosi' il confronto tra due scansioni non cambia a seconda di cosa e' caricato.
        if ($d.StartMode -eq 'Disabled') { continue }
        $path = Resolve-CommandPath $d.PathName
        $extra = 0; $why = @()
        $info = Get-FileInfo $path
        if ($info.Exists -and -not $info.IsMicrosoft) {
            if ($info.SignatureStatus -ne 'Valid') { $extra += 30; $why += 'Driver del kernel senza firma valida: puo'' nascondere file, processi e connessioni (rootkit)' }
            if ($path -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)\\|\\Windows\\SysWOW64\\|\\Program Files') { $extra += 25; $why += 'Driver caricato da una posizione insolita' }
        }
        Register-AutorunEntry -Category 'Driver' -Location "Driver: $($d.Name) [avvio $($d.StartMode)]" -Name "$($d.DisplayName) ($($d.Name))" `
            -Command "`"$path`"" -Mitre 'T1014' -ExtraScore $extra -ExtraReasons $why `
            -Recommendation 'Non eliminare driver a mano: cerca il nome online e usa un antirootkit dedicato (es. Malwarebytes, Kaspersky TDSSKiller) o lo scanner offline di Defender.'
    }

    # --- Servizi abilitati in Modalita' provvisoria -------------------------
    # Crackonosh si registra qui per partire in Modalita' provvisoria, dove
    # l'antivirus non gira, e da li' disattivare Defender.
    foreach ($mode in 'Minimal', 'Network') {
        $sb = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode"
        foreach ($k in Get-ChildItem -LiteralPath $sb -ErrorAction SilentlyContinue) {
            $name = $k.PSChildName
            $img = Get-RegValue "$svcKey\$name" 'ImagePath'
            if (-not $img) { continue }
            Add-InventoryItem 'Modalita provvisoria' "$mode | $name" $img
            $risk = Get-CommandRisk $img
            $info = $null; if ($risk.Target) { $info = Get-FileInfo $risk.Target }
            if ($info -and $info.Exists -and -not $info.IsMicrosoft -and $info.SignatureStatus -ne 'Valid') {
                Add-Finding -Category $cat -Severity 'Alto' -Title "Servizio non firmato abilitato in Modalita' provvisoria: $name" -Detail $sb `
                    -Path $risk.Target -Evidence $img -Mitre 'T1562.009' -Sha256 $info.Sha256 `
                    -Reasons (@("Tecnica usata dal malware Crackonosh (giochi crackati) per disattivare l'antivirus avviandosi in Modalita' provvisoria") + $risk.Reasons)
            }
        }
    }

    # --- RDP Wrapper: abilita il Desktop remoto su Windows Home ------------
    $rdpDll = Get-RegValue "$svcKey\TermService\Parameters" 'ServiceDll'
    if ($rdpDll -and $rdpDll -notmatch '(?i)\\termsrv\.dll$') {
        Add-Finding -Category $cat -Severity 'Alto' -Title 'Servizio Desktop remoto dirottato (RDP Wrapper)' -Detail "$svcKey\TermService\Parameters" `
            -Evidence "ServiceDll = $rdpDll" -Mitre 'T1021.001' `
            -Reasons "Al posto di termsrv.dll viene caricata un'altra DLL: e' il modo con cui molti malware aprono un accesso Desktop remoto nascosto." `
            -Recommendation 'Ripristina ServiceDll a %SystemRoot%\System32\termsrv.dll ed elimina la DLL indicata (spesso in C:\Program Files\RDP Wrapper).'
    }
}
