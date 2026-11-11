# Difese indebolite (T1562.001): la prima cosa che fa un malware dei crack e'
# aggiungere esclusioni a Defender o spegnerlo, cosi' tutto il resto passa inosservato.

function Invoke-CheckSecurity {
    $cat = 'Difese di Windows'

    # Antivirus registrati nel Centro sicurezza
    $avs = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
    $thirdPartyAv = @($avs | Where-Object { $_.displayName -notmatch '(?i)Windows Defender|Microsoft Defender' })
    foreach ($a in $avs) { Add-InventoryItem $cat "Antivirus | $($a.displayName)" "$($a.pathToSignedProductExe)" }

    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($status) {
        if (-not $thirdPartyAv) {
            if (-not $status.RealTimeProtectionEnabled) {
                Add-Finding -Category $cat -Severity 'Alto' -Title 'Protezione in tempo reale di Defender DISATTIVATA' -Mitre 'T1562.001' `
                    -Reasons 'Non risulta installato un altro antivirus, quindi il PC non e'' protetto. Molti crack chiedono di disattivarla: e'' proprio cosi'' che passano i malware.' `
                    -Recommendation 'Riattivala da Sicurezza di Windows > Protezione da virus e minacce. Se si spegne da sola, e'' un forte indizio di infezione.'
            }
            if (-not $status.AntivirusEnabled -or -not $status.AMServiceEnabled) {
                Add-Finding -Category $cat -Severity 'Alto' -Title 'Microsoft Defender non attivo' -Mitre 'T1562.001' `
                    -Evidence "AntivirusEnabled=$($status.AntivirusEnabled) AMServiceEnabled=$($status.AMServiceEnabled)" `
                    -Reasons 'Il motore antivirus e'' spento e non c''e'' un antivirus alternativo.'
            }
            if ($status.AntivirusSignatureAge -gt 7) {
                Add-Finding -Category $cat -Severity 'Medio' -Title "Firme antivirus vecchie di $($status.AntivirusSignatureAge) giorni" -Mitre 'T1562.001' `
                    -Reasons 'Defender non si aggiorna: puo'' dipendere da Windows Update bloccato o dal file hosts modificato.'
            }
        }
        if ($status.PSObject.Properties['IsTamperProtected'] -and -not $status.IsTamperProtected -and -not $thirdPartyAv) {
            Add-Finding -Category $cat -Severity 'Basso' -Title 'Protezione da manomissioni disattivata' -Mitre 'T1562.001' `
                -Reasons 'Senza questa protezione un malware con privilegi di amministratore puo'' spegnere Defender.' `
                -Recommendation 'Sicurezza di Windows > Protezione da virus e minacce > Gestisci impostazioni > Protezione da manomissioni: Attivato.'
        }
    }

    # Esclusioni: il segnale piu' tipico dei malware nei crack
    $pref = $null
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
    $exclusions = @()
    if ($pref) {
        foreach ($e in @($pref.ExclusionPath)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Percorso'; Value = $e } } }
        foreach ($e in @($pref.ExclusionProcess)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Processo'; Value = $e } } }
        foreach ($e in @($pref.ExclusionExtension)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Estensione'; Value = $e } } }
        foreach ($e in @($pref.ExclusionIpAddress)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Indirizzo IP'; Value = $e } } }
    }
    # Le esclusioni impostate tramite Criteri di gruppo stanno qui
    foreach ($t in 'Paths', 'Processes', 'Extensions', 'IpAddresses') {
        foreach ($base in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions') {
            foreach ($v in Get-RegValues "$base\$t") { $exclusions += [pscustomobject]@{ Type = $t; Value = $v.Name } }
        }
    }
    $hiddenByPerm = $exclusions | Where-Object { $_.Value -match '^N/A' }
    $exclusions = @($exclusions | Where-Object { $_.Value -notmatch '^N/A' } | Sort-Object Type, Value -Unique)
    if ($hiddenByPerm -or (-not $script:IsAdmin -and -not $exclusions)) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'Esclusioni di Defender non leggibili' `
            -Reasons 'Avvia la scansione come amministratore per vedere le esclusioni di Defender: e'' uno dei controlli piu'' importanti.'
    }
    foreach ($e in $exclusions) {
        Add-InventoryItem $cat "Esclusione Defender | $($e.Type)" $e.Value
        $v = [Environment]::ExpandEnvironmentVariables($e.Value)
        $sev = 'Medio'
        $why = @('Defender non analizzera'' nulla di cio'' che corrisponde a questa esclusione.')
        if ($v -match '^(?i)([A-Z]:\\?|\\|\*|.*\\Users\\?[^\\]*\\?|.*\\AppData(\\(Roaming|Local))?\\?|.*\\Temp\\?|.*\\ProgramData\\?|.*\\Windows(\\System32)?\\?|.*\\Downloads\\?|.*\\Desktop\\?)$' -or
            $v -match '^(?i)\.?(exe|dll|ps1|vbs|js|bat|cmd|scr|tmp|com)$' -or
            $v -match '(?i)\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|svchost|explorer)\.exe$') {
            $sev = 'Alto'; $why += 'Esclusione molto ampia o su un programma di sistema: e'' esattamente cio'' che fanno i miner e i RAT distribuiti con i crack.'
        }
        Add-Finding -Category $cat -Severity $sev -Title "Esclusione di Defender ($($e.Type)): $($e.Value)" -Evidence $e.Value -Mitre 'T1562.001' `
            -Reasons $why -Recommendation "Se non l'hai aggiunta tu: Sicurezza di Windows > Protezione da virus e minacce > Gestisci impostazioni > Esclusioni, rimuovila, poi esegui una scansione COMPLETA e una 'Microsoft Defender Offline'."
    }

    # Defender disattivato tramite criteri (registro)
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $polChecks = @(
        @{ P = $pol; N = 'DisableAntiSpyware' }; @{ P = $pol; N = 'DisableAntiVirus' }
        @{ P = "$pol\Real-Time Protection"; N = 'DisableRealtimeMonitoring' }; @{ P = "$pol\Real-Time Protection"; N = 'DisableBehaviorMonitoring' }
        @{ P = "$pol\Real-Time Protection"; N = 'DisableOnAccessProtection' }; @{ P = "$pol\Real-Time Protection"; N = 'DisableScanOnRealtimeEnable' }
        @{ P = "$pol\Spynet"; N = 'SpynetReporting'; Bad = 0 }; @{ P = "$pol\Spynet"; N = 'SubmitSamplesConsent'; Bad = 2 }
    )
    foreach ($c in $polChecks) {
        $val = Get-RegValue $c.P $c.N
        if ($null -eq $val) { continue }
        $bad = 1; if ($c.ContainsKey('Bad')) { $bad = $c.Bad }
        if ($val -eq $bad) {
            Add-Finding -Category $cat -Severity 'Alto' -Title "Criterio che indebolisce Defender: $($c.N) = $val" -Detail $c.P -Mitre 'T1562.001' `
                -Reasons 'Su un PC di casa nessuno imposta questi criteri: sono tipici dei "Defender killer" inclusi nei crack.' `
                -Recommendation "Elimina il valore $($c.N) dalla chiave $($c.P) e riavvia."
        }
    }

    # Cronologia delle minacce rilevate da Defender
    try {
        $threats = @{}
        foreach ($t in Get-MpThreat -ErrorAction Stop) { $threats[[string]$t.ThreatID] = $t }
        foreach ($d in Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 40) {
            $t = $threats[[string]$d.ThreatID]
            $name = if ($t) { $t.ThreatName } else { "ID $($d.ThreatID)" }
            $sev = 'Basso'
            if ($name -match '(?i)Backdoor|Trojan|PWS|Stealer|RAT|CoinMiner|Rootkit|Ransom|Dropper|Bladabindi|AsyncRat|Remcos|Lumma|RedLine|Vidar|Raccoon') { $sev = 'Medio' }
            if ($d.ActionSuccess -eq $false) { $sev = 'Alto' }
            Add-Finding -Category $cat -Severity $sev -Title "Defender ha rilevato: $name" -Evidence (($d.Resources | Select-Object -First 3) -join ' ; ') `
                -Detail "Rilevato il $($d.InitialDetectionTime); azione riuscita: $($d.ActionSuccess)" `
                -Reasons @('Questa minaccia e'' gia'' stata vista da Defender sul PC.', $(if ($d.ActionSuccess -eq $false) { 'La rimozione NON e'' riuscita: la minaccia potrebbe essere ancora attiva.' })) `
                -Recommendation 'Se si tratta di un Trojan/Backdoor/Stealer, considera compromesse le password salvate nel browser: cambiale da un altro dispositivo e attiva la verifica in due passaggi.'
        }
    } catch { }

    # Windows Update e servizi di sicurezza disattivati o rimossi (es. Crackonosh)
    foreach ($svc in @(
            @{ N = 'wuauserv'; D = 'Windows Update' }, @{ N = 'WinDefend'; D = 'Microsoft Defender Antivirus' },
            @{ N = 'SecurityHealthService'; D = 'Servizio Sicurezza di Windows' }, @{ N = 'WdNisSvc'; D = 'Defender Network Inspection' },
            @{ N = 'mpssvc'; D = 'Windows Firewall' }, @{ N = 'BITS'; D = 'Servizio trasferimento intelligente (BITS)' })) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$($svc.N)'" -ErrorAction SilentlyContinue
        if (-not $s) {
            if ($svc.N -in 'wuauserv', 'mpssvc') {
                Add-Finding -Category $cat -Severity 'Alto' -Title "Servizio $($svc.D) mancante" -Mitre 'T1562.001' `
                    -Reasons 'Il servizio e'' stato eliminato: comportamento documentato di malware come Crackonosh.'
            }
            continue
        }
        if ($s.StartMode -eq 'Disabled' -and -not ($svc.N -in 'WinDefend', 'WdNisSvc' -and $thirdPartyAv)) {
            Add-Finding -Category $cat -Severity 'Medio' -Title "Servizio $($svc.D) disabilitato" -Evidence "$($s.Name): $($s.StartMode)" -Mitre 'T1562.001' `
                -Reasons 'Un servizio di sicurezza/aggiornamento disabilitato impedisce di ricevere protezioni. Alcuni "tool di ottimizzazione" lo fanno, ma anche molti malware.'
        }
    }
    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if ((Get-RegValue $wuPol 'NoAutoUpdate') -eq 1) {
        Add-Finding -Category $cat -Severity 'Basso' -Title 'Aggiornamenti automatici disattivati tramite criterio' -Detail $wuPol -Mitre 'T1562.001' `
            -Reasons 'Windows non scarica le patch di sicurezza.'
    }

    # UAC
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ((Get-RegValue $uac 'EnableLUA') -eq 0) {
        Add-Finding -Category $cat -Severity 'Medio' -Title 'Controllo account utente (UAC) disattivato' -Detail $uac -Mitre 'T1548.002' `
            -Reasons 'Senza UAC qualsiasi programma ottiene i privilegi di amministratore senza chiedere.'
    } elseif ((Get-RegValue $uac 'ConsentPromptBehaviorAdmin') -eq 0) {
        Add-Finding -Category $cat -Severity 'Basso' -Title 'UAC eleva i programmi senza chiedere conferma' -Detail $uac -Mitre 'T1548.002' `
            -Reasons 'ConsentPromptBehaviorAdmin = 0: i programmi diventano amministratori senza mostrare la finestra di conferma.'
    }

    # Programmi di accessibilita' sostituiti (backdoor della schermata di login)
    foreach ($exe in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:SystemRoot\System32" $exe
        $info = Get-FileInfo $p
        if (-not $info.Exists) { continue }
        $cmdHash = Get-FileSha256 "$env:SystemRoot\System32\cmd.exe"
        $psHash = Get-FileSha256 "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        if (-not $info.IsMicrosoft -or (Get-FileSha256 $p) -in $cmdHash, $psHash -or $info.OriginalName -match '(?i)^(cmd|powershell|explorer)') {
            Add-Finding -Category $cat -Severity 'Alto' -Title "$exe e' stato sostituito" -Path $p -Sha256 $info.Sha256 -Signer $info.Signer -Mitre 'T1546.008' `
                -Evidence "Firma: $($info.SignatureStatus) $($info.Signer); nome originale: $($info.OriginalName)" `
                -Reasons "Sostituire $exe con cmd.exe permette di aprire un prompt SYSTEM dalla schermata di login senza password." `
                -Recommendation 'Esegui da prompt amministratore: sfc /scannow (ripristina il file originale).'
        }
    }

    # Avvio in Modalita' provvisoria forzato (Crackonosh) - richiede admin
    if ($script:IsAdmin) {
        $bcd = (bcdedit /enum '{current}' 2>$null) -join "`n"
        if ($bcd -match '(?im)^\s*safeboot\s') {
            Add-Finding -Category $cat -Severity 'Alto' -Title "Avvio in Modalita' provvisoria forzato" -Evidence ($bcd -split "`n" | Where-Object { $_ -match 'safeboot' }) -Mitre 'T1562.009' `
                -Reasons 'Al prossimo riavvio Windows partira'' in Modalita'' provvisoria, dove l''antivirus non gira.' `
                -Recommendation 'Esegui da prompt amministratore: bcdedit /deletevalue {current} safeboot'
        }
    }
}
