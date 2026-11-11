# Processi in esecuzione: travestimenti da processi di sistema (T1036),
# genitori anomali, eseguibili non firmati in cartelle utente, cryptominer.

function Invoke-CheckProcesses {
    $cat = 'Processi'
    $sys32 = "$env:SystemRoot\System32".ToLower()
    $wow64 = "$env:SystemRoot\SysWOW64".ToLower()
    $expected = @{
        'svchost.exe' = @($sys32, $wow64); 'lsass.exe' = @($sys32); 'csrss.exe' = @($sys32); 'smss.exe' = @($sys32)
        'wininit.exe' = @($sys32); 'winlogon.exe' = @($sys32); 'services.exe' = @($sys32); 'spoolsv.exe' = @($sys32)
        'taskhostw.exe' = @($sys32); 'dllhost.exe' = @($sys32, $wow64); 'conhost.exe' = @($sys32); 'runtimebroker.exe' = @($sys32)
        'sihost.exe' = @($sys32); 'ctfmon.exe' = @($sys32, $wow64); 'dwm.exe' = @($sys32); 'fontdrvhost.exe' = @($sys32)
        'lsaiso.exe' = @($sys32); 'searchindexer.exe' = @($sys32); 'wmiprvse.exe' = @("$sys32\wbem", "$wow64\wbem")
        'audiodg.exe' = @($sys32); 'userinit.exe' = @($sys32); 'rundll32.exe' = @($sys32, $wow64); 'regsvr32.exe' = @($sys32, $wow64)
        'explorer.exe' = @($env:SystemRoot.ToLower())
    }
    $lookalikeTargets = @($expected.Keys | ForEach-Object { $_ -replace '\.exe$', '' } | Where-Object { $_.Length -ge 5 })
    $legitNear = '^(?i)(iexplore|taskhost|svchost|services|lsass|csrss|explorer|winlogon|wininit|spoolsv|dllhost|conhost|sihost|ctfmon|smss|dwm|userinit|audiodg|rundll32|regsvr32|searchindexer|runtimebroker|fontdrvhost|lsaiso|taskhostw|wmiprvse|wmiadap|service|servicehost)$'

    $procs = Get-ProcessTable
    # Lo scanner stesso (e chi l'ha avviato) usa powershell -ExecutionPolicy Bypass: non va segnalato
    $selfChain = @{}
    $cur = $PID
    for ($n = 0; $n -lt 2 -and $cur; $n++) {
        $selfChain[[int]$cur] = $true
        $pp = $procs[[int]$cur]; if (-not $pp) { break }
        $cur = $pp.ParentProcessId
    }
    $byName = $procs.Values | Group-Object { "$($_.Name)".ToLower() } -AsHashTable -AsString

    foreach ($p in $procs.Values) {
        $name = "$($p.Name)".ToLower()
        $path = $p.ExecutablePath
        $parent = $procs[[int]$p.ParentProcessId]
        $evidence = "PID $($p.ProcessId) - $path $(if ($p.CommandLine) { '| ' + $p.CommandLine })"

        # 1) Nome di sistema ma percorso sbagliato
        if ($path -and $expected.ContainsKey($name)) {
            $dir = [IO.Path]::GetDirectoryName($path).ToLower()
            if ($dir -notin $expected[$name]) {
                $info = Get-FileInfo $path
                Add-Finding -Category $cat -Severity 'Alto' -Title "Processo travestito da $($p.Name)" -Path $path -Evidence $evidence `
                    -Mitre 'T1036.005' -Sha256 $info.Sha256 -Signer $info.Signer `
                    -Reasons "Il vero $($p.Name) si trova solo in $($expected[$name] -join ' o '). Questo gira da un'altra cartella." `
                    -Recommendation 'Termina il processo, carica il file su virustotal.com e cerca quale voce di avvio lo lancia (vedi le altre sezioni del report).'
                continue
            }
        }

        # 2) Nome quasi identico a un processo di sistema (svch0st, lsas, scvhost...)
        $base = $name -replace '\.exe$', ''
        if ($base.Length -ge 4 -and $base -notmatch $legitNear) {
            foreach ($t in $lookalikeTargets) {
                if ((Get-EditDistance $base $t) -eq 1) {
                    $info = Get-FileInfo $path
                    if ($info -and $info.IsMicrosoft) { break }
                    Add-Finding -Category $cat -Severity 'Alto' -Title "Nome che imita un processo di sistema: $($p.Name) (simile a $t.exe)" `
                        -Path $path -Evidence $evidence -Mitre 'T1036.005' -Sha256 $info.Sha256 -Signer $info.Signer `
                        -Reasons 'I malware scelgono nomi quasi identici a quelli di Windows per non dare nell''occhio in Gestione attivita''.'
                    break
                }
            }
        }

        # 3) Genitore anomalo
        if ($parent -and $parent.CreationDate -le $p.CreationDate) {
            $pname = "$($parent.Name)".ToLower()
            $badParent = $null
            if ($name -eq 'svchost.exe' -and $pname -notin 'services.exe', 'msmpeng.exe') { $badParent = 'services.exe' }
            elseif ($name -eq 'lsass.exe' -and $pname -ne 'wininit.exe') { $badParent = 'wininit.exe' }
            elseif ($name -eq 'services.exe' -and $pname -ne 'wininit.exe') { $badParent = 'wininit.exe' }
            if ($badParent) {
                Add-Finding -Category $cat -Severity 'Alto' -Title "$($p.Name) avviato da un processo insolito ($($parent.Name))" -Path $path `
                    -Evidence "$evidence | genitore: PID $($parent.ProcessId) $($parent.ExecutablePath)" -Mitre 'T1036' `
                    -Reasons "Normalmente $($p.Name) viene avviato solo da $badParent."
            }
            # Office / browser che lanciano interpreti di comandi
            if ($pname -match '^(winword|excel|powerpnt|outlook|acrord32|wordpad)\.exe$' -and $name -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$') {
                Add-Finding -Category $cat -Severity 'Alto' -Title "$($parent.Name) ha avviato $($p.Name)" -Path $path -Evidence $evidence -Mitre 'T1204.002' `
                    -Reasons 'Un documento che apre un interprete di comandi e'' il comportamento tipico di una macro malevola.'
            }
        }

        # 4) Un solo lsass e' ammesso
        if ($name -eq 'lsass.exe' -and $byName['lsass.exe'].Count -gt 1) {
            Add-Finding -Category $cat -Severity 'Alto' -Title 'Piu'' di un processo lsass.exe in esecuzione' -Path $path -Evidence $evidence -Mitre 'T1036.005' `
                -Reasons 'Deve esistere un solo lsass.exe: le copie servono a rubare credenziali o a mimetizzarsi.'
        }

        # 5) Riga di comando o eseguibile sospetti. Un programma non firmato in
        # AppData da solo e' comunissimo (plugin, launcher...): serve un indizio forte.
        if (($p.CommandLine -or $path) -and -not $selfChain.ContainsKey([int]$p.ProcessId)) {
            $cmd = $p.CommandLine; if (-not $cmd) { $cmd = "`"$path`"" }
            $risk = Get-CommandRisk $cmd
            $sev = ConvertTo-Severity $risk.Score
            $patternHit = @($script:SuspiciousPatterns | Where-Object { $risk.Reasons -contains $_.R }).Count -gt 0
            $strong = $patternHit -or ($risk.Reasons -match 'nascosto|casuale|manomessa') -or
                ($risk.Target -match '(?i)\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|^[A-Z]:\\ProgramData\\[^\\]+$|\\AppData\\(Roaming|Local|LocalLow)\\[^\\]+$')
            if ($sev -in 'Alto', 'Medio' -and $strong) {
                Add-Finding -Category $cat -Severity $sev -Title "Processo sospetto: $($p.Name) (PID $($p.ProcessId))" -Path $risk.Target `
                    -Evidence $cmd -Mitre 'T1059' -Reasons $risk.Reasons -Sha256 $risk.Sha256 -Signer $risk.Signer `
                    -Recommendation 'Controlla in Gestione attivita'' (tasto destro > Apri percorso file) e carica il file su virustotal.com.'
            }
        }
    }

    # 6) Uso CPU: i miner consumano CPU in modo costante. Campioniamo per qualche
    # secondo (Gestione attivita' non e' aperta, quindi i miner "furbi" che si
    # fermano quando la apri qui continuano a lavorare).
    $samples = @{}
    $cores = [Environment]::ProcessorCount
    $first = @{}
    foreach ($gp in Get-Process -ErrorAction SilentlyContinue) { try { $first[$gp.Id] = $gp.TotalProcessorTime.TotalSeconds } catch { } }
    $seconds = 5
    Start-Sleep -Seconds $seconds
    foreach ($gp in Get-Process -ErrorAction SilentlyContinue) {
        if (-not $first.ContainsKey($gp.Id)) { continue }
        try { $samples[$gp.Id] = (($gp.TotalProcessorTime.TotalSeconds - $first[$gp.Id]) / $seconds / $cores) * 100 } catch { }
    }
    foreach ($procId in $samples.Keys) {
        $pct = [math]::Round($samples[$procId], 1)
        if ($pct -lt 20 -or $procId -le 4) { continue }
        $p = $procs[[int]$procId]
        if (-not $p -or -not $p.ExecutablePath) { continue }
        $info = Get-FileInfo $p.ExecutablePath
        if ($info.IsMicrosoft) { continue }
        $sev = 'Basso'; $why = @("Usa il $pct% della CPU totale mentre il PC e' a riposo")
        if ($info.SignatureStatus -ne 'Valid') { $sev = 'Medio'; $why += 'Non firmato' }
        if ($info.SignatureStatus -ne 'Valid' -and (Test-UserWritablePath $p.ExecutablePath)) { $sev = 'Alto'; $why += 'Gira da una cartella utente' }
        Add-Finding -Category $cat -Severity $sev -Title "Alto consumo di CPU: $($p.Name) ($pct%)" -Path $p.ExecutablePath -Evidence $p.CommandLine `
            -Mitre 'T1496' -Reasons (@('Possibile cryptominer.') + $why) -Sha256 $info.Sha256 -Signer $info.Signer `
            -Recommendation "Se in quel momento non stavi usando quel programma, verificalo su virustotal.com. Nota: un consumo alto durante giochi, compilazioni o aggiornamenti e' normale."
    }
}
