# Attivita' pianificate (T1053.005): il metodo di persistenza preferito da miner,
# RAT e stealer distribuiti nei crack, perche' sopravvive anche alla
# disinstallazione del gioco.

function Invoke-CheckScheduledTasks {
    $cat = "Attivita' pianificate"
    $visible = @{}

    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        $visible[$full.ToLowerInvariant()] = $true

        foreach ($a in $t.Actions) {
            if ($a.CimClass.CimClassName -ne 'MSFT_TaskExecAction' -or -not $a.Execute) { continue }
            $exe = $a.Execute.Trim()
            if (-not $exe.StartsWith('"')) { $exe = "`"$exe`"" }
            $cmd = "$exe $($a.Arguments)".Trim()
            # La verifica programmata dall'app: e' CheckBackdoor stesso, non va segnalata
            if ($t.TaskPath -eq '\CheckBackdoor\' -and (Test-OwnEngineCommand $cmd)) {
                Add-InventoryItem $cat "Attivita': $full | $($t.TaskName)" $cmd
                continue
            }

            $extra = 0; $why = @()
            $risk = Get-CommandRisk $cmd
            $info = $null; if ($risk.Target) { $info = Get-FileInfo $risk.Target }
            $isMs = $info -and $info.IsMicrosoft

            if ($t.Settings.Hidden -and -not $isMs) { $extra += 10; $why += "L'attivita' e' contrassegnata come nascosta" }
            if ($t.TaskPath -like '\Microsoft\*' -and $info -and $info.Exists -and -not $isMs -and $info.SignatureStatus -ne 'Valid') {
                $extra += 25; $why += "Si mimetizza nella cartella \Microsoft\ ma il programma non e' firmato Microsoft"
            }
            if ($t.Principal.UserId -match '(?i)SYSTEM|S-1-5-18' -and $risk.Target -and (Test-UserWritablePath $risk.Target) -and -not $isMs) {
                $extra += 15; $why += 'Gira come SYSTEM ma esegue un file da una cartella utente'
            }
            if ($risk.Score -gt 0) {
                $rep = @($t.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval -match '^PT([1-9]|1[0-5])M$' })
                if ($rep) { $extra += 5; $why += "Si ripete molto spesso ($($rep[0].Repetition.Interval)): tipico di chi vuole riavviarsi se viene chiuso" }
            }

            Register-AutorunEntry -Category $cat -Location "Attivita': $full" -Name $t.TaskName -Command $cmd -Mitre 'T1053.005' `
                -ExtraScore $extra -ExtraReasons $why -Remedy @{ Kind = 'ScheduledTask'; Path = $t.TaskPath; Name = $t.TaskName; Admin = $true } `
                -Recommendation "Apri Utilita' di pianificazione (taskschd.msc), trova '$full', disattivala e, se confermi che e' malevola, eliminala insieme al file che esegue."
        }
    }

    # Attivita' nascoste con la tecnica "Tarrask": il malware cancella il valore
    # SD dal registro e l'attivita' sparisce da schtasks e dall'interfaccia, ma
    # continua a funzionare. Le cerchiamo direttamente nel registro.
    $inRegistry = @{}
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $stack = New-Object System.Collections.Stack
    $stack.Push($tree)
    while ($stack.Count -gt 0) {
        $p = $stack.Pop()
        foreach ($k in Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue) {
            $id = Get-RegValue $k.PSPath 'Id'
            if ($id) {
                $rel = ($k.Name -replace '^.*\\TaskCache\\Tree', '')
                $inRegistry[$rel.ToLowerInvariant()] = $true
                $names = $k.GetValueNames()
                if ($script:IsAdmin -and -not ($names -contains 'SD')) {
                    Add-Finding -Category $cat -Severity 'Alto' -Title "Attivita' pianificata nascosta: $rel" -Detail $k.Name `
                        -Evidence "Id = $id (manca il descrittore di sicurezza SD)" -Mitre 'T1053.005' `
                        -Reasons "Il descrittore di sicurezza e' stato rimosso apposta per renderla invisibile (tecnica Tarrask usata da gruppi APT)" `
                        -Recommendation "Esporta e analizza la chiave del registro e la cartella C:\Windows\System32\Tasks$rel; poi elimina entrambe."
                } elseif (-not $visible.ContainsKey($rel.ToLowerInvariant()) -and $script:IsAdmin) {
                    Add-Finding -Category $cat -Severity 'Medio' -Title "Attivita' presente nel registro ma non visibile: $rel" -Detail $k.Name `
                        -Evidence "Id = $id" -Mitre 'T1053.005' `
                        -Reasons "L'attivita' esiste nel registro ma Windows non la elenca: potrebbe essere stata nascosta o essere un residuo corrotto"
                }
            }
            $stack.Push($k.PSPath)
        }
    }

    # Attivita' presenti solo come file XML in System32\Tasks: Windows non le conosce,
    # ma basta reimportarle (o ripristinare il registro) per riattivarle.
    if ($script:IsAdmin) {
        $tasksDir = Join-Path $env:SystemRoot 'System32\Tasks'
        foreach ($f in Get-ChildItem -LiteralPath $tasksDir -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $rel = $f.FullName.Substring($tasksDir.Length)
            $key = $rel.ToLowerInvariant()
            if ($visible.ContainsKey($key) -or $inRegistry.ContainsKey($key)) { continue }
            $cmd = Get-TaskXmlCommand $f.FullName
            if (-not $cmd) { continue }
            Register-AutorunEntry -Category $cat -Location "File XML senza attivita': $rel" -Name $f.Name -Command $cmd -Mitre 'T1053.005' `
                -ExtraScore 15 -ExtraReasons "Il file dell'attivita' esiste ma Windows non la elenca: e' un residuo o un'attivita' preparata per essere registrata in seguito" `
                -Recommendation "Apri il file $($f.FullName) con il Blocco note per vedere cosa esegue; se non lo riconosci, eliminalo insieme al programma indicato."
        }
    }
}

# Comando eseguito da un'attivita', letto dal suo file XML
function Get-TaskXmlCommand {
    param([string]$Path)
    try { [xml]$x = [IO.File]::ReadAllText($Path) } catch { return $null }
    $exec = @($x.Task.Actions.Exec) | Where-Object { $_ -and $_.Command } | Select-Object -First 1
    if (-not $exec) { return $null }
    $c = [string]$exec.Command
    if (-not $c.StartsWith('"')) { $c = "`"$c`"" }
    return "$c $($exec.Arguments)".Trim()
}
