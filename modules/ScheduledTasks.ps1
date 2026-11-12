# Scheduled tasks (T1053.005): the favourite persistence method of miners, RATs and
# stealers bundled with cracks, because it survives even uninstalling the game.

function Invoke-CheckScheduledTasks {
    $cat = 'Scheduled tasks'
    $visible = @{}

    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        $visible[$full.ToLowerInvariant()] = $true

        foreach ($a in $t.Actions) {
            if ($a.CimClass.CimClassName -ne 'MSFT_TaskExecAction' -or -not $a.Execute) { continue }
            $exe = $a.Execute.Trim()
            if (-not $exe.StartsWith('"')) { $exe = "`"$exe`"" }
            $cmd = "$exe $($a.Arguments)".Trim()
            # The check scheduled by the app: it is CheckBackdoor itself, not to be reported
            if ($t.TaskPath -eq '\CheckBackdoor\' -and (Test-OwnEngineCommand $cmd)) {
                Add-InventoryItem $cat "Task: $full | $($t.TaskName)" $cmd
                continue
            }

            $extra = 0; $why = @()
            $risk = Get-CommandRisk $cmd
            $info = $null; if ($risk.Target) { $info = Get-FileInfo $risk.Target }
            $isMs = $info -and $info.IsMicrosoft

            if ($t.Settings.Hidden -and -not $isMs) { $extra += 10; $why += 'The task is marked as hidden' }
            if ($t.TaskPath -like '\Microsoft\*' -and $info -and $info.Exists -and -not $isMs -and $info.SignatureStatus -ne 'Valid') {
                $extra += 25; $why += 'It hides in the \Microsoft\ folder but the program is not signed by Microsoft'
            }
            if ($t.Principal.UserId -match '(?i)SYSTEM|S-1-5-18' -and $risk.Target -and (Test-UserWritablePath $risk.Target) -and -not $isMs) {
                $extra += 15; $why += 'Runs as SYSTEM but executes a file from a user folder'
            }
            if ($risk.Score -gt 0) {
                $rep = @($t.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval -match '^PT([1-9]|1[0-5])M$' })
                if ($rep) { $extra += 5; $why += "Repeats very often ($($rep[0].Repetition.Interval)): typical of something that wants to restart if closed" }
            }

            Register-AutorunEntry -Category $cat -Location "Task: $full" -Name $t.TaskName -Command $cmd -Mitre 'T1053.005' `
                -ExtraScore $extra -ExtraReasons $why -Remedy @{ Kind = 'ScheduledTask'; Path = $t.TaskPath; Name = $t.TaskName; Admin = $true } `
                -Recommendation "Open Task Scheduler (taskschd.msc), find '$full', disable it and, once you confirm it is malicious, delete it together with the file it runs."
        }
    }

    # Tasks hidden with the "Tarrask" technique: the malware deletes the SD value from
    # the registry and the task disappears from schtasks and the interface, but keeps
    # working. They are looked for directly in the registry.
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
                    Add-Finding -Category $cat -Severity 'High' -Title "Hidden scheduled task: $rel" -Detail $k.Name `
                        -Evidence "Id = $id (the SD security descriptor is missing)" -Mitre 'T1053.005' `
                        -Reasons 'The security descriptor was removed on purpose to make it invisible (Tarrask technique used by APT groups)' `
                        -Recommendation "Export and analyse the registry key and the folder C:\Windows\System32\Tasks$rel; then delete both."
                } elseif (-not $visible.ContainsKey($rel.ToLowerInvariant()) -and $script:IsAdmin) {
                    Add-Finding -Category $cat -Severity 'Medium' -Title "Task in the registry but not visible: $rel" -Detail $k.Name `
                        -Evidence "Id = $id" -Mitre 'T1053.005' `
                        -Reasons 'The task exists in the registry but Windows does not list it: it may have been hidden, or it is a corrupted leftover'
                }
            }
            $stack.Push($k.PSPath)
        }
    }

    # Tasks that exist only as XML files in System32\Tasks: Windows does not know them,
    # but re-importing them (or restoring the registry) is enough to bring them back.
    if ($script:IsAdmin) {
        $tasksDir = Join-Path $env:SystemRoot 'System32\Tasks'
        foreach ($f in Get-ChildItem -LiteralPath $tasksDir -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $rel = $f.FullName.Substring($tasksDir.Length)
            $key = $rel.ToLowerInvariant()
            if ($visible.ContainsKey($key) -or $inRegistry.ContainsKey($key)) { continue }
            $cmd = Get-TaskXmlCommand $f.FullName
            if (-not $cmd) { continue }
            Register-AutorunEntry -Category $cat -Location "XML file without a task: $rel" -Name $f.Name -Command $cmd -Mitre 'T1053.005' `
                -ExtraScore 15 -ExtraReasons 'The task file exists but Windows does not list it: a leftover, or a task prepared to be registered later' `
                -Recommendation "Open $($f.FullName) in Notepad to see what it runs; if you do not recognise it, delete it together with the program it points to."
        }
    }
}

# Command run by a task, read from its XML file
function Get-TaskXmlCommand {
    param([string]$Path)
    try { [xml]$x = [IO.File]::ReadAllText($Path) } catch { return $null }
    $exec = @($x.Task.Actions.Exec) | Where-Object { $_ -and $_.Command } | Select-Object -First 1
    if (-not $exec) { return $null }
    $c = [string]$exec.Command
    if (-not $c.StartsWith('"')) { $c = "`"$c`"" }
    return "$c $($exec.Arguments)".Trim()
}
