# Running processes: disguises as system processes (T1036), odd parents, unsigned
# executables in user folders, cryptominers.

# "End process" from the app: the start time tells this process apart from another one that
# gets the same number later
function New-ProcessRemedy {
    param($Process)
    if (-not $Process.ExecutablePath) { return $null }
    $started = if ($Process.CreationDate) { ([datetime]$Process.CreationDate).ToString('o') } else { $null }
    return @{ Kind = 'Process'; ProcessId = [int]$Process.ProcessId; Path = "$($Process.ExecutablePath)"; Started = $started; Admin = $true }
}

function Invoke-CheckProcesses {
    $cat = 'Processes'
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
    # The scanner itself (and whoever started it) uses powershell -ExecutionPolicy Bypass: not reported
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

        # 1) System name but wrong location
        if ($path -and $expected.ContainsKey($name)) {
            $dir = [IO.Path]::GetDirectoryName($path).ToLower()
            if ($dir -notin $expected[$name]) {
                $info = Get-FileInfo $path
                Add-Finding -Category $cat -Severity 'High' -Title "Process disguised as $($p.Name)" -Path $path -Evidence $evidence `
                    -Mitre 'T1036.005' -Sha256 $info.Sha256 -Signer $info.Signer -Remedy (New-ProcessRemedy $p) `
                    -Reasons "The real $($p.Name) only lives in $($expected[$name] -join ' or '). This one runs from another folder." `
                    -Recommendation 'End the process, upload the file to virustotal.com and find which autostart entry launches it (see the other sections of the report).'
                continue
            }
        }

        # 2) Name almost identical to a system process (svch0st, lsas, scvhost...)
        $base = $name -replace '\.exe$', ''
        if ($base.Length -ge 4 -and $base -notmatch $legitNear) {
            foreach ($t in $lookalikeTargets) {
                if ((Get-EditDistance $base $t) -eq 1) {
                    $info = Get-FileInfo $path
                    if ($info -and $info.IsMicrosoft) { break }
                    Add-Finding -Category $cat -Severity 'High' -Title "Name imitating a system process: $($p.Name) (similar to $t.exe)" `
                        -Path $path -Evidence $evidence -Mitre 'T1036.005' -Sha256 $info.Sha256 -Signer $info.Signer -Remedy (New-ProcessRemedy $p) `
                        -Reasons 'Malware picks names almost identical to Windows ones so as not to stand out in Task Manager.'
                    break
                }
            }
        }

        # 3) Odd parent
        if ($parent -and $parent.CreationDate -le $p.CreationDate) {
            $pname = "$($parent.Name)".ToLower()
            $badParent = $null
            if ($name -eq 'svchost.exe' -and $pname -notin 'services.exe', 'msmpeng.exe') { $badParent = 'services.exe' }
            elseif ($name -eq 'lsass.exe' -and $pname -ne 'wininit.exe') { $badParent = 'wininit.exe' }
            elseif ($name -eq 'services.exe' -and $pname -ne 'wininit.exe') { $badParent = 'wininit.exe' }
            if ($badParent) {
                Add-Finding -Category $cat -Severity 'High' -Title "$($p.Name) started by an unusual process ($($parent.Name))" -Path $path `
                    -Evidence "$evidence | parent: PID $($parent.ProcessId) $($parent.ExecutablePath)" -Mitre 'T1036' `
                    -Reasons "Normally $($p.Name) is started only by $badParent."
            }
            # Office / document readers launching command interpreters
            if ($pname -match '^(winword|excel|powerpnt|outlook|acrord32|wordpad)\.exe$' -and $name -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$') {
                Add-Finding -Category $cat -Severity 'High' -Title "$($parent.Name) started $($p.Name)" -Path $path -Evidence $evidence -Mitre 'T1204.002' `
                    -Reasons 'A document that opens a command interpreter is the typical behaviour of a malicious macro.'
            }
        }

        # 4) Only one lsass is allowed
        if ($name -eq 'lsass.exe' -and $byName['lsass.exe'].Count -gt 1) {
            Add-Finding -Category $cat -Severity 'High' -Title 'More than one lsass.exe process running' -Path $path -Evidence $evidence -Mitre 'T1036.005' `
                -Reasons 'There must be only one lsass.exe: copies are used to steal credentials or to blend in.'
        }

        # 5) Suspicious command line or executable. An unsigned program in AppData on its
        # own is very common (plugins, launchers...): a strong clue is needed.
        if (($p.CommandLine -or $path) -and -not $selfChain.ContainsKey([int]$p.ProcessId)) {
            $cmd = $p.CommandLine; if (-not $cmd) { $cmd = "`"$path`"" }
            $risk = Get-CommandRisk $cmd
            $sev = ConvertTo-Severity $risk.Score
            $patternHit = @($script:SuspiciousPatterns | Where-Object { $risk.Reasons -contains $_.R }).Count -gt 0
            $strong = $patternHit -or ($risk.Reasons -match 'hidden|Random-looking|Tampered') -or
                ($risk.Target -match '(?i)\\Temp\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|^[A-Z]:\\ProgramData\\[^\\]+$|\\AppData\\(Roaming|Local|LocalLow)\\[^\\]+$')
            if ($sev -in 'High', 'Medium' -and $strong) {
                Add-Finding -Category $cat -Severity $sev -Title "Suspicious process: $($p.Name) (PID $($p.ProcessId))" -Path $risk.Target `
                    -Evidence $cmd -Mitre 'T1059' -Reasons $risk.Reasons -Sha256 $risk.Sha256 -Signer $risk.Signer -Remedy (New-ProcessRemedy $p) `
                    -Recommendation 'Check it in Task Manager (right click > Open file location) and upload the file to virustotal.com.'
            }
        }
    }

    # 6) CPU usage: miners use the CPU constantly. Sampled for a few seconds (Task Manager
    # is not open, so "smart" miners that pause when you open it keep working here).
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
        $sev = 'Low'; $why = @("Uses $pct% of total CPU while the PC is idle")
        if ($info.SignatureStatus -ne 'Valid') { $sev = 'Medium'; $why += 'Not signed' }
        if ($info.SignatureStatus -ne 'Valid' -and (Test-UserWritablePath $p.ExecutablePath)) { $sev = 'High'; $why += 'Runs from a user folder' }
        Add-Finding -Category $cat -Severity $sev -Title "High CPU usage: $($p.Name) ($pct%)" -Path $p.ExecutablePath -Evidence $p.CommandLine `
            -Mitre 'T1496' -Reasons (@('Possible cryptominer.') + $why) -Sha256 $info.Sha256 -Signer $info.Signer -Remedy (New-ProcessRemedy $p) `
            -Recommendation 'If you were not using that program at the time, check it on virustotal.com. Note: high usage during games, builds or updates is normal.'
    }
}
