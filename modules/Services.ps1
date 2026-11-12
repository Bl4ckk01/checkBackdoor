# Services and drivers (T1543.003, T1014): they run as SYSTEM or in the kernel, which
# makes them the most dangerous form of persistence.

function Invoke-CheckServices {
    $cat = 'Services'
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if (-not $s.PathName) { continue }
        $cmd = $s.PathName
        # Services hosted by svchost load a DLL: that is the file to analyse
        if ($cmd -match '(?i)\\svchost\.exe') {
            $dll = Get-RegValue "$svcKey\$($s.Name)\Parameters" 'ServiceDll'
            if (-not $dll) { $dll = Get-RegValue "$svcKey\$($s.Name)" 'ServiceDll' }
            if ($dll) { $cmd = "`"$([Environment]::ExpandEnvironmentVariables($dll))`"" }
        }
        $extra = 0; $why = @()
        # Many legitimate services in Program Files are not signed: the risk goes up only
        # when a SYSTEM service runs a file that any user can replace.
        if ($s.StartMode -eq 'Auto' -and $s.StartName -match '(?i)LocalSystem') {
            $target = Resolve-CommandPath $cmd
            if ($target -and (Test-UserWritablePath $target) -and -not (Get-FileInfo $target).IsMicrosoft) {
                $extra += 15; $why += 'Service with full privileges (LocalSystem) that runs a file from a user folder'
            }
        }
        # Unquoted path with spaces: a weakness that can be exploited to gain privileges
        if ($s.PathName -notmatch '^"' -and $s.PathName -match '^(?i)[A-Z]:\\[^"]*\s[^"]*\.exe') {
            $exePart = ([regex]::Match($s.PathName, '^(?i)(.+?\.exe)')).Groups[1].Value
            if ($exePart -match '\s') {
                Add-Finding -Category $cat -Severity 'Low' -Title "Unquoted service path: $($s.Name)" -Evidence $s.PathName `
                    -Mitre 'T1574.009' -Reasons 'It is not a backdoor, but a weakness that malware can exploit to gain SYSTEM rights.' `
                    -Recommendation 'Update the program that installed the service, or add quotes around the path (ImagePath in the registry).'
            }
        }
        # Only the start type in the key: the state (running/stopped) changes on its own
        # and would make the comparison between scans noisy.
        Register-AutorunEntry -Category $cat -Location "Service: $($s.Name) [start $($s.StartMode)]" -Name "$($s.DisplayName) ($($s.Name))" `
            -Command $cmd -Mitre 'T1543.003' -ExtraScore $extra -ExtraReasons $why `
            -Remedy @{ Kind = 'Service'; Name = $s.Name; Admin = $true } `
            -Recommendation "Open services.msc, set the '$($s.Name)' service to Disabled and stop it; then analyse the file. Delete the service (sc.exe delete $($s.Name)) only once you are sure."
    }

    # --- Kernel drivers: a malicious driver is effectively a rootkit ---------------
    foreach ($d in Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue) {
        if (-not $d.PathName) { continue }
        # Every driver that is not disabled, not just those running right now: this way
        # the comparison between two scans does not depend on what is loaded.
        if ($d.StartMode -eq 'Disabled') { continue }
        $path = Resolve-CommandPath $d.PathName
        $extra = 0; $why = @()
        $info = Get-FileInfo $path
        if ($info.Exists -and -not $info.IsMicrosoft) {
            if ($info.SignatureStatus -ne 'Valid') { $extra += 30; $why += 'Kernel driver without a valid signature: it can hide files, processes and connections (rootkit)' }
            if ($path -notmatch '(?i)\\Windows\\System32\\(drivers|DriverStore)\\|\\Windows\\SysWOW64\\|\\Program Files') { $extra += 25; $why += 'Driver loaded from an unusual location' }
        }
        Register-AutorunEntry -Category 'Drivers' -Location "Driver: $($d.Name) [start $($d.StartMode)]" -Name "$($d.DisplayName) ($($d.Name))" `
            -Command "`"$path`"" -Mitre 'T1014' -ExtraScore $extra -ExtraReasons $why `
            -Recommendation 'Do not delete drivers by hand: search the name online and use a dedicated anti-rootkit tool (e.g. Malwarebytes, Kaspersky TDSSKiller) or Microsoft Defender Offline.'
    }

    # --- Services enabled in Safe Mode -------------------------------------------------
    # Crackonosh registers itself here to start in Safe Mode, where the antivirus does
    # not run, and from there it turns Defender off.
    foreach ($mode in 'Minimal', 'Network') {
        $sb = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode"
        foreach ($k in Get-ChildItem -LiteralPath $sb -ErrorAction SilentlyContinue) {
            $name = $k.PSChildName
            $img = Get-RegValue "$svcKey\$name" 'ImagePath'
            if (-not $img) { continue }
            Add-InventoryItem 'Safe Mode' "$mode | $name" $img
            $risk = Get-CommandRisk $img
            $info = $null; if ($risk.Target) { $info = Get-FileInfo $risk.Target }
            if ($info -and $info.Exists -and -not $info.IsMicrosoft -and $info.SignatureStatus -ne 'Valid') {
                Add-Finding -Category $cat -Severity 'High' -Title "Unsigned service enabled in Safe Mode: $name" -Detail $sb `
                    -Path $risk.Target -Evidence $img -Mitre 'T1562.009' -Sha256 $info.Sha256 `
                    -Reasons (@('Technique used by the Crackonosh malware (cracked games) to disable the antivirus by starting in Safe Mode') + $risk.Reasons)
            }
        }
    }

    # --- RDP Wrapper: enables Remote Desktop on Windows Home ------------------------
    $rdpDll = Get-RegValue "$svcKey\TermService\Parameters" 'ServiceDll'
    if ($rdpDll -and $rdpDll -notmatch '(?i)\\termsrv\.dll$') {
        Add-Finding -Category $cat -Severity 'High' -Title 'Remote Desktop service hijacked (RDP Wrapper)' -Detail "$svcKey\TermService\Parameters" `
            -Evidence "ServiceDll = $rdpDll" -Mitre 'T1021.001' `
            -Reasons 'Another DLL is loaded instead of termsrv.dll: this is how a lot of malware opens hidden Remote Desktop access.' `
            -Recommendation 'Set ServiceDll back to %SystemRoot%\System32\termsrv.dll and delete the DLL it points to (often in C:\Program Files\RDP Wrapper).'
    }
}
