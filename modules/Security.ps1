# Weakened defenses (T1562.001): the first thing malware from cracks does is add
# Defender exclusions or turn it off, so everything else goes unnoticed.

function Invoke-CheckSecurity {
    $cat = 'Windows defenses'

    # Antivirus products registered in Security Center
    $avs = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
    $thirdPartyAv = @($avs | Where-Object { $_.displayName -notmatch '(?i)Windows Defender|Microsoft Defender' })
    foreach ($a in $avs) { Add-InventoryItem $cat "Antivirus | $($a.displayName)" "$($a.pathToSignedProductExe)" }

    $status = $null
    try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($status) {
        if (-not $thirdPartyAv) {
            if (-not $status.RealTimeProtectionEnabled) {
                Add-Finding -Category $cat -Severity 'High' -Title 'Defender real-time protection is OFF' -Mitre 'T1562.001' `
                    -Reasons 'No other antivirus seems to be installed, so the PC is not protected. Many cracks ask you to turn it off: that is exactly how malware gets in.' `
                    -Recommendation 'Turn it back on from Windows Security > Virus & threat protection. If it keeps turning itself off, that is a strong sign of infection.'
            }
            if (-not $status.AntivirusEnabled -or -not $status.AMServiceEnabled) {
                Add-Finding -Category $cat -Severity 'High' -Title 'Microsoft Defender is not active' -Mitre 'T1562.001' `
                    -Evidence "AntivirusEnabled=$($status.AntivirusEnabled) AMServiceEnabled=$($status.AMServiceEnabled)" `
                    -Reasons 'The antivirus engine is off and there is no other antivirus.'
            }
            if ($status.AntivirusSignatureAge -gt 7) {
                Add-Finding -Category $cat -Severity 'Medium' -Title "Antivirus signatures $($status.AntivirusSignatureAge) days old" -Mitre 'T1562.001' `
                    -Reasons 'Defender is not updating: it may be caused by a blocked Windows Update or a modified hosts file.'
            }
        }
        if ($status.PSObject.Properties['IsTamperProtected'] -and -not $status.IsTamperProtected -and -not $thirdPartyAv) {
            Add-Finding -Category $cat -Severity 'Low' -Title 'Tamper protection is off' -Mitre 'T1562.001' `
                -Reasons 'Without it, malware with administrator rights can turn Defender off.' `
                -Recommendation 'Windows Security > Virus & threat protection > Manage settings > Tamper protection: On.'
        }
    }

    # Exclusions: the most typical sign of malware from cracks
    $pref = $null
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
    $exclusions = @()
    if ($pref) {
        foreach ($e in @($pref.ExclusionPath)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Path'; Value = $e } } }
        foreach ($e in @($pref.ExclusionProcess)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Process'; Value = $e } } }
        foreach ($e in @($pref.ExclusionExtension)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Extension'; Value = $e } } }
        foreach ($e in @($pref.ExclusionIpAddress)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'IP address'; Value = $e } } }
    }
    # Exclusions set through Group Policy live here
    foreach ($t in 'Paths', 'Processes', 'Extensions', 'IpAddresses') {
        foreach ($base in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions') {
            foreach ($v in Get-RegValues "$base\$t") { $exclusions += [pscustomobject]@{ Type = $t; Value = $v.Name } }
        }
    }
    $hiddenByPerm = $exclusions | Where-Object { $_.Value -match '^N/A' }
    $exclusions = @($exclusions | Where-Object { $_.Value -notmatch '^N/A' } | Sort-Object Type, Value -Unique)
    if ($hiddenByPerm -or (-not $script:IsAdmin -and -not $exclusions)) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'Defender exclusions cannot be read' `
            -Reasons 'Run the scan as administrator to see the Defender exclusions: it is one of the most important checks.'
    }
    foreach ($e in $exclusions) {
        Add-InventoryItem $cat "Defender exclusion | $($e.Type)" $e.Value
        $v = [Environment]::ExpandEnvironmentVariables($e.Value)
        $sev = 'Medium'
        $why = @('Defender will not scan anything that matches this exclusion.')
        if ($v -match '^(?i)([A-Z]:\\?|\\|\*|.*\\Users\\?[^\\]*\\?|.*\\AppData(\\(Roaming|Local))?\\?|.*\\Temp\\?|.*\\ProgramData\\?|.*\\Windows(\\System32)?\\?|.*\\Downloads\\?|.*\\Desktop\\?)$' -or
            $v -match '^(?i)\.?(exe|dll|ps1|vbs|js|bat|cmd|scr|tmp|com)$' -or
            $v -match '(?i)\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|svchost|explorer)\.exe$') {
            $sev = 'High'; $why += 'A very broad exclusion, or one on a system program: exactly what miners and RATs bundled with cracks do.'
        }
        Add-Finding -Category $cat -Severity $sev -Title "Defender exclusion ($($e.Type)): $($e.Value)" -Evidence $e.Value -Mitre 'T1562.001' `
            -Reasons $why -Recommendation "If you did not add it: Windows Security > Virus & threat protection > Manage settings > Exclusions, remove it, then run a FULL scan and a 'Microsoft Defender Offline' scan."
    }

    # Defender turned off through policies (registry)
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
            Add-Finding -Category $cat -Severity 'High' -Title "Policy that weakens Defender: $($c.N) = $val" -Detail $c.P -Mitre 'T1562.001' `
                -Reasons 'Nobody sets these policies on a home PC: they are typical of the "Defender killers" bundled with cracks.' `
                -Recommendation "Delete the $($c.N) value from the $($c.P) key and restart."
        }
    }

    # History of threats detected by Defender
    try {
        $threats = @{}
        foreach ($t in Get-MpThreat -ErrorAction Stop) { $threats[[string]$t.ThreatID] = $t }
        foreach ($d in Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 40) {
            $t = $threats[[string]$d.ThreatID]
            $name = if ($t) { $t.ThreatName } else { "ID $($d.ThreatID)" }
            $sev = 'Low'
            if ($name -match '(?i)Backdoor|Trojan|PWS|Stealer|RAT|CoinMiner|Rootkit|Ransom|Dropper|Bladabindi|AsyncRat|Remcos|Lumma|RedLine|Vidar|Raccoon') { $sev = 'Medium' }
            if ($d.ActionSuccess -eq $false) { $sev = 'High' }
            Add-Finding -Category $cat -Severity $sev -Title "Defender detected: $name" -Evidence (($d.Resources | Select-Object -First 3) -join ' ; ') `
                -Detail "Detected on $($d.InitialDetectionTime); action succeeded: $($d.ActionSuccess)" `
                -Reasons @('Defender has already seen this threat on the PC.', $(if ($d.ActionSuccess -eq $false) { 'Removal did NOT succeed: the threat may still be active.' })) `
                -Recommendation 'If it is a Trojan/Backdoor/Stealer, consider the passwords saved in the browser compromised: change them from another device and turn on two-step verification.'
        }
    } catch { }

    # Windows Update and security services disabled or removed (e.g. Crackonosh)
    foreach ($svc in @(
            @{ N = 'wuauserv'; D = 'Windows Update' }, @{ N = 'WinDefend'; D = 'Microsoft Defender Antivirus' },
            @{ N = 'SecurityHealthService'; D = 'Windows Security Service' }, @{ N = 'WdNisSvc'; D = 'Defender Network Inspection' },
            @{ N = 'mpssvc'; D = 'Windows Firewall' }, @{ N = 'BITS'; D = 'Background Intelligent Transfer Service (BITS)' })) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$($svc.N)'" -ErrorAction SilentlyContinue
        if (-not $s) {
            if ($svc.N -in 'wuauserv', 'mpssvc') {
                Add-Finding -Category $cat -Severity 'High' -Title "$($svc.D) service missing" -Mitre 'T1562.001' `
                    -Reasons 'The service was deleted: documented behaviour of malware such as Crackonosh.'
            }
            continue
        }
        if ($s.StartMode -eq 'Disabled' -and -not ($svc.N -in 'WinDefend', 'WdNisSvc' -and $thirdPartyAv)) {
            Add-Finding -Category $cat -Severity 'Medium' -Title "$($svc.D) service disabled" -Evidence "$($s.Name): $($s.StartMode)" -Mitre 'T1562.001' `
                -Reasons 'A disabled security or update service stops you from receiving protection. Some "optimisation tools" do it, but so does a lot of malware.'
        }
    }
    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if ((Get-RegValue $wuPol 'NoAutoUpdate') -eq 1) {
        Add-Finding -Category $cat -Severity 'Low' -Title 'Automatic updates disabled by policy' -Detail $wuPol -Mitre 'T1562.001' `
            -Reasons 'Windows does not download security patches.'
    }

    # UAC
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ((Get-RegValue $uac 'EnableLUA') -eq 0) {
        Add-Finding -Category $cat -Severity 'Medium' -Title 'User Account Control (UAC) disabled' -Detail $uac -Mitre 'T1548.002' `
            -Reasons 'Without UAC any program gets administrator rights without asking.'
    } elseif ((Get-RegValue $uac 'ConsentPromptBehaviorAdmin') -eq 0) {
        Add-Finding -Category $cat -Severity 'Low' -Title 'UAC elevates programs without asking' -Detail $uac -Mitre 'T1548.002' `
            -Reasons 'ConsentPromptBehaviorAdmin = 0: programs become administrators without showing the confirmation prompt.'
    }

    # Accessibility programs replaced (sign-in screen backdoor)
    foreach ($exe in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:SystemRoot\System32" $exe
        $info = Get-FileInfo $p
        if (-not $info.Exists) { continue }
        $cmdHash = Get-FileSha256 "$env:SystemRoot\System32\cmd.exe"
        $psHash = Get-FileSha256 "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        if (-not $info.IsMicrosoft -or (Get-FileSha256 $p) -in $cmdHash, $psHash -or $info.OriginalName -match '(?i)^(cmd|powershell|explorer)') {
            Add-Finding -Category $cat -Severity 'High' -Title "$exe has been replaced" -Path $p -Sha256 $info.Sha256 -Signer $info.Signer -Mitre 'T1546.008' `
                -Evidence "Signature: $($info.SignatureStatus) $($info.Signer); original name: $($info.OriginalName)" `
                -Reasons "Replacing $exe with cmd.exe opens a SYSTEM prompt from the sign-in screen without a password." `
                -Recommendation 'Run from an administrator prompt: sfc /scannow (restores the original file).'
        }
    }

    # Boot into Safe Mode forced (Crackonosh) - needs administrator rights
    if ($script:IsAdmin) {
        $bcd = (bcdedit /enum '{current}' 2>$null) -join "`n"
        if ($bcd -match '(?im)^\s*safeboot\s') {
            Add-Finding -Category $cat -Severity 'High' -Title 'Boot into Safe Mode forced' -Evidence ($bcd -split "`n" | Where-Object { $_ -match 'safeboot' }) -Mitre 'T1562.009' `
                -Reasons 'At the next restart Windows will start in Safe Mode, where the antivirus does not run.' `
                -Recommendation 'Run from an administrator prompt: bcdedit /deletevalue {current} safeboot'
        }
    }
}
