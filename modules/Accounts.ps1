# Accounts and remote access: an attacker often creates a hidden administrator or
# enables Remote Desktop to come back whenever they want (T1136, T1021).

function Invoke-CheckAccounts {
    $cat = 'Accounts and remote access'

    $admins = @()
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    } catch {
        # Get-LocalGroupMember fails when the group contains an orphaned SID: fall back to net.exe
        $out = net localgroup (Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'").Name 2>$null
        $admins = @($out | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^(The command|Esecuzione comando)' } | ForEach-Object { [pscustomobject]@{ Name = $_; PrincipalSource = '?' } })
    }
    foreach ($a in $admins) { Add-InventoryItem $cat 'Administrator' "$($a.Name)" }

    # Accounts hidden from the sign-in screen
    $special = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    $hidden = @{}
    foreach ($v in Get-RegValues $special) {
        if ($v.Value -eq 0) { $hidden[$v.Name.ToLower()] = $true }
    }

    foreach ($u in Get-LocalUser -ErrorAction SilentlyContinue) {
        Add-InventoryItem $cat "User | $($u.Name)" "Enabled=$($u.Enabled)"
        if (-not $u.Enabled) { continue }
        $isAdmin = [bool]($admins | Where-Object { $_.Name -match "\\$([regex]::Escape($u.Name))$" -or $_.Name -eq $u.Name })
        $why = @(); $sev = $null

        if ($u.SID.Value -match '-500$') { $sev = 'Medium'; $why += 'The built-in Administrator account is enabled: it is normally disabled.' }
        if ($u.SID.Value -match '-501$') { $sev = 'Medium'; $why += 'The Guest account is enabled.' }
        if ($hidden.ContainsKey($u.Name.ToLower())) {
            $sev = 'Medium'; $why += 'Account hidden from the sign-in screen through SpecialAccounts\UserList.'
            if ($isAdmin) { $sev = 'High'; $why += 'And it is an administrator: a classic backdoor to get back into the PC.' }
            if ($u.Name -match '^(?i)CodexSandbox') { $why += 'The name matches the accounts created by the OpenAI Codex sandbox: if you use Codex this is normal.' }
        }
        if ($isAdmin -and -not $sev -and $u.Name -ne $env:USERNAME -and $u.Name -notmatch '^(?i)(defaultuser\d*|WDAGUtilityAccount)$') {
            $sev = 'Low'; $why += "It is an administrator other than you ($env:USERNAME): make sure you recognise it."
        }
        if ($u.PasswordLastSet -and $u.PasswordLastSet -gt (Get-Date).AddDays(-30) -and $u.Name -ne $env:USERNAME) {
            $why += "Password set recently ($($u.PasswordLastSet.ToString('yyyy-MM-dd'))): the account may have been created recently."
            if (-not $sev) { $sev = 'Low' }
        }
        if ($sev) {
            Add-Finding -Category $cat -Severity $sev -Title "Account: $($u.Name)$(if ($isAdmin) { ' (administrator)' })" `
                -Evidence "SID $($u.SID); last sign-in: $($u.LastLogon); description: $($u.Description)" -Mitre 'T1136.001' -Reasons $why `
                -Recommendation 'If you do not recognise the account: Settings > Accounts > Other users, remove it (or from an admin prompt: net user NAME /active:no).'
        }
    }

    # Remote Desktop
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -eq 0) {
        $edition = (Get-CimInstance Win32_OperatingSystem).Caption
        $sev = 'Medium'; $why = @('Remote Desktop is enabled: anyone with a valid password can connect.')
        if ($edition -match '(?i)Home') { $sev = 'High'; $why += 'Windows Home has no Remote Desktop: if it is on, it was forced (e.g. RDP Wrapper installed by malware).' }
        Add-Finding -Category $cat -Severity $sev -Title 'Remote Desktop enabled' -Detail $ts -Evidence 'fDenyTSConnections = 0' -Mitre 'T1021.001' -Reasons $why `
            -Recommendation 'Settings > System > Remote Desktop: turn it off if you do not use it.'
    }
    if ((Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication') -eq 0 -and (Get-RegValue $ts 'fDenyTSConnections') -eq 0) {
        Add-Finding -Category $cat -Severity 'Medium' -Title 'Remote Desktop without Network Level Authentication (NLA)' -Mitre 'T1021.001' `
            -Reasons 'Without NLA the service is more exposed to attacks.'
    }

    # Remote Assistance and WinRM
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp') -eq 1) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'Remote Assistance allowed' -Mitre 'T1021' `
            -Reasons 'It is the Windows default; if you do not use it you can turn it off in System Properties > Remote.'
    }
    $winrm = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.State -eq 'Running') {
        Add-Finding -Category $cat -Severity 'Low' -Title 'WinRM service (PowerShell remote management) running' -Mitre 'T1021.006' `
            -Reasons 'A home PC does not need WinRM; when running it allows commands to be run remotely.'
    }
}
