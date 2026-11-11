# Account e accessi remoti: un attaccante spesso crea un utente amministratore
# nascosto o abilita il Desktop remoto per tornare quando vuole (T1136, T1021).

function Invoke-CheckAccounts {
    $cat = 'Account e accesso remoto'

    $admins = @()
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    } catch {
        # Get-LocalGroupMember fallisce se nel gruppo c'e' un SID orfano: ripiego su net.exe
        $out = net localgroup (Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'").Name 2>$null
        $admins = @($out | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^(The command|Esecuzione comando)' } | ForEach-Object { [pscustomobject]@{ Name = $_; PrincipalSource = '?' } })
    }
    foreach ($a in $admins) { Add-InventoryItem $cat 'Amministratore' "$($a.Name)" }

    # Account nascosti dalla schermata di accesso
    $special = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    $hidden = @{}
    foreach ($v in Get-RegValues $special) {
        if ($v.Value -eq 0) { $hidden[$v.Name.ToLower()] = $true }
    }

    foreach ($u in Get-LocalUser -ErrorAction SilentlyContinue) {
        Add-InventoryItem $cat "Utente | $($u.Name)" "Abilitato=$($u.Enabled)"
        if (-not $u.Enabled) { continue }
        $isAdmin = [bool]($admins | Where-Object { $_.Name -match "\\$([regex]::Escape($u.Name))$" -or $_.Name -eq $u.Name })
        $why = @(); $sev = $null

        if ($u.SID.Value -match '-500$') { $sev = 'Medio'; $why += 'L''account Administrator integrato e'' attivo: normalmente e'' disabilitato.' }
        if ($u.SID.Value -match '-501$') { $sev = 'Medio'; $why += 'L''account Guest e'' attivo.' }
        if ($hidden.ContainsKey($u.Name.ToLower())) {
            $sev = 'Medio'; $why += 'Account nascosto dalla schermata di accesso tramite SpecialAccounts\UserList.'
            if ($isAdmin) { $sev = 'Alto'; $why += 'Ed e'' amministratore: classica backdoor per rientrare nel PC.' }
            if ($u.Name -match '^(?i)CodexSandbox') { $why += 'Il nome corrisponde agli account creati dalla sandbox di OpenAI Codex: se usi Codex e'' normale.' }
        }
        if ($isAdmin -and -not $sev -and $u.Name -ne $env:USERNAME -and $u.Name -notmatch '^(?i)(defaultuser\d*|WDAGUtilityAccount)$') {
            $sev = 'Basso'; $why += "E' un amministratore diverso da te ($env:USERNAME): verifica di riconoscerlo."
        }
        if ($u.PasswordLastSet -and $u.PasswordLastSet -gt (Get-Date).AddDays(-30) -and $u.Name -ne $env:USERNAME) {
            $why += "Password impostata di recente ($($u.PasswordLastSet.ToString('dd/MM/yyyy'))): l'account potrebbe essere stato creato da poco."
            if (-not $sev) { $sev = 'Basso' }
        }
        if ($sev) {
            Add-Finding -Category $cat -Severity $sev -Title "Account: $($u.Name)$(if ($isAdmin) { ' (amministratore)' })" `
                -Evidence "SID $($u.SID); ultimo accesso: $($u.LastLogon); descrizione: $($u.Description)" -Mitre 'T1136.001' -Reasons $why `
                -Recommendation 'Se non riconosci l''account: Impostazioni > Account > Altri utenti, rimuovilo (oppure da prompt admin: net user NOME /active:no).'
        }
    }

    # Desktop remoto
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -eq 0) {
        $edition = (Get-CimInstance Win32_OperatingSystem).Caption
        $sev = 'Medio'; $why = @('Il Desktop remoto e'' abilitato: chiunque abbia una password valida puo'' collegarsi.')
        if ($edition -match '(?i)Home') { $sev = 'Alto'; $why += 'Su Windows Home il Desktop remoto non esiste: se e'' attivo e'' stato forzato (es. RDP Wrapper installato da un malware).' }
        Add-Finding -Category $cat -Severity $sev -Title 'Desktop remoto abilitato' -Detail $ts -Evidence 'fDenyTSConnections = 0' -Mitre 'T1021.001' -Reasons $why `
            -Recommendation 'Impostazioni > Sistema > Desktop remoto: disattivalo se non lo usi.'
    }
    if ((Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication') -eq 0 -and (Get-RegValue $ts 'fDenyTSConnections') -eq 0) {
        Add-Finding -Category $cat -Severity 'Medio' -Title 'Desktop remoto senza autenticazione a livello di rete (NLA)' -Mitre 'T1021.001' `
            -Reasons 'Senza NLA il servizio e'' piu'' esposto ad attacchi.'
    }

    # Assistenza remota e WinRM
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp') -eq 1) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'Assistenza remota consentita' -Mitre 'T1021' `
            -Reasons 'E'' l''impostazione predefinita di Windows; se non la usi puoi disattivarla da Proprieta'' del sistema > Remoto.'
    }
    $winrm = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.State -eq 'Running') {
        Add-Finding -Category $cat -Severity 'Basso' -Title 'Servizio WinRM (gestione remota PowerShell) in esecuzione' -Mitre 'T1021.006' `
            -Reasons 'Su un PC di casa WinRM non serve; se attivo permette l''esecuzione remota di comandi.'
    }
}
