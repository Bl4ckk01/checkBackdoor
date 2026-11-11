# Sottoscrizioni WMI permanenti (T1546.003): persistenza "senza file" che non
# compare ne' nelle chiavi Run ne' nelle attivita' pianificate.

function Invoke-CheckWmi {
    $cat = 'WMI'
    if (-not $script:IsAdmin) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'Controllo WMI incompleto' `
            -Reasons 'Per leggere le sottoscrizioni WMI servono i privilegi di amministratore.'
    }
    $ns = 'root\subscription'
    $filters   = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)
    $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    $bindings  = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)

    foreach ($c in $consumers) {
        $cls = $c.CimClass.CimClassName
        $payload = $null
        switch ($cls) {
            'CommandLineEventConsumer' { $payload = "$($c.ExecutablePath) $($c.CommandLineTemplate)".Trim() }
            'ActiveScriptEventConsumer' { $payload = "[$($c.ScriptingEngine)] $($c.ScriptFileName) $($c.ScriptText)".Trim() }
            default { $payload = $cls }
        }
        Add-InventoryItem $cat "$cls | $($c.Name)" $payload
        # Il consumer "SCM Event Log Consumer" (NTEventLogEventConsumer) e' di Windows
        if ($cls -notin 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { continue }

        $bound = @($bindings | Where-Object { $_.Consumer.Name -eq $c.Name })
        $filterText = @()
        foreach ($b in $bound) {
            $f = $filters | Where-Object { $_.Name -eq $b.Filter.Name } | Select-Object -First 1
            if ($f) { $filterText += "$($f.Name): $($f.Query)" }
        }
        $risk = Get-CommandRisk $payload
        Add-Finding -Category $cat -Severity 'Alto' -Title "Sottoscrizione WMI che esegue codice: $($c.Name)" `
            -Detail "Consumer $cls$(if ($filterText) { ' - attivata da: ' + ($filterText -join ' | ') })" `
            -Path $risk.Target -Evidence $payload -Mitre 'T1546.003' -Sha256 $risk.Sha256 `
            -Reasons (@('Esegue un comando o uno script quando si verifica un evento di sistema (avvio, logon, timer). Sui PC domestici e'' quasi sempre malevolo.') + $risk.Reasons) `
            -Recommendation "Rimuovi filtro, consumer e binding da PowerShell amministratore: Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter `"Name='$($c.Name)'`" | Remove-CimInstance (e lo stesso per __EventFilter e __FilterToConsumerBinding)."
    }
}
