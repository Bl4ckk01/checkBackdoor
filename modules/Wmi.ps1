# Permanent WMI subscriptions (T1546.003): "fileless" persistence that shows up neither
# in the Run keys nor among scheduled tasks.

function Invoke-CheckWmi {
    $cat = 'WMI'
    if (-not $script:IsAdmin) {
        Add-Finding -Category $cat -Severity 'Info' -Title 'WMI check incomplete' `
            -Reasons 'Reading WMI subscriptions requires administrator rights.'
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
        # The "SCM Event Log Consumer" (NTEventLogEventConsumer) belongs to Windows
        if ($cls -notin 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { continue }

        $bound = @($bindings | Where-Object { $_.Consumer.Name -eq $c.Name })
        $filterText = @()
        foreach ($b in $bound) {
            $f = $filters | Where-Object { $_.Name -eq $b.Filter.Name } | Select-Object -First 1
            if ($f) { $filterText += "$($f.Name): $($f.Query)" }
        }
        $risk = Get-CommandRisk $payload
        Add-Finding -Category $cat -Severity 'High' -Title "WMI subscription that runs code: $($c.Name)" `
            -Detail "Consumer $cls$(if ($filterText) { ' - triggered by: ' + ($filterText -join ' | ') })" `
            -Path $risk.Target -Evidence $payload -Mitre 'T1546.003' -Sha256 $risk.Sha256 `
            -Reasons (@('Runs a command or script when a system event happens (startup, sign-in, timer). On home PCs it is almost always malicious.') + $risk.Reasons) `
            -Recommendation "Remove the filter, consumer and binding from an administrator PowerShell: Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter `"Name='$($c.Name)'`" | Remove-CimInstance (and the same for __EventFilter and __FilterToConsumerBinding)."
    }
}
