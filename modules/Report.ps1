# Report: lista bianca, confronto con una scansione precedente, esportazione
# JSON/CSV e pagina HTML leggibile.

$script:SeverityOrder = @{ 'Alto' = 0; 'Medio' = 1; 'Basso' = 2; 'Info' = 3 }

# Applica la lista bianca a segnalazioni gia' raccolte. Durante una scansione la
# lista si carica prima (Import-Allowlist) e Add-Finding scarta da solo.
function Invoke-Allowlist {
    param([string[]]$Path)
    Import-Allowlist -Path $Path
    $keep = New-Object System.Collections.Generic.List[object]
    $removed = 0
    foreach ($f in $script:Findings) {
        if (Test-Allowlisted $f) { $removed++ } else { $keep.Add($f) }
    }
    $script:Findings = $keep
    return $removed
}

function Compare-WithPrevious {
    param([string]$PreviousJson)
    $prev = $null
    try { $prev = [IO.File]::ReadAllText($PreviousJson) | ConvertFrom-Json } catch { Write-ScanWarning "Impossibile leggere $PreviousJson"; return }
    # Le connessioni di rete cambiano di continuo: le escludiamo dal confronto
    $noisy = { param($i) $i.Category -eq 'Rete' -and $i.Key -match '^(Listen|Established) \|' -or $i.Key -eq 'File eseguibili esaminati' }
    $persistent = '^(Avvio automatico|Attivit|Servizi|Driver|WMI|Dirottamento COM|Modalita provvisoria|Account|Difese|Certificati|Browser|Iniezioni)'
    $old = @{}; foreach ($i in $prev.Inventory) { if (-not (& $noisy $i)) { $old["$($i.Category)|$($i.Key)|$($i.Value)"] = $i } }
    $new = @{}; foreach ($i in $script:Inventory) { if (-not (& $noisy $i)) { $new["$($i.Category)|$($i.Key)|$($i.Value)"] = $i } }
    $cat = 'Novita'' dalla scansione precedente'
    foreach ($k in $new.Keys) {
        if ($old.ContainsKey($k)) { continue }
        $i = $new[$k]
        $sev = 'Basso'; if ($i.Category -match $persistent) { $sev = 'Medio' }
        Add-Finding -Category $cat -Severity $sev -Title "Nuovo ($($i.Category)): $($i.Key)" -Evidence $i.Value `
            -Reasons "Non era presente nella scansione del $($prev.Meta.Date)." `
            -Recommendation 'Se nel frattempo hai installato qualcosa (es. un gioco o un crack), questa e'' una delle modifiche che ha fatto al sistema.'
    }
    # Le categorie assenti ora (controllo saltato con -Skip) non contano come "rimosse"
    $currentCats = @{}; foreach ($i in $new.Values) { $currentCats[$i.Category] = $true }
    foreach ($k in $old.Keys) {
        if ($new.ContainsKey($k)) { continue }
        $i = $old[$k]
        if (-not $currentCats.ContainsKey($i.Category)) { continue }
        Add-Finding -Category $cat -Severity 'Info' -Title "Rimosso ($($i.Category)): $($i.Key)" -Evidence $i.Value -Reasons "Presente nella scansione del $($prev.Meta.Date), ora non piu'."
    }
}

# Aree mostrate nella "libreria" del report, nell'ordine in cui le legge l'utente,
# con il controllo (-Skip) che le produce.
$script:ReportAreas = @(
    @{ Name = 'Difese di Windows'; Check = 'Security' }
    @{ Name = 'Avvio automatico'; Check = 'Persistence' }
    @{ Name = "Attivita' pianificate"; Check = 'ScheduledTasks' }
    @{ Name = 'Servizi'; Check = 'Services' }
    @{ Name = 'Driver'; Check = 'Services' }
    @{ Name = 'WMI'; Check = 'Wmi' }
    @{ Name = 'Dirottamento COM'; Check = 'Persistence' }
    @{ Name = 'Processi'; Check = 'Processes' }
    @{ Name = 'Rete'; Check = 'Network' }
    @{ Name = 'Browser'; Check = 'Browser' }
    @{ Name = 'Iniezioni nelle app'; Check = 'Injections' }
    @{ Name = 'Account e accesso remoto'; Check = 'Accounts' }
    @{ Name = 'Certificati'; Check = 'Certificates' }
    @{ Name = 'File sospetti'; Check = 'FileSystem' }
    @{ Name = 'Linea temporale'; Check = 'Timeline' }
)

# Quanti elementi ha esaminato ogni area: le voci d'inventario, piu' i conteggi
# che non finiscono in inventario (processi, file).
function Get-ExaminedCounts {
    $c = @{}
    foreach ($i in $script:Inventory) {
        $cat = $i.Category
        if ($cat -eq 'Modalita provvisoria') { $cat = 'Servizi' }
        if ($i.Key -eq 'File eseguibili esaminati') { $c[$cat] = [int]$c[$cat] + [int]$i.Value; continue }
        $c[$cat] = [int]$c[$cat] + 1
    }
    if ($script:ProcessTable) { $c['Processi'] = $script:ProcessTable.Count }
    if ($script:TimelineExamined) { $c['Linea temporale'] = $script:TimelineExamined }
    return $c
}

function Export-Results {
    param([string]$OutputDir, [hashtable]$Meta, [string]$Prefix = 'scansione')
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $OutputDir "$($Prefix)_$stamp"
    $sorted = @($script:Findings | Sort-Object { $script:SeverityOrder[$_.Severity] }, Category, Title)
    $Meta.Schema = 'checkbackdoor.report/1'
    $Meta.Examined = Get-ExaminedCounts
    $Meta.Files = @{ Json = "$($Prefix)_$stamp.json"; Csv = "$($Prefix)_$stamp.csv" }

    $timeline = $null
    if ($script:TimelineRan) { $timeline = @($script:Timeline | Sort-Object Time -Descending) }
    # Cio' che la lista bianca ha nascosto resta nel report: una lista ritoccata non passa inosservata
    $ignored = @($script:Ignored | Sort-Object { $script:SeverityOrder[$_.Severity] }, Category, Title)
    $json = [ordered]@{ Meta = $Meta; Findings = $sorted; Ignored = $ignored; Inventory = $script:Inventory; Timeline = $timeline } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText("$base.json", $json, (New-Object Text.UTF8Encoding($false)))

    $sorted | Select-Object Id, Severity, Category, Title, Path, Evidence, @{ n = 'Reasons'; e = { $_.Reasons -join ' | ' } }, Mitre, Sha256, Signer, Recommendation |
        Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    $html = New-HtmlReport -Findings $sorted -Meta $Meta -Timeline $timeline -Ignored $ignored
    [IO.File]::WriteAllText("$base.html", $html, (New-Object Text.UTF8Encoding($false)))
    return "$base.html"
}

# Il codice e' scritto senza accenti (PowerShell 5.1 e la codifica dei file):
# nel report il testo torna in italiano corretto ("e'" -> "è", "piu'" -> "più").
$script:Accent = @{ a = [string][char]0xE0; e = [string][char]0xE8; eUpper = [string][char]0xC8; eAcute = [string][char]0xE9; i = [string][char]0xEC; o = [string][char]0xF2; u = [string][char]0xF9 }

function ConvertTo-ItalianProse {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $end = "(?=[\s.,;:!?)""]|$)"
    $t = $Text
    $t = $t -replace "(?<=\b(?:[Pp]erch|[Pp]oich|[Aa]ffinch|[Bb]ench))e'$end", $script:Accent.eAcute
    $t = $t -replace "(?<=\b[cC]')e'$end", $script:Accent.e
    $t = $t -creplace "(?<=^|[\s(""])E'(?=\s)", $script:Accent.eUpper
    $t = $t -creplace "(?<=^|[\s(""])e'(?=\s)", $script:Accent.e
    $t = $t -replace "(?<=\p{L}\p{L})a'$end", $script:Accent.a
    $t = $t -replace "(?<=\p{L}\p{L})e'$end", $script:Accent.e
    $t = $t -replace "(?<=\p{L})i'$end", $script:Accent.i
    $t = $t -replace "(?<=\p{L})o'$end", $script:Accent.o
    $t = $t -replace "(?<=\p{L})u'$end", $script:Accent.u
    return $t
}

function ConvertTo-HtmlText {
    param($Text, [switch]$Prose)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    if ($Prose) { $s = ConvertTo-ItalianProse $s }
    return [Net.WebUtility]::HtmlEncode($s)
}

# Icone disegnate a mano, un solo tratto da 1.5px, colore dal testo
$script:Icons = @{
    Chevron = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 6l4 4 4-4"/></svg>'
    Search  = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>'
    Check   = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg>'
    Review  = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6"/><path d="M8 4.75v3.5M8 11.1v.15"/></svg>'
    Risk    = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.75L14.5 13.5h-13z"/><path d="M8 6v3.25M8 11.35v.15"/></svg>'
    Box     = '<svg class="ico sev-box" viewBox="0 0 16 16" aria-hidden="true"><rect x="2" y="2" width="12" height="12" rx="3"/><path class="sev-tick" d="M5 8.25l2 2 4-4.5"/></svg>'
    Out     = '<svg class="ico ico-s" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 4h6v6M12 4l-7.5 7.5"/></svg>'
    File    = '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 1.75h5l3 3v9.5H4z"/><path d="M9 1.75v3h3"/></svg>'
    Moon    = '<svg class="ico i-moon" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7z"/></svg>'
    Sun     = '<svg class="ico i-sun" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1"/></svg>'
    Mark    = '<svg class="mark-svg" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" stroke-dasharray="40 10.27" transform="rotate(-60 10 10)"/><path class="mark-tick" d="M6.5 10.2l2.4 2.4 4.6-5"/></svg>'
}

$script:ReportCss = @'
:root{
  --ground:#f2f4f7;--surface:#fff;--raised:#f6f7f9;--active:#e8ebef;--border:#e3e6ea;--rule:#eceef1;--control:#cdd2d8;
  --text:#0b0c0d;--muted:#596069;--hue:#1d5fbf;--hue-ink:#fff;
  --neg:#c4242a;--warn:#b45309;--warn-ink:#92400e;
  --p-alto-bg:#ffedea;--p-alto:#831c1e;--p-medio-bg:#fdf0dc;--p-medio:#7c3a06;--p-basso-bg:#eceef1;--p-basso:#3d434a;--p-info-bg:transparent;--p-info:#596069;
  --note-bg:#fffbeb;--note-line:#fde68a;--note-ink:#92400e;
  --radius:8px;--radius-c:6px;--gap:12px;
  --font:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --font-d:"Segoe UI Variable Display","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --ground:#0c0d0e;--surface:#151618;--raised:#1c1d20;--active:#26282c;--border:#282a2e;--rule:#1f2124;--control:#3b3e43;
  --text:#f0f1f2;--muted:#a2a8af;--hue:#6f9dff;--hue-ink:#0b0c0d;
  --neg:#ff6b6b;--warn:#f0a43c;--warn-ink:#f5c27a;
  --p-alto-bg:#3b191b;--p-alto:#ffb4b0;--p-medio-bg:#3a2810;--p-medio:#f5c27a;--p-basso-bg:#24262a;--p-basso:#c9cdd2;--p-info-bg:transparent;--p-info:#a2a8af;
  --note-bg:#241c0c;--note-line:#4a3815;--note-ink:#f5c27a;color-scheme:dark;}}
:root[data-theme=dark]{
  --ground:#0c0d0e;--surface:#151618;--raised:#1c1d20;--active:#26282c;--border:#282a2e;--rule:#1f2124;--control:#3b3e43;
  --text:#f0f1f2;--muted:#a2a8af;--hue:#6f9dff;--hue-ink:#0b0c0d;
  --neg:#ff6b6b;--warn:#f0a43c;--warn-ink:#f5c27a;
  --p-alto-bg:#3b191b;--p-alto:#ffb4b0;--p-medio-bg:#3a2810;--p-medio:#f5c27a;--p-basso-bg:#24262a;--p-basso:#c9cdd2;--p-info-bg:transparent;--p-info:#a2a8af;
  --note-bg:#241c0c;--note-line:#4a3815;--note-ink:#f5c27a;color-scheme:dark;}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scrollbar-color:var(--control) transparent;accent-color:var(--hue)}
body{margin:0;background:var(--ground);color:var(--text);font:400 14px/20px var(--font);font-variant-numeric:tabular-nums;caret-color:var(--hue)}
::selection{background:var(--hue);color:var(--hue-ink)}
a{color:inherit;text-underline-offset:3px;text-decoration-thickness:1px}
a:hover{color:var(--hue)}
:focus-visible{outline:2px solid var(--hue);outline-offset:2px;border-radius:4px}
button{font:inherit;color:inherit}
h1,h2,h3{margin:0;font-weight:600}
.ico{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}
.ico-s{width:12px;height:12px}
code,.mono{font-family:var(--mono);font-size:12.5px;line-height:18px}

/* Barra superiore */
.bar{border-bottom:1px solid var(--border);background:var(--ground)}
.embedded .bar{display:none}
.bar-in{max-width:1136px;margin:0 auto;height:48px;padding:0 24px;display:flex;align-items:center;gap:16px}
.mark{display:flex;align-items:center;gap:8px;font-weight:600;text-decoration:none}
.mark-svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round}
.mark-tick{stroke:var(--hue);stroke-width:1.9;stroke-linejoin:round}
.bar-scope{color:var(--muted);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.theme{margin-left:auto;display:none;align-items:center;justify-content:center;width:32px;height:32px;border:0;border-radius:var(--radius-c);background:transparent;cursor:pointer;color:var(--muted)}
.js .theme{display:inline-flex}
.theme:hover{background:var(--active);color:var(--text)}
.i-sun{display:none}
:root[data-theme=dark] .i-sun{display:block}:root[data-theme=dark] .i-moon{display:none}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .i-sun{display:block}:root:not([data-theme=light]) .i-moon{display:none}}

/* Pagina */
.page{max-width:1136px;margin:0 auto;padding:32px 24px 48px}
.title-row{display:flex;align-items:flex-end;justify-content:space-between;gap:24px}
h1{font:600 24px/30px var(--font-d);letter-spacing:-.01em}
.sub{margin:4px 0 0;color:var(--muted);font-size:12px;line-height:16px;overflow-wrap:anywhere}
.actions{display:flex;gap:8px;flex:none}
.btn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 12px;border:1px solid var(--control);border-radius:var(--radius-c);background:var(--surface);text-decoration:none;font-size:13px;white-space:nowrap;transition:background-color .15s,border-color .15s}
.btn:hover{background:var(--raised);border-color:var(--muted);color:var(--text)}
.btn:active{transform:translateY(1px)}
.note{margin:16px 0 0;padding:8px 12px;background:var(--note-bg);border:1px solid var(--note-line);border-radius:var(--radius-c);color:var(--note-ink);font-size:13px;line-height:18px}
.note ul{margin:4px 0 0;padding-left:18px}
.note-info{background:var(--surface);border-color:var(--border);color:var(--text)}

/* Verifica: il verdetto e la barra completata */
.verify{margin-top:24px;padding:24px 24px 20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
.verify-top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px}
.verdict{font:600 30px/36px var(--font-d);letter-spacing:-.015em}
.done{display:inline-flex;align-items:center;gap:6px;flex:none;margin-top:6px;color:var(--muted);font-size:13px;white-space:nowrap}
.done .ico{color:var(--hue)}
.verdict-text{margin:8px 0 0;max-width:72ch;color:var(--text)}
.meter{display:flex;gap:2px;height:8px;margin-top:20px;border-radius:999px;overflow:hidden;transform-origin:left center;animation:fill .9s cubic-bezier(.16,1,.3,1) both}
.meter span{display:block;min-width:4px}
.m-ok{background:var(--hue)}.m-alto{background:var(--neg)}.m-medio{background:var(--warn)}
.meter-legend{display:flex;flex-wrap:wrap;gap:4px 20px;margin:10px 0 0;color:var(--muted);font-size:13px}
.meter-legend b{color:var(--text);font-weight:600}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}
.d-ok{background:var(--hue)}.d-alto{background:var(--neg)}.d-medio{background:var(--warn)}
@keyframes fill{from{transform:scaleX(0)}to{transform:scaleX(1)}}

/* Gravita': un contenitore diviso, ogni cella e' anche un filtro */
.sev{display:grid;grid-template-columns:repeat(4,1fr);margin-top:var(--gap);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.sev-c{display:flex;flex-direction:column;align-items:flex-start;gap:2px;padding:12px 16px 14px;border:0;border-left:1px solid var(--rule);background:transparent;text-align:left;cursor:default;position:relative}
.sev-c:first-child{border-left:0}
.js .sev-c{cursor:pointer}
.js .sev-c:hover{background:var(--raised)}
.sev-l{display:flex;align-items:center;gap:6px;font-size:12px;line-height:16px;color:var(--muted)}
.sev-box{display:none;width:14px;height:14px}
.js .sev-box{display:block}
.sev-box rect{fill:var(--text);stroke:var(--text)}
.sev-box .sev-tick{stroke:var(--surface);stroke-width:1.8}
.sev-c[aria-pressed=false] .sev-box rect{fill:none;stroke:var(--control)}
.sev-c[aria-pressed=false] .sev-box .sev-tick{display:none}
.sev-n{font:600 24px/30px var(--font-d)}
.sev-n.is-alto{color:var(--neg)}.sev-n.is-medio{color:var(--warn-ink)}
.sev-off{display:none;color:var(--muted)}
.js .sev-c[aria-pressed=false] .sev-n{color:var(--muted);font-weight:400}
.js .sev-c[aria-pressed=false] .sev-off{display:inline}

/* Libreria delle aree + segnalazioni */
.work{display:grid;grid-template-columns:264px minmax(0,1fr);gap:var(--gap);align-items:start;margin-top:var(--gap)}
.lib{position:sticky;top:16px;padding:6px 0 0}
.lib-h{font-size:12px;line-height:16px;font-weight:400;color:var(--muted);padding:0 8px 8px}
.area:hover,.area[aria-pressed=true]{background:var(--active)}
.lib ul{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}
.area{width:100%;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;column-gap:8px;min-height:44px;padding:4px 8px;border:0;border-radius:var(--radius-c);background:transparent;text-align:left;cursor:default}
.js .area{cursor:pointer}
.area[aria-pressed=true] .a-name{color:var(--hue)}
.a-name{font-weight:500;overflow-wrap:anywhere}
.a-meta{grid-column:1;font-size:12px;line-height:16px;color:var(--muted)}
.a-state{grid-column:2;grid-row:1/span 2;display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--muted);white-space:nowrap}
.a-state.s-alto{color:var(--neg);font-weight:600}.a-state.s-medio{color:var(--warn-ink);font-weight:600}
.a-state.s-off{font-style:italic}

.list{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);min-width:0}
.list-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 16px;border-bottom:1px solid var(--border)}
.list-head h2{font-size:16px;line-height:24px}
.list-head .count{color:var(--muted);font-weight:400;margin-left:6px}
.search{display:none;align-items:center;gap:8px;flex:1;max-width:360px;height:32px;padding:0 10px;border:1px solid var(--control);border-radius:var(--radius-c);background:var(--surface);color:var(--muted)}
.js .search{display:flex}
.search:focus-within{border-color:var(--hue);outline:1px solid var(--hue)}
.search input{flex:1;min-width:0;border:0;outline:0;background:transparent;font:inherit;color:var(--text)}
.search input::placeholder{color:var(--muted)}

.row{border-top:1px solid var(--rule)}
.row:first-child{border-top:0}
.row>summary{display:grid;grid-template-columns:72px minmax(0,1fr) 16px;align-items:start;gap:16px;padding:14px 16px;list-style:none;cursor:pointer;transition:background-color .15s}
.row>summary::-webkit-details-marker{display:none}
.row>summary:hover{background:var(--raised)}
.row>summary .ico{margin-top:2px;color:var(--muted);transition:transform .2s cubic-bezier(.16,1,.3,1)}
.row[open]>summary .ico{transform:rotate(180deg)}
.pill{display:inline-flex;align-items:center;justify-content:center;height:22px;padding:0 8px;border-radius:4px;font-size:12px;font-weight:500;white-space:nowrap;flex:none;justify-self:start}
.p-Alto{background:var(--p-alto-bg);color:var(--p-alto)}
.p-Medio{background:var(--p-medio-bg);color:var(--p-medio)}
.p-Basso{background:var(--p-basso-bg);color:var(--p-basso)}
.p-Info{background:var(--p-info-bg);color:var(--p-info);border:1px solid var(--border)}
.r-title{display:block;font-weight:600;overflow-wrap:anywhere}
.r-sub{display:block;margin-top:2px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.r-body{padding:0 48px 18px 104px}
.reasons{margin:0;padding-left:18px;overflow-wrap:anywhere}
.todo,.verdict-text,.note{overflow-wrap:anywhere}
.reasons li+li{margin-top:4px}
.kv{display:grid;grid-template-columns:104px minmax(0,1fr);gap:6px 16px;margin:14px 0 0;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;min-width:0}
.kv code{display:inline-block;max-width:100%;padding:1px 6px;border-radius:4px;background:var(--raised);overflow-wrap:anywhere;word-break:break-all}
.kv a{display:inline-flex;align-items:center;gap:4px}
.acts{display:none}
.embedded .acts{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:14px}
.act{height:32px;padding:0 12px;border:1px solid var(--control);border-radius:var(--radius-c);background:var(--surface);color:var(--text);font:inherit;font-size:13px;cursor:pointer}
.act:hover{background:var(--raised);border-color:var(--muted)}
.act-main{border-color:var(--text)}
.act:disabled{opacity:.55;cursor:default}
.act-done{color:var(--muted);font-size:13px}
.todo{margin:14px 0 0;padding:10px 12px;border-radius:var(--radius-c);background:var(--raised);max-width:78ch}
.todo b{font-weight:600}
.empty{margin:0;padding:28px 16px;color:var(--muted);text-align:center}
.link{padding:0;border:0;background:none;font-weight:600;color:inherit;text-decoration:underline;text-underline-offset:3px;cursor:pointer}
.link:hover{color:var(--hue)}
.empty button{margin-left:8px;border:0;background:none;color:var(--hue);cursor:pointer;text-decoration:underline;text-underline-offset:3px}

/* Guida finale */
.guide{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:48px;margin-top:48px;padding-top:32px;border-top:1px solid var(--border)}
.guide h2{font-size:16px;line-height:24px;margin-bottom:8px}
.guide ol{margin:0;padding-left:20px}
.guide li+li{margin-top:6px}
.guide p{margin:0;max-width:70ch}
.guide p+p{margin-top:8px}
.tl{margin-top:24px}
.tl-note{margin:0;color:var(--muted)}
.tl-rows{list-style:none;margin:0;padding:0}
.tl-row{display:grid;grid-template-columns:128px 88px minmax(0,1fr);gap:16px;align-items:baseline;padding:10px 16px;border-top:1px solid var(--rule)}
.tl-row:first-child{border-top:0}
.tl-row time{color:var(--muted);white-space:nowrap}
.tl-src{color:var(--muted);font-size:12px}
.tl-what{min-width:0;overflow-wrap:anywhere}
.tl-what code{display:block;margin-top:2px;color:var(--muted);font-size:12px}
.tl-what a{color:var(--text);text-decoration:underline;text-decoration-color:var(--control);text-underline-offset:3px}
.tl-what a:hover{text-decoration-color:var(--hue)}
.tl-more{margin:0;padding:12px 16px;border-top:1px solid var(--rule);color:var(--muted)}
.foot{max-width:1136px;margin:0 auto;padding:0 24px 32px;color:var(--muted);font-size:12px;line-height:16px}

@media (max-width:1000px){
  .r-body{padding-left:16px;padding-right:16px}
  .work{grid-template-columns:minmax(0,1fr)}
  .lib{position:static;padding:0}
  .lib-h{padding:0 0 8px}
  .lib ul{flex-direction:row;overflow-x:auto;scroll-snap-type:x proximity;padding-bottom:4px}
  .lib li{flex:none;scroll-snap-align:start}
  .area{width:auto;min-width:168px;display:flex;flex-direction:column;align-items:flex-start;gap:2px;padding:8px 10px;background:var(--surface);border:1px solid var(--border)}
  .a-name{white-space:nowrap}
}
@media (max-width:760px){
  .page{padding:20px 16px 32px}.bar-in{padding:0 16px}
  .title-row{flex-direction:column;align-items:stretch;gap:12px}
  .verify{padding:18px 16px 16px}.verdict{font-size:24px;line-height:30px}
  .verify-top{flex-direction:column;gap:4px}.done{order:-1;margin-top:0}
  .search{max-width:none}
  .sev{grid-template-columns:repeat(2,1fr)}
  .sev-c:nth-child(3){border-left:0}.sev-c:nth-child(n+3){border-top:1px solid var(--rule)}
  .list-head{flex-direction:column;align-items:stretch;gap:10px}
  .search{width:100%;height:40px}
  .row>summary{grid-template-columns:minmax(0,1fr) 16px;row-gap:8px}
  .row>summary .pill{grid-column:1;grid-row:1}
  .row>summary .r-main{grid-column:1/span 2;grid-row:2}
  .row>summary .ico{grid-column:2;grid-row:1}
  .r-body{padding:0 16px 16px}
  .kv{grid-template-columns:minmax(0,1fr)}.kv dd{margin-bottom:6px}
  .guide{grid-template-columns:minmax(0,1fr);gap:32px;margin-top:32px;padding-top:24px}
  .tl-row{grid-template-columns:minmax(0,1fr) auto;row-gap:4px}
  .tl-row .tl-what{grid-column:1/span 2}
  .foot{padding:0 16px 24px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
@media print{.bar,.actions,.search,.theme{display:none!important}.lib{position:static}.row>.r-body{display:block}body{background:#fff}}
'@

$script:ReportJs = @'
(function () {
  var d = document, root = d.documentElement;
  var rows = [].slice.call(d.querySelectorAll('.row'));
  var sevButtons = [].slice.call(d.querySelectorAll('.sev-c'));
  var areaButtons = [].slice.call(d.querySelectorAll('.area'));
  var count = d.querySelector('[data-count]');
  var empty = d.querySelector('.empty-filter');
  var input = d.querySelector('.search input');
  var on = {}, area = '', query = '';
  sevButtons.forEach(function (b) { on[b.getAttribute('data-sev')] = b.getAttribute('aria-pressed') === 'true'; });

  var allCount = d.querySelector('[data-all-count]');
  function apply() {
    var shown = 0, inAll = 0;
    rows.forEach(function (r) {
      var base = on[r.getAttribute('data-sev')] &&
        (!query || r.getAttribute('data-text').indexOf(query) !== -1);
      var ok = base && (!area || r.getAttribute('data-area') === area);
      r.hidden = !ok;
      if (base) inAll++;
      if (ok) shown++;
    });
    if (count) count.textContent = shown;
    if (allCount) allCount.textContent = inAll;
    if (empty) empty.hidden = shown > 0 || rows.length === 0;
  }
  sevButtons.forEach(function (b) {
    b.addEventListener('click', function () {
      var s = b.getAttribute('data-sev');
      on[s] = !on[s];
      b.setAttribute('aria-pressed', on[s] ? 'true' : 'false');
      apply();
    });
  });
  areaButtons.forEach(function (b) {
    b.addEventListener('click', function () {
      area = b.getAttribute('data-area');
      areaButtons.forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      apply();
    });
  });
  [].slice.call(d.querySelectorAll('[data-goto]')).forEach(function (g) {
    g.addEventListener('click', function () {
      var target = areaButtons.filter(function (b) { return b.getAttribute('data-area') === g.getAttribute('data-goto'); })[0];
      if (!target) return;
      target.click();
      var list = d.querySelector('.list');
      if (list) list.scrollIntoView({ block: 'start', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    });
  });
  if (input) input.addEventListener('input', function () { query = input.value.trim().toLowerCase(); apply(); });
  var reset = d.querySelector('[data-reset]');
  if (reset) reset.addEventListener('click', function () {
    sevButtons.forEach(function (b) { on[b.getAttribute('data-sev')] = true; b.setAttribute('aria-pressed', 'true'); });
    area = ''; query = ''; if (input) input.value = '';
    areaButtons.forEach(function (x, i) { x.setAttribute('aria-pressed', i === 0 ? 'true' : 'false'); });
    apply();
  });
  var theme = d.querySelector('.theme');
  if (theme) theme.addEventListener('click', function () {
    var dark = root.getAttribute('data-theme') ? root.getAttribute('data-theme') === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches;
    var next = dark ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    theme.setAttribute('aria-label', next === 'dark' ? 'Passa al tema chiaro' : 'Passa al tema scuro');
    try { localStorage.setItem('checkbackdoor-theme', next); } catch (e) {}
  });
  apply();

  // Dentro l'app: i pulsanti delle azioni chiedono all'app di eseguirle, e l'app risponde
  // con l'esito. Solo verso la pagina dell'app, e solo i messaggi che arrivano da li'.
  var APP = 'https://app.checkbackdoor.example';
  if (window.parent !== window) {
    d.addEventListener('click', function (e) {
      var b = e.target.closest && e.target.closest('[data-act]');
      if (!b) return;
      var box = b.closest('.acts');
      window.parent.postMessage({ source: 'checkbackdoor-report', action: b.getAttribute('data-act'), id: box.getAttribute('data-id') }, APP);
    });
    window.addEventListener('message', function (e) {
      if (e.origin !== APP || !e.data || e.data.source !== 'checkbackdoor-app') return;
      var box = d.querySelector('.acts[data-id="' + String(e.data.id).replace(/[^0-9a-f]/g, '') + '"]');
      if (!box) return;
      box.querySelector('.act-done').textContent = e.data.text || '';
      if (e.data.done) [].slice.call(box.querySelectorAll('[data-act="' + e.data.action + '"]')).forEach(function (x) { x.disabled = true; });
    });
  }
})();
'@

# Dentro l'app il report e' in un iframe: niente barra propria, tema passato nell'indirizzo (#theme=dark)
$script:ReportHeadJs = @'
var r=document.documentElement;r.className='js'+(window.self!==window.top?' embedded':'');try{var m=location.hash.match(/theme=(dark|light)/),t=m?m[1]:localStorage.getItem('checkbackdoor-theme');if(t==='dark'||t==='light')r.setAttribute('data-theme',t)}catch(e){}
'@

# Impronta di uno script per la Content-Security-Policy del report: il browser esegue solo
# gli script con queste impronte. Il testo del report e' gia' trasformato in testo semplice;
# questa e' la seconda barriera, se un giorno sfuggisse un nome scelto da un attaccante.
function Get-CspScriptHash {
    param([string]$Script)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return "'sha256-$([Convert]::ToBase64String($sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($Script))))'" } finally { $sha.Dispose() }
}

function New-HtmlReport {
    param($Findings, [hashtable]$Meta, $Timeline, $Ignored)
    $e = { param($t) ConvertTo-HtmlText $t }
    $p = { param($t) ConvertTo-HtmlText $t -Prose }
    $Findings = @($Findings)
    $counts = @{ Alto = 0; Medio = 0; Basso = 0; Info = 0 }
    foreach ($f in $Findings) { $counts[$f.Severity]++ }

    $examined = @{}; if ($Meta.Examined) { $examined = $Meta.Examined }
    $total = 0; foreach ($v in $examined.Values) { $total += [int]$v }
    $flagged = $counts.Alto + $counts.Medio
    $okCount = [Math]::Max($total - $flagged, 0)
    $fmt = { param($n) ([int]$n).ToString('N0', [Globalization.CultureInfo]'it-IT') }

    $fileMode = $Meta.Mode -eq 'File'
    $target = if ($fileMode -and $Meta.Target) { Split-Path -Leaf ([string]$Meta.Target) } else { $null }
    if ($fileMode) {
        # Controllo di un file: la domanda e' "posso aprirlo?"
        if ($counts.Alto -gt 0) {
            $verdict = if ($total -le 1) { 'Non aprire questo file' } else { "$($counts.Alto) file da non aprire" }
            $verdictText = 'Il file ha caratteristiche tipiche dei malware: firma manomessa, nome ingannevole, trucchi per sfuggire agli antivirus o DLL di sistema sostituite. Verificalo su VirusTotal prima di qualsiasi altra cosa.'
        } elseif ($counts.Medio -gt 0) {
            $verdict = 'Da verificare prima di aprirlo'
            $verdictText = 'Nessun segnale forte, ma qualcosa merita un controllo: leggi i motivi qui sotto e verifica il file su VirusTotal.'
        } else {
            $verdict = if ($total -le 1) { 'Nessun indizio nel file' } else { 'Nessun indizio nei file controllati' }
            $verdictText = 'La struttura del file non mostra i trucchi tipici dei malware. Non e'' una garanzia: un file ben confezionato puo'' sembrare pulito. Se viene da una fonte non ufficiale, verificalo anche su VirusTotal.'
        }
    } elseif ($counts.Alto -gt 0) {
        $verdict = if ($counts.Alto -eq 1) { 'Un indizio ad alto rischio da controllare subito' } else { "$($counts.Alto) indizi ad alto rischio da controllare subito" }
        $verdictText = 'Questi elementi corrispondono a tecniche usate da backdoor e malware. Non sono per forza infezioni, ma vanno verificati uno per uno, a partire dalle voci rosse.'
    } elseif ($counts.Medio -gt 0) {
        $verdict = "Nessun indizio grave, $($counts.Medio) $(if ($counts.Medio -eq 1) { 'elemento' } else { 'elementi' }) da verificare"
        $verdictText = 'Non ci sono segnali forti di compromissione. Gli elementi da verificare sono spesso software legittimo: controlla di riconoscerli uno per uno.'
    } else {
        $verdict = 'Nessun indizio di backdoor'
        $verdictText = 'Tutte le aree hanno superato la verifica. Riduce molto il rischio, ma nessuno strumento puo'' garantirlo al 100%: leggi i limiti in fondo alla pagina.'
    }

    $sb = New-Object Text.StringBuilder
    $add = { param($s) [void]$sb.Append($s) }

    $title = if ($fileMode) { "Controllo di $target" } else { "Verifica di $($Meta.Computer)" }
    # Il browser legge i ritorni a capo come LF: le impronte si calcolano sullo stesso testo
    $headJs = $script:ReportHeadJs -replace "`r`n", "`n"
    $bodyJs = $script:ReportJs -replace "`r`n", "`n"
    $csp = "default-src 'none'; script-src $(Get-CspScriptHash $headJs) $(Get-CspScriptHash $bodyJs); style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    & $add "<!doctype html>`n<html lang=""it""><head><meta charset=""utf-8""><meta http-equiv=""Content-Security-Policy"" content=""$csp"">"
    & $add "<meta name=""viewport"" content=""width=device-width,initial-scale=1"">"
    & $add "<meta name=""color-scheme"" content=""light dark""><meta name=""referrer"" content=""no-referrer"">"
    & $add "<title>$(& $e $title) - CheckBackdoor</title>"
    & $add "<script>$headJs</script>"
    & $add "<style>$script:ReportCss</style></head><body>"

    # Barra superiore: prodotto, PC esaminato, tema
    & $add "<header class=""bar""><div class=""bar-in""><span class=""mark"">$($script:Icons.Mark)CheckBackdoor</span>"
    & $add "<span class=""bar-scope"">$(& $e $Meta.Computer) &middot; $(& $e $Meta.User)</span>"
    & $add "<button class=""theme"" type=""button"" aria-label=""Cambia tema"">$($script:Icons.Moon)$($script:Icons.Sun)</button></div></header>"

    # Titolo e file collegati
    $subParts = if ($fileMode) { @("Controllato prima dell'apertura il $($Meta.Date)", [string]$Meta.Target) } else { @("Scansione del $($Meta.Date)") }
    if ($Meta.OS) { $subParts += $Meta.OS }
    if ($Meta.Deep) { $subParts += 'scansione approfondita' }
    & $add "<main class=""page""><div class=""title-row""><div><h1>$(& $e $title)</h1><p class=""sub"">$(($subParts | ForEach-Object { & $e $_ }) -join ' &middot; ')</p></div>"
    if ($Meta.Files) {
        & $add "<div class=""actions""><a class=""btn"" href=""$(& $e $Meta.Files.Json)"">$($script:Icons.File)Dati JSON</a><a class=""btn"" href=""$(& $e $Meta.Files.Csv)"">$($script:Icons.File)Tabella CSV</a></div>"
    }
    & $add '</div>'

    if (-not $Meta.Admin -and -not $fileMode) {
        & $add "<p class=""note""><b>Controlli incompleti:</b> la scansione non &egrave; stata eseguita come amministratore, quindi esclusioni di Defender, sottoscrizioni WMI e alcuni processi di sistema non sono stati letti. Avviala con Avvia-Scansione.bat e accetta la richiesta di privilegi.</p>"
    }
    if ($Meta.Errors) {
        & $add '<div class="note"><b>Alcuni controlli non sono stati completati:</b><ul>'
        foreach ($err in $Meta.Errors) { & $add "<li>$(& $e $err)</li>" }
        & $add '</ul></div>'
    }
    if ($Meta.ComparedTo) {
        $prevName = [IO.Path]::GetFileName([string]$Meta.ComparedTo)
        & $add "<p class=""note note-info"">Confrontata con la scansione precedente <code>$(& $e $prevName)</code>: le differenze sono nell'area <button class=""link"" type=""button"" data-goto=""$(& $e "Novita' dalla scansione precedente")"">Novit&agrave; dalla scansione precedente</button>.</p>"
    }

    # La verifica completata: verdetto e barra
    $unit = if ($fileMode) { 'file controllati' } else { 'elementi verificati' }
    $meterLabel = "$(& $fmt $total) $($unit): $($counts.Alto) a rischio alto, $($counts.Medio) da verificare"
    & $add "<section class=""verify"" aria-labelledby=""verdict""><div class=""verify-top""><h2 id=""verdict"" class=""verdict"">$(& $p $verdict)</h2>"
    & $add "<span class=""done"">$($script:Icons.Check)$(if ($fileMode) { 'Controllo' } else { 'Verifica' }) completat$(if ($fileMode) { 'o' } else { 'a' }) in $(& $e $Meta.Duration)</span></div>"
    & $add "<p class=""verdict-text"">$(& $p $verdictText)</p>"
    & $add "<div class=""meter"" role=""img"" aria-label=""$(& $e $meterLabel)""><span class=""m-ok"" style=""flex-grow:$okCount""></span>"
    if ($counts.Medio) { & $add "<span class=""m-medio"" style=""flex-grow:$($counts.Medio)""></span>" }
    if ($counts.Alto) { & $add "<span class=""m-alto"" style=""flex-grow:$($counts.Alto)""></span>" }
    & $add '</div><p class="meter-legend">'
    & $add "<span><span class=""dot d-ok""></span><b>$(& $fmt $okCount)</b> superati, su $(& $fmt $total) $unit</span>"
    & $add "<span><span class=""dot d-medio""></span><b>$($counts.Medio)</b> da verificare</span>"
    & $add "<span><span class=""dot d-alto""></span><b>$($counts.Alto)</b> a rischio alto</span></p></section>"

    # Gravita' come filtri
    $sevDef = @(
        @{ S = 'Alto'; L = 'Rischio alto'; C = 'is-alto' }, @{ S = 'Medio'; L = 'Da verificare'; C = 'is-medio' },
        @{ S = 'Basso'; L = 'Rischio basso'; C = '' }, @{ S = 'Info'; L = 'Informazioni'; C = '' }
    )
    & $add '<div class="sev" role="group" aria-label="Mostra le segnalazioni per gravit&agrave;">'
    foreach ($s in $sevDef) {
        $n = $counts[$s.S]
        $cls = 'sev-n'; if ($n -gt 0 -and $s.C) { $cls += " $($s.C)" }
        # Nel controllo di un file anche "nessun indizio" (Info) e' una risposta: si vede subito
        $pressed = if ($s.S -eq 'Info' -and -not $fileMode) { 'false' } else { 'true' }
        & $add "<button class=""sev-c"" type=""button"" data-sev=""$($s.S)"" aria-pressed=""$pressed""><span class=""sev-l"">$($script:Icons.Box)$($s.L)<span class=""sev-off"">&middot; nascoste</span></span><span class=""$cls"">$n</span></button>"
    }
    & $add '</div>'

    # Libreria delle aree
    $skipped = @($Meta.Skipped)
    $shown = @($Findings | Where-Object { $fileMode -or $_.Severity -ne 'Info' }).Count
    & $add "<div class=""work""><nav class=""lib"" aria-label=""Aree verificate""><h2 class=""lib-h"">Aree verificate</h2><ul>"
    & $add "<li><button class=""area"" type=""button"" data-area="""" aria-pressed=""true""><span class=""a-name"">Tutte le aree</span><span class=""a-meta"">$(if ($total -eq 1) { '1 elemento' } else { "$(& $fmt $total) elementi" })</span><span class=""a-state""><span data-all-count>$shown</span>segnalazioni</span></button></li>"
    if ($fileMode) {
        $areaList = @(@{ Name = 'File analizzato'; Check = 'File' })
    } else {
        $areaNames = @($script:ReportAreas | ForEach-Object { $_.Name })
        $extraAreas = @($Findings | Select-Object -ExpandProperty Category -Unique | Where-Object { $_ -notin $areaNames })
        $areaList = @($script:ReportAreas) + @($extraAreas | ForEach-Object { @{ Name = $_; Check = $null } })
    }
    foreach ($a in $areaList) {
        $af = @($Findings | Where-Object { $_.Category -eq $a.Name })
        $na = @($af | Where-Object Severity -eq 'Alto').Count
        $nm = @($af | Where-Object Severity -eq 'Medio').Count
        $isSkipped = $a.Check -and ($skipped -contains $a.Check)
        if ($isSkipped) { $state = '<span class="a-state s-off">Non eseguito</span>' }
        elseif ($na) { $state = "<span class=""a-state s-alto"">$($script:Icons.Risk)$na a rischio</span>" }
        elseif ($nm) { $state = "<span class=""a-state s-medio"">$($script:Icons.Review)$nm da verificare</span>" }
        else { $state = "<span class=""a-state"">$($script:Icons.Check)Verificato</span>" }
        $n = [int]$examined[$a.Name]
        $areaInfo = if (-not $a.Check) { "$($af.Count) differenze" } elseif ($n -eq 1) { '1 elemento' } else { "$(& $fmt $n) elementi" }
        & $add "<li><button class=""area"" type=""button"" data-area=""$(& $e $a.Name)"" aria-pressed=""false""><span class=""a-name"">$(& $p $a.Name)</span><span class=""a-meta"">$areaInfo</span>$state</button></li>"
    }
    & $add '</ul></nav>'

    # Segnalazioni
    & $add "<section class=""list"" aria-labelledby=""list-h""><div class=""list-head""><h2 id=""list-h"">Segnalazioni<span class=""count"" data-count>$shown</span></h2>"
    & $add "<label class=""search"">$($script:Icons.Search)<input type=""search"" placeholder=""Cerca file, programma o tecnica"" aria-label=""Cerca nelle segnalazioni""></label></div><div class=""rows"">"
    foreach ($f in $Findings) {
        $text = (@($f.Title, $f.Path, $f.Evidence, $f.Category, $f.Mitre, $f.Signer) + @($f.Reasons) | Where-Object { $_ }) -join ' '
        $first = @($f.Reasons | Where-Object { $_ } | Select-Object -First 1)
        $subline = (ConvertTo-ItalianProse $f.Category)
        if ($first) { $subline += " - $(ConvertTo-ItalianProse $first[0])" }
        $open = ''; if ($f.Severity -eq 'Alto') { $open = ' open' }
        $label = @{ Alto = 'Alto'; Medio = 'Da verificare'; Basso = 'Basso'; Info = 'Info' }[$f.Severity]
        & $add "<details class=""row"" id=""f-$(& $e $f.Id)"" data-sev=""$($f.Severity)"" data-area=""$(& $e $f.Category)"" data-text=""$(& $e $text.ToLowerInvariant())""$open>"
        & $add "<summary><span class=""pill p-$($f.Severity)"">$label</span><span class=""r-main""><span class=""r-title"">$(& $p $f.Title)</span><span class=""r-sub"">$(& $e $subline)</span></span>$($script:Icons.Chevron)</summary><div class=""r-body"">"
        if ($f.Reasons) {
            & $add '<ul class="reasons">'
            foreach ($r in $f.Reasons) { if ($r) { & $add "<li>$(& $p $r)</li>" } }
            & $add '</ul>'
        }
        & $add '<dl class="kv">'
        if ($f.Path) { & $add "<dt>File</dt><dd><code>$(& $e $f.Path)</code></dd>" }
        if ($f.Evidence) { & $add "<dt>Dettaglio</dt><dd><code>$(& $e $f.Evidence)</code></dd>" }
        if ($f.Detail) { & $add "<dt>Posizione</dt><dd>$(& $p $f.Detail)</dd>" }
        if ($f.Signer) { & $add "<dt>Firmato da</dt><dd>$(& $e $f.Signer)</dd>" }
        if ($f.Sha256) {
            $vt = "https://www.virustotal.com/gui/file/$($f.Sha256)"
            & $add "<dt>SHA-256</dt><dd><code>$($f.Sha256)</code><br><a href=""$vt"" target=""_blank"" rel=""noopener noreferrer"">Cerca su VirusTotal$($script:Icons.Out)</a></dd>"
        }
        if ($f.Mitre) {
            $links = foreach ($m in ($f.Mitre -split '\s*/\s*')) {
                if ($m -match '^T(\d{4})(\.(\d{3}))?$') {
                    $url = "https://attack.mitre.org/techniques/T$($Matches[1])/$(if ($Matches[3]) { $Matches[3] + '/' })"
                    "<a href=""$url"" target=""_blank"" rel=""noopener noreferrer"">$m$($script:Icons.Out)</a>"
                } else { & $e $m }
            }
            & $add "<dt>Tecnica</dt><dd>MITRE ATT&amp;CK $($links -join ' / ')</dd>"
        }
        & $add '</dl>'
        if ($f.Recommendation) { & $add "<p class=""todo""><b>Cosa fare.</b> $(& $p $f.Recommendation)</p>" }
        # Azioni: visibili solo dentro l'app, che le esegue (il report da solo resta di sola lettura)
        $acts = @()
        if ($f.Path -and [IO.Path]::IsPathRooted($f.Path)) { $acts += '<button type="button" class="act" data-act="reveal">Mostra il file</button>' }
        if ($f.Remedy) { $acts += '<button type="button" class="act act-main" data-act="disable">Disattiva</button>' }
        if ($f.Severity -ne 'Info') { $acts += '<button type="button" class="act" data-act="ignore">Ignora nelle prossime verifiche</button>' }
        if ($acts) { & $add "<div class=""acts"" data-id=""$(& $e $f.Id)"">$($acts -join '')<span class=""act-done"" role=""status""></span></div>" }
        & $add '</div></details>'
    }
    & $add '</div>'
    if (-not $Findings) { & $add '<p class="empty">Nessuna segnalazione: tutte le aree hanno superato la verifica.</p>' }
    & $add '<p class="empty empty-filter" hidden>Nessuna segnalazione con questi filtri.<button type="button" data-reset>Mostra tutto</button></p>'
    & $add '</section></div>'

    # Linea temporale: solo se il controllo e' stato eseguito ($null = non eseguito)
    if ($null -ne $Timeline) {
        $tl = @($Timeline | Sort-Object Time -Descending)
        $ids = @{}; foreach ($f in $Findings) { $ids[$f.Id] = $true }
        $maxRows = 60
        & $add "<section class=""list tl"" aria-labelledby=""tl-h""><div class=""list-head""><h2 id=""tl-h"">Linea temporale<span class=""count"">$($tl.Count)</span></h2><p class=""tl-note"">Ultimi 30 giorni secondo i registri di Windows</p></div>"
        if (-not $tl) {
            & $add '<p class="empty">Nessun evento rilevante negli ultimi 30 giorni.</p>'
        } else {
            & $add '<ol class="tl-rows">'
            foreach ($t in ($tl | Select-Object -First $maxRows)) {
                $when = [datetime]::Parse($t.Time, [Globalization.CultureInfo]::InvariantCulture)
                $dot = @{ Alto = '<span class="dot d-alto"></span>'; Medio = '<span class="dot d-medio"></span>' }[$t.Severity]
                $what = & $p $t.Text
                if ($t.FindingId -and $ids.ContainsKey($t.FindingId)) { $what = "<a href=""#f-$(& $e $t.FindingId)"">$what</a>" }
                $path = ''; if ($t.Path) { $path = "<code>$(& $e $t.Path)</code>" }
                & $add "<li class=""tl-row""><time datetime=""$(& $e $t.Time)"">$($when.ToString('dd/MM/yyyy HH:mm'))</time><span class=""tl-src"">$(& $e $t.Source)</span><span class=""tl-what"">$dot$what$path</span></li>"
            }
            & $add '</ol>'
            if ($tl.Count -gt $maxRows) { & $add "<p class=""tl-more"">Altri $($tl.Count - $maxRows) eventi nel file JSON.</p>" }
        }
        & $add '</section>'
    }

    # Elementi nascosti dalla lista bianca: chiusi, ma sempre elencati con la regola che li nasconde
    $hidden = @($Ignored | Where-Object { $_ })
    if ($hidden) {
        $maxHidden = 200
        & $add "<section class=""list tl"" aria-labelledby=""ig-h""><details><summary class=""list-head""><h2 id=""ig-h"">Nascosti dalla lista bianca<span class=""count"">$($hidden.Count)</span></h2><span class=""tl-note"">Controlla di riconoscerli tutti</span></summary>"
        & $add '<p class="tl-more">Questi elementi non compaiono tra le segnalazioni perch&eacute; corrispondono alla lista bianca o li hai ignorati dall''app. Se ne vedi uno che non hai scelto tu, qualcuno ha modificato la lista: toglilo e ripeti la verifica.</p><ol class="tl-rows">'
        foreach ($h in ($hidden | Select-Object -First $maxHidden)) {
            $path = ''; if ($h.Path) { $path = "<code>$(& $e $h.Path)</code>" }
            # Colonna stretta: solo il tipo di regola ("percorso", "titolo"...); la regola intera sotto il titolo
            $kind = ("$($h.Rule)" -split ' ')[0]
            & $add "<li class=""tl-row""><span class=""tl-src"">$(& $p $h.Category)</span><span class=""tl-src"">$(& $e $kind)</span><span class=""tl-what"">$(& $p $h.Title)$path<code>Regola: $(& $e $h.Rule)</code></span></li>"
        }
        & $add '</ol>'
        if ($hidden.Count -gt $maxHidden) { & $add "<p class=""tl-more"">Altri $($hidden.Count - $maxHidden) elementi nel file JSON.</p>" }
        & $add '</details></section>'
    }

    # Cosa fare e limiti
    & $add @'
<div class="guide"><section aria-labelledby="g1"><h2 id="g1">Se trovi qualcosa</h2><ol>
<li><b>Non cancellare subito.</b> Annota il percorso e cerca il file su VirusTotal con il link nella segnalazione.</li>
<li>Se un elemento rosso &egrave; confermato malevolo, scollega il PC da internet.</li>
<li>Esegui Microsoft Defender Offline (Sicurezza di Windows, Protezione da virus e minacce, Opzioni di analisi) e un secondo scanner.</li>
<li>Rimuovi prima le voci di avvio (attivit&agrave; pianificata, chiave Run, servizio) e solo dopo i file, altrimenti il malware si reinstalla.</li>
<li>Da un altro dispositivo cambia le password, a partire dall'email, e attiva la verifica in due passaggi.</li>
<li>Nel dubbio, su un PC con dati importanti, reinstalla Windows.</li>
</ol></section><section aria-labelledby="g2"><h2 id="g2">Cosa questa verifica non vede</h2>
<p>CheckBackdoor cerca le tracce che una backdoor lascia per sopravvivere ai riavvii e per comunicare. Non vede un rootkit gi&agrave; attivo nel kernel, che pu&ograve; nascondersi a Windows stesso: per quello serve Microsoft Defender Offline. Non vede il malware che vive solo in memoria, n&eacute; uno stealer che ha gi&agrave; rubato i dati e si &egrave; cancellato.</p>
<p>Molti elementi da verificare sono software legittimo: quelli che hai controllato si nascondono aggiungendoli ad <code>allowlist.local.json</code>. Per vedere cosa cambia un programma sospetto, esegui una scansione prima e una dopo con <code>-CompareLast</code>.</p>
</section></div></main>
'@
    $privacy = 'Report creato su questo PC: nessun dato della scansione &egrave; stato inviato.'
    if ($Meta.VirusTotal) { $privacy = 'Report creato su questo PC: solo le impronte SHA-256 dei file segnalati sono state inviate a VirusTotal.' }
    $ignored = ''
    if ($Meta.Ignored) { $ignored = " $($Meta.Ignored) elementi nascosti dalla lista bianca$(if ($hidden) { ', elencati qui sopra' })." }
    & $add "<footer class=""foot"">CheckBackdoor $(& $e $Meta.Version). $privacy$ignored</footer>"
    & $add "<script>$bodyJs</script></body></html>"
    return $sb.ToString()
}
