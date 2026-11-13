# Report: allowlist, comparison with a previous scan, JSON/CSV export and a
# readable HTML page.

$script:SeverityOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
$script:ChangesCategory = 'Changes since the previous scan'

# Applies the allowlist to findings already collected. During a scan the list is
# loaded first (Import-Allowlist) and Add-Finding drops matches by itself.
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
    try { $prev = [IO.File]::ReadAllText($PreviousJson) | ConvertFrom-Json } catch { Write-ScanWarning "Cannot read $PreviousJson"; return }
    # Network connections change all the time: they are left out of the comparison
    $noisy = { param($i) $i.Category -eq 'Network' -and $i.Key -match '^(Listen|Established) \|' -or $i.Key -eq 'Executable files examined' }
    $persistent = '^(Autostart|Scheduled tasks|Services|Drivers|WMI|COM hijacking|Safe Mode|Accounts|Windows defenses|Certificates|Browsers|App injections)'
    $old = @{}; foreach ($i in $prev.Inventory) { if (-not (& $noisy $i)) { $old["$($i.Category)|$($i.Key)|$($i.Value)"] = $i } }
    $new = @{}; foreach ($i in $script:Inventory) { if (-not (& $noisy $i)) { $new["$($i.Category)|$($i.Key)|$($i.Value)"] = $i } }
    $cat = $script:ChangesCategory
    foreach ($k in $new.Keys) {
        if ($old.ContainsKey($k)) { continue }
        $i = $new[$k]
        $sev = 'Low'; if ($i.Category -match $persistent) { $sev = 'Medium' }
        Add-Finding -Category $cat -Severity $sev -Title "New ($($i.Category)): $($i.Key)" -Evidence $i.Value `
            -Reasons "It was not there in the scan of $($prev.Meta.Date)." `
            -Recommendation 'If you installed something in the meantime (for example a game or a crack), this is one of the changes it made to the system.'
    }
    # Categories missing now (check skipped with -Skip) do not count as "removed"
    $currentCats = @{}; foreach ($i in $new.Values) { $currentCats[$i.Category] = $true }
    foreach ($k in $old.Keys) {
        if ($new.ContainsKey($k)) { continue }
        $i = $old[$k]
        if (-not $currentCats.ContainsKey($i.Category)) { continue }
        Add-Finding -Category $cat -Severity 'Info' -Title "Removed ($($i.Category)): $($i.Key)" -Evidence $i.Value -Reasons "It was there in the scan of $($prev.Meta.Date), not any more."
    }
}

# Areas shown in the report "library", in the order the user reads them,
# with the check (-Skip) that produces them.
$script:ReportAreas = @(
    @{ Name = 'Windows defenses'; Check = 'Security' }
    @{ Name = 'Autostart'; Check = 'Persistence' }
    @{ Name = 'Scheduled tasks'; Check = 'ScheduledTasks' }
    @{ Name = 'Services'; Check = 'Services' }
    @{ Name = 'Drivers'; Check = 'Services' }
    @{ Name = 'WMI'; Check = 'Wmi' }
    @{ Name = 'COM hijacking'; Check = 'Persistence' }
    @{ Name = 'Processes'; Check = 'Processes' }
    @{ Name = 'Network'; Check = 'Network' }
    @{ Name = 'Browsers'; Check = 'Browser' }
    @{ Name = 'App injections'; Check = 'Injections' }
    @{ Name = 'Accounts and remote access'; Check = 'Accounts' }
    @{ Name = 'Certificates'; Check = 'Certificates' }
    @{ Name = 'Suspicious files'; Check = 'FileSystem' }
    @{ Name = 'Timeline'; Check = 'Timeline' }
)

# How many items each area examined: the inventory entries, plus the counts
# that do not end up in the inventory (processes, files).
function Get-ExaminedCounts {
    $c = @{}
    foreach ($i in $script:Inventory) {
        $cat = $i.Category
        if ($cat -eq 'Safe Mode') { $cat = 'Services' }
        if ($i.Key -eq 'Executable files examined') { $c[$cat] = [int]$c[$cat] + [int]$i.Value; continue }
        $c[$cat] = [int]$c[$cat] + 1
    }
    if ($script:ProcessTable) { $c['Processes'] = $script:ProcessTable.Count }
    if ($script:TimelineExamined) { $c['Timeline'] = $script:TimelineExamined }
    return $c
}

function Export-Results {
    param([string]$OutputDir, [hashtable]$Meta, [string]$Prefix = 'scan')
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $OutputDir "$($Prefix)_$stamp"
    $sorted = @($script:Findings | Sort-Object { $script:SeverityOrder[$_.Severity] }, Category, Title)
    $Meta.Schema = 'checkbackdoor.report/1'
    $Meta.Examined = Get-ExaminedCounts
    $Meta.Files = @{ Json = "$($Prefix)_$stamp.json"; Csv = "$($Prefix)_$stamp.csv" }

    $timeline = $null
    if ($script:TimelineRan) { $timeline = @($script:Timeline | Sort-Object Time -Descending) }
    # What the allowlist hid stays in the report: a tampered list does not go unnoticed
    $ignored = @($script:Ignored | Sort-Object { $script:SeverityOrder[$_.Severity] }, Category, Title)
    $json = [ordered]@{ Meta = $Meta; Findings = $sorted; Ignored = $ignored; Inventory = $script:Inventory; Timeline = $timeline } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText("$base.json", $json, (New-Object Text.UTF8Encoding($false)))

    $sorted | Select-Object Id, Severity, Category, Title, Path, Evidence, @{ n = 'Reasons'; e = { $_.Reasons -join ' | ' } }, Mitre, Sha256, Signer, Recommendation |
        Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    $html = New-HtmlReport -Findings $sorted -Meta $Meta -Timeline $timeline -Ignored $ignored
    [IO.File]::WriteAllText("$base.html", $html, (New-Object Text.UTF8Encoding($false)))
    return "$base.html"
}

function ConvertTo-HtmlText {
    param($Text)
    if ($null -eq $Text) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Text)
}

# Hand-drawn icons, a single 1.5px stroke, color from the text
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
  --p-high-bg:#ffedea;--p-high:#831c1e;--p-medium-bg:#fdf0dc;--p-medium:#7c3a06;--p-low-bg:#eceef1;--p-low:#3d434a;--p-info-bg:transparent;--p-info:#596069;
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
  --p-high-bg:#3b191b;--p-high:#ffb4b0;--p-medium-bg:#3a2810;--p-medium:#f5c27a;--p-low-bg:#24262a;--p-low:#c9cdd2;--p-info-bg:transparent;--p-info:#a2a8af;
  --note-bg:#241c0c;--note-line:#4a3815;--note-ink:#f5c27a;color-scheme:dark;}}
:root[data-theme=dark]{
  --ground:#0c0d0e;--surface:#151618;--raised:#1c1d20;--active:#26282c;--border:#282a2e;--rule:#1f2124;--control:#3b3e43;
  --text:#f0f1f2;--muted:#a2a8af;--hue:#6f9dff;--hue-ink:#0b0c0d;
  --neg:#ff6b6b;--warn:#f0a43c;--warn-ink:#f5c27a;
  --p-high-bg:#3b191b;--p-high:#ffb4b0;--p-medium-bg:#3a2810;--p-medium:#f5c27a;--p-low-bg:#24262a;--p-low:#c9cdd2;--p-info-bg:transparent;--p-info:#a2a8af;
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

/* Top bar */
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

/* Page */
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

/* Check: the verdict and the completed bar */
.verify{margin-top:24px;padding:24px 24px 20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
.verify-top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px}
.verdict{font:600 30px/36px var(--font-d);letter-spacing:-.015em}
.done{display:inline-flex;align-items:center;gap:6px;flex:none;margin-top:6px;color:var(--muted);font-size:13px;white-space:nowrap}
.done .ico{color:var(--hue)}
.verdict-text{margin:8px 0 0;max-width:72ch;color:var(--text)}
.meter{display:flex;gap:2px;height:8px;margin-top:20px;border-radius:999px;overflow:hidden;transform-origin:left center;animation:fill .9s cubic-bezier(.16,1,.3,1) both}
.meter span{display:block;min-width:4px}
.m-ok{background:var(--hue)}.m-high{background:var(--neg)}.m-medium{background:var(--warn)}
.meter-legend{display:flex;flex-wrap:wrap;gap:4px 20px;margin:10px 0 0;color:var(--muted);font-size:13px}
.meter-legend b{color:var(--text);font-weight:600}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}
.d-ok{background:var(--hue)}.d-high{background:var(--neg)}.d-medium{background:var(--warn)}
@keyframes fill{from{transform:scaleX(0)}to{transform:scaleX(1)}}

/* Severity: one split container, every cell is also a filter */
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
.sev-n.is-high{color:var(--neg)}.sev-n.is-medium{color:var(--warn-ink)}
.sev-off{display:none;color:var(--muted)}
.js .sev-c[aria-pressed=false] .sev-n{color:var(--muted);font-weight:400}
.js .sev-c[aria-pressed=false] .sev-off{display:inline}

/* Area library + findings */
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
.a-state.s-high{color:var(--neg);font-weight:600}.a-state.s-medium{color:var(--warn-ink);font-weight:600}
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
.p-High{background:var(--p-high-bg);color:var(--p-high)}
.p-Medium{background:var(--p-medium-bg);color:var(--p-medium)}
.p-Low{background:var(--p-low-bg);color:var(--p-low)}
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

/* Closing guide */
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
    theme.setAttribute('aria-label', next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    try { localStorage.setItem('checkbackdoor-theme', next); } catch (e) {}
  });
  apply();

  // Inside the app: the action buttons ask the app to run them, and the app replies
  // with the outcome. Only towards the app page, and only messages coming from there.
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

# Inside the app the report is in an iframe: no own bar, theme passed in the address (#theme=dark)
$script:ReportHeadJs = @'
var r=document.documentElement;r.className='js'+(window.self!==window.top?' embedded':'');try{var m=location.hash.match(/theme=(dark|light)/),t=m?m[1]:localStorage.getItem('checkbackdoor-theme');if(t==='dark'||t==='light')r.setAttribute('data-theme',t)}catch(e){}
'@

# Hash of a script for the report's Content-Security-Policy: the browser runs only the
# scripts with these hashes. The report text is already turned into plain text;
# this is the second barrier, should a name chosen by an attacker ever slip through.
function Get-CspScriptHash {
    param([string]$Script)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return "'sha256-$([Convert]::ToBase64String($sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($Script))))'" } finally { $sha.Dispose() }
}

function New-HtmlReport {
    param($Findings, [hashtable]$Meta, $Timeline, $Ignored)
    $e = { param($t) ConvertTo-HtmlText $t }
    $Findings = @($Findings)
    $counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $Findings) { $counts[$f.Severity]++ }

    $examined = @{}; if ($Meta.Examined) { $examined = $Meta.Examined }
    $total = 0; foreach ($v in $examined.Values) { $total += [int]$v }
    $flagged = $counts.High + $counts.Medium
    $okCount = [Math]::Max($total - $flagged, 0)
    $fmt = { param($n) ([int]$n).ToString('N0', [Globalization.CultureInfo]::InvariantCulture) }
    $items = { param($n) if ([int]$n -eq 1) { '1 item' } else { "$(& $fmt $n) items" } }

    $fileMode = $Meta.Mode -eq 'File'
    $target = if ($fileMode -and $Meta.Target) { Split-Path -Leaf ([string]$Meta.Target) } else { $null }
    if ($fileMode) {
        # Checking a file: the question is "can I open it?"
        if ($counts.High -gt 0) {
            $verdict = if ($total -le 1) { 'Do not open this file' } else { "$($counts.High) files not to open" }
            $verdictText = 'The file has traits typical of malware: a tampered signature, a misleading name, tricks to slip past antivirus software or replaced system DLLs. Check it on VirusTotal before anything else.'
        } elseif ($counts.Medium -gt 0) {
            $verdict = 'Check it before opening it'
            $verdictText = 'No strong signal, but something deserves a look: read the reasons below and check the file on VirusTotal.'
        } else {
            $verdict = if ($total -le 1) { 'No clues in the file' } else { 'No clues in the checked files' }
            $verdictText = 'The structure of the file shows none of the usual malware tricks. It is not a guarantee: a well-made file can look clean. If it comes from an unofficial source, check it on VirusTotal too.'
        }
    } elseif ($counts.High -gt 0) {
        $verdict = if ($counts.High -eq 1) { 'One high-risk clue to check now' } else { "$($counts.High) high-risk clues to check now" }
        $verdictText = 'These items match techniques used by backdoors and malware. They are not necessarily infections, but check them one by one, starting with the red ones.'
    } elseif ($counts.Medium -gt 0) {
        $verdict = "No serious clues, $($counts.Medium) $(if ($counts.Medium -eq 1) { 'item' } else { 'items' }) to review"
        $verdictText = 'There are no strong signs of compromise. Items to review are often legitimate software: make sure you recognize each one.'
    } else {
        $verdict = 'No signs of a backdoor'
        $verdictText = 'Every area passed the check. This lowers the risk a lot, but no tool can guarantee it 100%: read the limits at the bottom of the page.'
    }

    $sb = New-Object Text.StringBuilder
    $add = { param($s) [void]$sb.Append($s) }

    $title = if ($fileMode) { "Check of $target" } else { "Scan of $($Meta.Computer)" }
    # The browser reads line breaks as LF: hashes are computed on the same text
    $headJs = $script:ReportHeadJs -replace "`r`n", "`n"
    $bodyJs = $script:ReportJs -replace "`r`n", "`n"
    $csp = "default-src 'none'; script-src $(Get-CspScriptHash $headJs) $(Get-CspScriptHash $bodyJs); style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
    & $add "<!doctype html>`n<html lang=""en""><head><meta charset=""utf-8""><meta http-equiv=""Content-Security-Policy"" content=""$csp"">"
    & $add "<meta name=""viewport"" content=""width=device-width,initial-scale=1"">"
    & $add "<meta name=""color-scheme"" content=""light dark""><meta name=""referrer"" content=""no-referrer"">"
    & $add "<title>$(& $e $title) - CheckBackdoor</title>"
    & $add "<script>$headJs</script>"
    & $add "<style>$script:ReportCss</style></head><body>"

    # Top bar: product, scanned PC, theme
    & $add "<header class=""bar""><div class=""bar-in""><span class=""mark"">$($script:Icons.Mark)CheckBackdoor</span>"
    & $add "<span class=""bar-scope"">$(& $e $Meta.Computer) &middot; $(& $e $Meta.User)</span>"
    & $add "<button class=""theme"" type=""button"" aria-label=""Change theme"">$($script:Icons.Moon)$($script:Icons.Sun)</button></div></header>"

    # Title and linked files
    $subParts = if ($fileMode) { @("Checked before opening on $($Meta.Date)", [string]$Meta.Target) } else { @("Scan of $($Meta.Date)") }
    if ($Meta.OS) { $subParts += $Meta.OS }
    if ($Meta.Deep) { $subParts += 'deep scan' }
    & $add "<main class=""page""><div class=""title-row""><div><h1>$(& $e $title)</h1><p class=""sub"">$(($subParts | ForEach-Object { & $e $_ }) -join ' &middot; ')</p></div>"
    if ($Meta.Files) {
        & $add "<div class=""actions""><a class=""btn"" href=""$(& $e $Meta.Files.Json)"">$($script:Icons.File)JSON data</a><a class=""btn"" href=""$(& $e $Meta.Files.Csv)"">$($script:Icons.File)CSV table</a></div>"
    }
    & $add '</div>'

    if (-not $Meta.Admin -and -not $fileMode) {
        & $add "<p class=""note""><b>Incomplete checks:</b> the scan did not run as administrator, so Defender exclusions, WMI subscriptions and some system processes were not read. Start it with Start-Scan.bat and accept the elevation prompt.</p>"
    }
    if ($Meta.Errors) {
        & $add '<div class="note"><b>Some checks did not complete:</b><ul>'
        foreach ($err in $Meta.Errors) { & $add "<li>$(& $e $err)</li>" }
        & $add '</ul></div>'
    }
    if ($Meta.ComparedTo) {
        $prevName = [IO.Path]::GetFileName([string]$Meta.ComparedTo)
        & $add "<p class=""note note-info"">Compared with the previous scan <code>$(& $e $prevName)</code>: the differences are in the area <button class=""link"" type=""button"" data-goto=""$(& $e $script:ChangesCategory)"">$(& $e $script:ChangesCategory)</button>.</p>"
    }

    # The completed check: verdict and bar
    $unit = if ($fileMode) { 'files checked' } else { 'items checked' }
    $meterLabel = "$(& $fmt $total) $($unit): $($counts.High) high risk, $($counts.Medium) to review"
    & $add "<section class=""verify"" aria-labelledby=""verdict""><div class=""verify-top""><h2 id=""verdict"" class=""verdict"">$(& $e $verdict)</h2>"
    & $add "<span class=""done"">$($script:Icons.Check)$(if ($fileMode) { 'Check' } else { 'Scan' }) completed in $(& $e $Meta.Duration)</span></div>"
    & $add "<p class=""verdict-text"">$(& $e $verdictText)</p>"
    & $add "<div class=""meter"" role=""img"" aria-label=""$(& $e $meterLabel)""><span class=""m-ok"" style=""flex-grow:$okCount""></span>"
    if ($counts.Medium) { & $add "<span class=""m-medium"" style=""flex-grow:$($counts.Medium)""></span>" }
    if ($counts.High) { & $add "<span class=""m-high"" style=""flex-grow:$($counts.High)""></span>" }
    & $add '</div><p class="meter-legend">'
    & $add "<span><span class=""dot d-ok""></span><b>$(& $fmt $okCount)</b> passed, out of $(& $fmt $total) $unit</span>"
    & $add "<span><span class=""dot d-medium""></span><b>$($counts.Medium)</b> to review</span>"
    & $add "<span><span class=""dot d-high""></span><b>$($counts.High)</b> high risk</span></p></section>"

    # Severity as filters
    $sevDef = @(
        @{ S = 'High'; L = 'High risk'; C = 'is-high' }, @{ S = 'Medium'; L = 'To review'; C = 'is-medium' },
        @{ S = 'Low'; L = 'Low risk'; C = '' }, @{ S = 'Info'; L = 'Information'; C = '' }
    )
    & $add '<div class="sev" role="group" aria-label="Show findings by severity">'
    foreach ($s in $sevDef) {
        $n = $counts[$s.S]
        $cls = 'sev-n'; if ($n -gt 0 -and $s.C) { $cls += " $($s.C)" }
        # When checking a file, "no clues" (Info) is an answer too: it shows right away
        $pressed = if ($s.S -eq 'Info' -and -not $fileMode) { 'false' } else { 'true' }
        & $add "<button class=""sev-c"" type=""button"" data-sev=""$($s.S)"" aria-pressed=""$pressed""><span class=""sev-l"">$($script:Icons.Box)$($s.L)<span class=""sev-off"">&middot; hidden</span></span><span class=""$cls"">$n</span></button>"
    }
    & $add '</div>'

    # Area library
    $skipped = @($Meta.Skipped)
    $shown = @($Findings | Where-Object { $fileMode -or $_.Severity -ne 'Info' }).Count
    & $add "<div class=""work""><nav class=""lib"" aria-label=""Areas checked""><h2 class=""lib-h"">Areas checked</h2><ul>"
    & $add "<li><button class=""area"" type=""button"" data-area="""" aria-pressed=""true""><span class=""a-name"">All areas</span><span class=""a-meta"">$(& $items $total)</span><span class=""a-state""><span data-all-count>$shown</span>findings</span></button></li>"
    if ($fileMode) {
        $areaList = @(@{ Name = 'Checked file'; Check = 'File' })
    } else {
        $areaNames = @($script:ReportAreas | ForEach-Object { $_.Name })
        $extraAreas = @($Findings | Select-Object -ExpandProperty Category -Unique | Where-Object { $_ -notin $areaNames })
        $areaList = @($script:ReportAreas) + @($extraAreas | ForEach-Object { @{ Name = $_; Check = $null } })
    }
    foreach ($a in $areaList) {
        $af = @($Findings | Where-Object { $_.Category -eq $a.Name })
        $nh = @($af | Where-Object Severity -eq 'High').Count
        $nm = @($af | Where-Object Severity -eq 'Medium').Count
        $isSkipped = $a.Check -and ($skipped -contains $a.Check)
        if ($isSkipped) { $state = '<span class="a-state s-off">Not run</span>' }
        elseif ($nh) { $state = "<span class=""a-state s-high"">$($script:Icons.Risk)$nh at risk</span>" }
        elseif ($nm) { $state = "<span class=""a-state s-medium"">$($script:Icons.Review)$nm to review</span>" }
        else { $state = "<span class=""a-state"">$($script:Icons.Check)Checked</span>" }
        $n = [int]$examined[$a.Name]
        $areaInfo = if (-not $a.Check) { "$($af.Count) $(if ($af.Count -eq 1) { 'difference' } else { 'differences' })" } else { & $items $n }
        & $add "<li><button class=""area"" type=""button"" data-area=""$(& $e $a.Name)"" aria-pressed=""false""><span class=""a-name"">$(& $e $a.Name)</span><span class=""a-meta"">$areaInfo</span>$state</button></li>"
    }
    & $add '</ul></nav>'

    # Findings
    & $add "<section class=""list"" aria-labelledby=""list-h""><div class=""list-head""><h2 id=""list-h"">Findings<span class=""count"" data-count>$shown</span></h2>"
    & $add "<label class=""search"">$($script:Icons.Search)<input type=""search"" placeholder=""Search file, program or technique"" aria-label=""Search the findings""></label></div><div class=""rows"">"
    foreach ($f in $Findings) {
        $text = (@($f.Title, $f.Path, $f.Evidence, $f.Category, $f.Mitre, $f.Signer) + @($f.Reasons) | Where-Object { $_ }) -join ' '
        $first = @($f.Reasons | Where-Object { $_ } | Select-Object -First 1)
        $subline = [string]$f.Category
        if ($first) { $subline += " - $($first[0])" }
        $open = ''; if ($f.Severity -eq 'High') { $open = ' open' }
        $label = @{ High = 'High'; Medium = 'Review'; Low = 'Low'; Info = 'Info' }[$f.Severity]
        & $add "<details class=""row"" id=""f-$(& $e $f.Id)"" data-sev=""$($f.Severity)"" data-area=""$(& $e $f.Category)"" data-text=""$(& $e $text.ToLowerInvariant())""$open>"
        & $add "<summary><span class=""pill p-$($f.Severity)"">$label</span><span class=""r-main""><span class=""r-title"">$(& $e $f.Title)</span><span class=""r-sub"">$(& $e $subline)</span></span>$($script:Icons.Chevron)</summary><div class=""r-body"">"
        if ($f.Reasons) {
            & $add '<ul class="reasons">'
            foreach ($r in $f.Reasons) { if ($r) { & $add "<li>$(& $e $r)</li>" } }
            & $add '</ul>'
        }
        & $add '<dl class="kv">'
        if ($f.Path) { & $add "<dt>File</dt><dd><code>$(& $e $f.Path)</code></dd>" }
        if ($f.Evidence) { & $add "<dt>Detail</dt><dd><code>$(& $e $f.Evidence)</code></dd>" }
        if ($f.Detail) { & $add "<dt>Location</dt><dd>$(& $e $f.Detail)</dd>" }
        if ($f.Signer) { & $add "<dt>Signed by</dt><dd>$(& $e $f.Signer)</dd>" }
        if ($f.Sha256) {
            $vt = "https://www.virustotal.com/gui/file/$($f.Sha256)"
            & $add "<dt>SHA-256</dt><dd><code>$($f.Sha256)</code><br><a href=""$vt"" target=""_blank"" rel=""noopener noreferrer"">Look up on VirusTotal$($script:Icons.Out)</a></dd>"
        }
        if ($f.Mitre) {
            $links = foreach ($m in ($f.Mitre -split '\s*/\s*')) {
                if ($m -match '^T(\d{4})(\.(\d{3}))?$') {
                    $url = "https://attack.mitre.org/techniques/T$($Matches[1])/$(if ($Matches[3]) { $Matches[3] + '/' })"
                    "<a href=""$url"" target=""_blank"" rel=""noopener noreferrer"">$m$($script:Icons.Out)</a>"
                } else { & $e $m }
            }
            & $add "<dt>Technique</dt><dd>MITRE ATT&amp;CK $($links -join ' / ')</dd>"
        }
        & $add '</dl>'
        if ($f.Recommendation) { & $add "<p class=""todo""><b>What to do.</b> $(& $e $f.Recommendation)</p>" }
        # Actions: visible only inside the app, which carries them out (the report alone stays read-only)
        $acts = @()
        if ($f.Path -and [IO.Path]::IsPathRooted($f.Path)) { $acts += '<button type="button" class="act" data-act="reveal">Show the file</button>' }
        if ($f.Remedy) { $acts += '<button type="button" class="act act-main" data-act="disable">Disable</button>' }
        if ($f.Severity -ne 'Info') { $acts += '<button type="button" class="act" data-act="ignore">Ignore in future scans</button>' }
        if ($acts) { & $add "<div class=""acts"" data-id=""$(& $e $f.Id)"">$($acts -join '')<span class=""act-done"" role=""status""></span></div>" }
        & $add '</div></details>'
    }
    & $add '</div>'
    if (-not $Findings) { & $add '<p class="empty">No findings: every area passed the check.</p>' }
    & $add '<p class="empty empty-filter" hidden>No findings match these filters.<button type="button" data-reset>Show all</button></p>'
    & $add '</section></div>'

    # Timeline: only if the check ran ($null = not run)
    if ($null -ne $Timeline) {
        $tl = @($Timeline | Sort-Object Time -Descending)
        $ids = @{}; foreach ($f in $Findings) { $ids[$f.Id] = $true }
        $maxRows = 60
        & $add "<section class=""list tl"" aria-labelledby=""tl-h""><div class=""list-head""><h2 id=""tl-h"">Timeline<span class=""count"">$($tl.Count)</span></h2><p class=""tl-note"">Last 30 days according to the Windows logs</p></div>"
        if (-not $tl) {
            & $add '<p class="empty">No relevant events in the last 30 days.</p>'
        } else {
            & $add '<ol class="tl-rows">'
            foreach ($t in ($tl | Select-Object -First $maxRows)) {
                $when = [datetime]::Parse($t.Time, [Globalization.CultureInfo]::InvariantCulture)
                $dot = @{ High = '<span class="dot d-high"></span>'; Medium = '<span class="dot d-medium"></span>' }[$t.Severity]
                $what = & $e $t.Text
                if ($t.FindingId -and $ids.ContainsKey($t.FindingId)) { $what = "<a href=""#f-$(& $e $t.FindingId)"">$what</a>" }
                $path = ''; if ($t.Path) { $path = "<code>$(& $e $t.Path)</code>" }
                & $add "<li class=""tl-row""><time datetime=""$(& $e $t.Time)"">$($when.ToString('yyyy-MM-dd HH:mm'))</time><span class=""tl-src"">$(& $e $t.Source)</span><span class=""tl-what"">$dot$what$path</span></li>"
            }
            & $add '</ol>'
            if ($tl.Count -gt $maxRows) { & $add "<p class=""tl-more"">$($tl.Count - $maxRows) more events in the JSON file.</p>" }
        }
        & $add '</section>'
    }

    # Items hidden by the allowlist: collapsed, but always listed with the rule that hides them
    $hidden = @($Ignored | Where-Object { $_ })
    if ($hidden) {
        $maxHidden = 200
        & $add "<section class=""list tl"" aria-labelledby=""ig-h""><details><summary class=""list-head""><h2 id=""ig-h"">Hidden by the allowlist<span class=""count"">$($hidden.Count)</span></h2><span class=""tl-note"">Make sure you recognize all of them</span></summary>"
        & $add '<p class="tl-more">These items are not among the findings because they match the allowlist or you ignored them in the app. If you see one you did not choose yourself, someone changed the list: remove it and run the scan again.</p><ol class="tl-rows">'
        foreach ($h in ($hidden | Select-Object -First $maxHidden)) {
            $path = ''; if ($h.Path) { $path = "<code>$(& $e $h.Path)</code>" }
            # Narrow column: only the kind of rule ("path", "title"...); the full rule under the title
            $kind = ("$($h.Rule)" -split ' ')[0]
            & $add "<li class=""tl-row""><span class=""tl-src"">$(& $e $h.Category)</span><span class=""tl-src"">$(& $e $kind)</span><span class=""tl-what"">$(& $e $h.Title)$path<code>Rule: $(& $e $h.Rule)</code></span></li>"
        }
        & $add '</ol>'
        if ($hidden.Count -gt $maxHidden) { & $add "<p class=""tl-more"">$($hidden.Count - $maxHidden) more items in the JSON file.</p>" }
        & $add '</details></section>'
    }

    # What to do and limits
    & $add @'
<div class="guide"><section aria-labelledby="g1"><h2 id="g1">If you find something</h2><ol>
<li><b>Do not delete it right away.</b> Note the path and look the file up on VirusTotal with the link in the finding.</li>
<li>If a red item is confirmed malicious, disconnect the PC from the internet.</li>
<li>Run Microsoft Defender Offline (Windows Security, Virus &amp; threat protection, Scan options) and a second scanner.</li>
<li>Remove the startup entries first (scheduled task, Run key, service) and only then the files, otherwise the malware reinstalls itself.</li>
<li>From another device, change your passwords, starting with your email, and turn on two-step verification.</li>
<li>When in doubt, on a PC with important data, reinstall Windows.</li>
</ol></section><section aria-labelledby="g2"><h2 id="g2">What this scan cannot see</h2>
<p>CheckBackdoor looks for the traces a backdoor leaves to survive reboots and to communicate. It cannot see a rootkit already active in the kernel, which can hide from Windows itself: for that you need Microsoft Defender Offline. It cannot see malware that lives only in memory, nor a stealer that already stole the data and deleted itself.</p>
<p>Many items to review are legitimate software: hide the ones you have checked by adding them to <code>allowlist.local.json</code>. To see what a suspicious program changes, run one scan before and one after with <code>-CompareLast</code>.</p>
</section></div></main>
'@
    $privacy = 'Report created on this PC: no scan data was sent anywhere.'
    if ($Meta.VirusTotal) { $privacy = 'Report created on this PC: only the SHA-256 hashes of the flagged files were sent to VirusTotal.' }
    $ignoredNote = ''
    if ($Meta.Ignored) { $ignoredNote = " $($Meta.Ignored) items hidden by the allowlist$(if ($hidden) { ', listed above' })." }
    & $add "<footer class=""foot"">CheckBackdoor $(& $e $Meta.Version). $privacy$ignoredNote</footer>"
    & $add "<script>$bodyJs</script></body></html>"
    return $sb.ToString()
}
