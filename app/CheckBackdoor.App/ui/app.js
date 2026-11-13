// CheckBackdoor - interface. Talks to the window (MainWindow.xaml.cs) through
// { type, ... } messages and shows the engine events (docs/EVENTS.md).
// Outside the app (in a browser) it uses a demo engine with fake data.
(function () {
  'use strict';
  var d = document, root = d.documentElement;
  var $ = function (id) { return d.getElementById(id); };
  var webview = window.chrome && window.chrome.webview;
  var host = webview ? realHost() : demoHost();

  var ICON = {
    check: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg>',
    review: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6"/><path d="M8 4.75v3.5M8 11.1v.15"/></svg>',
    risk: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.75L14.5 13.5h-13z"/><path d="M8 6v3.25M8 11.35v.15"/></svg>',
    file: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 1.75h5l3 3v9.5H4z"/><path d="M9 1.75v3h3"/></svg>'
  };
  var LABEL = { High: 'High', Medium: 'Review', Low: 'Low', Info: 'Info' };
  // One sentence per area: while waiting, the user understands what is being looked for
  var EXPLAIN = {
    Security: 'Whether Defender is on, whether someone added exclusions (the most common trick of cracks) and whether Windows Update or the firewall were turned off.',
    Persistence: 'The registry keys and folders from which programs start by themselves at every boot: that is where a backdoor makes sure it survives a restart.',
    ScheduledTasks: 'Scheduled tasks, including the ones hidden on purpose: miners and RATs use them to come back even after the game was uninstalled.',
    Services: 'Services and drivers: they run with the highest privileges or in the core of Windows, so they are the most dangerous form of persistence.',
    Wmi: 'WMI subscriptions: a "fileless" way to start that does not show up among the programs that start automatically.',
    Processes: 'The programs running right now: names that imitate Windows ones, obfuscated commands and the CPU usage typical of miners.',
    Network: 'Open ports, connections to the internet, the hosts file, proxies and remote control programs.',
    Browser: 'Browser extensions: those flagged as malware, loaded secretly or forced by a policy. It does not read history, cookies or passwords.',
    Injections: 'The code of Discord and of crypto wallets: some stealers change it to steal the token or the recovery phrase.',
    Accounts: 'Unknown or hidden administrator accounts and remote access to the PC.',
    Certificates: 'Added root certificates, which would allow reading protected (HTTPS) traffic.',
    FileSystem: 'Files in AppData, Temp and ProgramData, where malware installs itself without asking for permission. This is the longest step.',
    Timeline: 'The Windows logs of the last 30 days: services installed and then gone, Defender turned off or given exclusions, threats found, accounts created, suspicious PowerShell scripts and programs started from Downloads and Temp.',
    File: 'Digital signature, origin, structure of the executable and tricks to slip past antivirus software. The file is only read.',
    VirusTotal: 'The hashes of the flagged files are compared with VirusTotal: only the hash is sent, never the file.',
    Compare: 'The comparison with the previous scan, to see what changed.'
  };

  var app = { recent: [], isAdmin: false, scan: null, lastReport: null };

  // --- helpers ------------------------------------------------------------
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return '&#' + c.charCodeAt(0) + ';'; }); }
  function num(n) { return n.toLocaleString('en-US'); }
  function plural(n, one, many) { return n === 1 ? '1 ' + one : num(n) + ' ' + many; }
  function show(view) {
    ['home', 'scan', 'end', 'results', 'history', 'compare', 'settings'].forEach(function (v) { $('view-' + v).hidden = v !== view; });
    var section = { history: 'history', compare: 'history', settings: 'settings' }[view] || 'home';
    [].slice.call(d.querySelectorAll('.nav-b')).forEach(function (b) {
      if (b.getAttribute('data-nav') === section) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    // The active view goes right after the bar: its title is the first one on the page
    d.querySelector('.bar').after($('view-' + view));
    window.scrollTo(0, 0);
  }
  function theme() {
    var t = root.getAttribute('data-theme');
    return t || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }

  // --- home ---------------------------------------------------------------
  function verdictOf(r) {
    var c = r.counts || {};
    if (r.mode === 'File') {
      if (c.High) return 'Do not open the checked file';
      if (c.Medium) return 'Check the file before opening it';
      return 'No clues in the checked file';
    }
    if (c.High) return (c.High === 1 ? 'One high-risk clue' : c.High + ' high-risk clues') + ' to check';
    if (c.Medium) return 'No serious clues, ' + plural(c.Medium, 'item', 'items') + ' to review';
    return 'No signs of a backdoor';
  }
  function stateOf(r) {
    var c = r.counts || {};
    if (c.High) return '<span class="h-state s-high">' + ICON.risk + c.High + ' at risk</span>';
    if (c.Medium) return '<span class="h-state s-medium">' + ICON.review + c.Medium + ' to review</span>';
    return '<span class="h-state">' + ICON.check + 'No clues</span>';
  }
  function nameOf(path) { return String(path || '').split(/[\\/]/).pop(); }

  function renderHome() {
    var scans = app.recent.filter(function (r) { return r.mode !== 'File'; });
    var last = scans[0];
    $('home-sub').textContent = last ? 'Last PC scan on ' + last.date + (last.admin ? '' : ' (without administrator rights)') : 'No scans yet';
    var p = $('last');
    if (!last) {
      p.className = 'verify first-run';
      p.innerHTML = '<h2 id="last-h" class="verdict">You have not scanned this PC yet</h2>' +
        '<p class="verdict-text">The scan reads the places where a backdoor hides, without changing anything, and takes two or three minutes. Windows will ask for administrator rights: they are needed to read the Defender exclusions and the system processes.</p>' +
        '<div class="verify-actions"><button class="btn btn-primary" type="button" data-action="startScan">Start the scan</button></div>';
      return renderHistory();
    }
    var c = last.counts, total = last.examined || 0, flagged = c.High + c.Medium, ok = Math.max(total - flagged, 0);
    p.className = 'verify';
    p.innerHTML = '<div class="verify-top"><h2 id="last-h" class="verdict">' + esc(verdictOf(last)) + '</h2>' +
      '<span class="done">' + ICON.check + 'Scan of ' + esc(last.date) + '</span></div>' +
      '<div class="meter" role="img" aria-label="' + total + ' items checked, ' + c.High + ' high risk, ' + c.Medium + ' to review">' +
      '<span class="m-ok" style="flex-grow:' + ok + '"></span>' + (c.Medium ? '<span class="m-medium" style="flex-grow:' + c.Medium + '"></span>' : '') +
      (c.High ? '<span class="m-high" style="flex-grow:' + c.High + '"></span>' : '') + '</div>' +
      '<p class="meter-legend"><span><span class="dot d-ok"></span><b>' + num(ok) + '</b> passed, out of ' + num(total) + ' items checked</span>' +
      '<span><span class="dot d-medium"></span><b>' + c.Medium + '</b> to review</span><span><span class="dot d-high"></span><b>' + c.High + '</b> high risk</span></p>' +
      (last.htmlUrl ? '<div class="verify-actions"><button class="btn" type="button" data-open="0">Open the results</button></div>' : '');
    p.querySelector('[data-open]') && (p.querySelector('[data-open]').dataset.open = String(app.recent.indexOf(last)));
    renderHistory();
  }

  function renderHistory() {
    var list = $('hist');
    var items = app.recent.slice(0, 4);
    if (!items.length) {
      list.innerHTML = '<li class="hist-empty">Scans and checked files will show up here. The PC scan checks:' +
        '<ul><li>Windows defenses and Defender exclusions</li><li>programs that start by themselves, services and scheduled tasks</li>' +
        '<li>browser extensions and the code of Discord and wallets</li><li>hidden files in the folders where malware installs itself</li></ul></li>';
      return;
    }
    list.innerHTML = items.map(function (r, i) {
      var what = r.mode === 'File' ? 'Check of ' + nameOf(r.target) : 'PC scan';
      return '<li><button type="button" data-open="' + i + '"' + (r.htmlUrl ? '' : ' disabled') + '><span class="h-what">' + esc(what) + '</span>' +
        '<span class="h-when">' + esc(r.date) + (r.duration ? ' · ' + esc(r.duration) : '') + '</span>' + stateOf(r) + '</button></li>';
    }).join('');
  }

  // --- scan in progress -----------------------------------------------------
  function startView(mode, target) {
    app.scan = { mode: mode, target: target, checks: [], byId: {}, findings: [], counts: { High: 0, Medium: 0, Low: 0, Info: 0 }, started: Date.now(), cancelling: false };
    $('scan-title').textContent = mode === 'File' ? 'Check of ' + nameOf(target) : 'Scan in progress';
    $('scan-sub').textContent = 'Starting the scan engine...';
    $('progress-h').textContent = 'Starting the scan';
    $('uac').hidden = true;
    $('cancel').disabled = false; $('cancel').textContent = 'Cancel';
    $('areas').innerHTML = ''; $('found').innerHTML = '<p class="empty">No findings so far.</p>';
    $('found-count').textContent = '0';
    setProgress(0);
    renderCounts();
    show('scan');
    tick();
  }
  function tick() {
    if (!app.scan || $('view-scan').hidden) return;
    var s = Math.floor((Date.now() - app.scan.started) / 1000);
    $('elapsed').textContent = 'Elapsed: ' + (s >= 60 ? Math.floor(s / 60) + ' min ' : '') + (s % 60) + ' s';
    setTimeout(tick, 1000);
  }
  function setProgress(pct) {
    $('meter-fill').style.width = pct + '%';
    $('meter').setAttribute('aria-valuenow', String(Math.round(pct)));
  }
  function renderCounts() {
    var c = app.scan.counts;
    $('live-counts').innerHTML = '<span><span class="dot d-high"></span><b>' + c.High + '</b> high risk</span>' +
      '<span><span class="dot d-medium"></span><b>' + c.Medium + '</b> to review</span><span><b>' + c.Low + '</b> low risk</span>';
  }
  function areaRow(ch) {
    var mark = { pending: '<span class="pend"></span>', running: '<span class="spin"></span>', ok: ICON.check, error: ICON.risk }[ch.state];
    var state = ch.state === 'running' ? 'running' : ch.state === 'ok' ? (ch.findings ? plural(ch.findings, 'finding', 'findings') : 'checked') : ch.state === 'error' ? 'error' : '';
    return '<li class="area ' + ch.state + '" id="area-' + esc(ch.id) + '"><span class="a-mark">' + mark + '</span><span class="a-name">' + esc(ch.short) + '</span><span class="a-state">' + state + '</span></li>';
  }
  function shortLabel(label) { return String(label).replace(/\s*\(.*\)\s*$/, ''); }
  function addCheck(id, label) {
    var ch = { id: id, label: label, short: shortLabel(label), state: 'pending', findings: 0 };
    app.scan.checks.push(ch); app.scan.byId[id] = ch;
    return ch;
  }
  function renderAreas() { $('areas').innerHTML = app.scan.checks.map(areaRow).join(''); }
  function progressText() {
    var done = app.scan.checks.filter(function (c) { return c.state === 'ok' || c.state === 'error'; }).length;
    var total = app.scan.checks.length;
    setProgress(total ? 100 * done / total : 0);
    $('progress-h').textContent = total ? done + ' of ' + total + ' areas checked' : 'Starting the scan';
  }
  function addFinding(f) {
    var s = app.scan;
    var i = s.findings.findIndex(function (x) { return x.Id === f.Id; });
    if (i >= 0) { s.counts[s.findings[i].Severity]--; s.findings[i] = f; } else s.findings.unshift(f);
    s.counts[f.Severity] = (s.counts[f.Severity] || 0) + 1;
    var visible = s.findings.filter(function (x) { return x.Severity !== 'Info'; });
    $('found-count').textContent = String(visible.length);
    $('found').innerHTML = visible.length ? visible.slice(0, 12).map(function (x) {
      var why = (x.Reasons && x.Reasons[0]) || '';
      return '<div class="f-row"><span class="pill p-' + esc(x.Severity) + '">' + LABEL[x.Severity] + '</span><div><div class="f-title">' + esc(x.Title) + '</div><div class="f-sub">' + esc(x.Category + (why ? ' - ' + why : '')) + '</div></div></div>';
    }).join('') : '<p class="empty">No findings so far.</p>';
    renderCounts();
  }

  function onEngine(evt, summary) {
    var s = app.scan, data = evt.data || {};
    if (!s) return;
    switch (evt.type) {
      case 'scan.elevating':
        $('uac').hidden = false;
        $('scan-sub').textContent = 'Waiting for the Windows confirmation...';
        break;
      case 'scan.started':
        $('uac').hidden = true;
        s.checks = []; s.byId = {};
        (data.checks || []).forEach(function (c) { addCheck(c.id, c.label); });
        $('scan-sub').textContent = data.admin ? 'Full scan, with administrator rights' : (s.mode === 'File' ? 'The file is only read, never run' : 'Without administrator rights: some checks will be incomplete');
        renderAreas(); progressText();
        break;
      case 'check.started':
        var ch = s.byId[data.id] || addCheck(data.id, data.label);
        ch.state = 'running';
        if (!s.cancelling) $('scan-sub').textContent = 'Running: ' + ch.short;
        $('now-what').innerHTML = '<b>' + esc(ch.short) + '.</b> ' + esc(EXPLAIN[data.id] || '');
        renderAreas(); progressText();
        break;
      case 'check.completed':
        var c2 = s.byId[data.id];
        if (c2) { c2.state = data.status === 'error' ? 'error' : 'ok'; c2.findings = data.findings || 0; }
        renderAreas(); progressText();
        break;
      case 'finding':
      case 'finding.updated':
        if (data.finding) addFinding(data.finding);
        break;
      case 'scan.completed':
        setProgress(100);
        if (summary) { app.recent.unshift(summary); openReport(summary); }
        host.send({ type: 'refresh' });
        break;
      case 'scan.cancelled':
        endView('Scan cancelled', 'No report was produced. You can start a new scan whenever you want.');
        break;
      case 'scan.failed':
        var why = (data.message || 'unknown').replace(/\.\s*$/, '');
        endView('Scan interrupted', 'An error occurred: ' + why + '.');
        break;
    }
  }
  function endView(title, text) {
    app.scan = null;
    $('end-h').textContent = title; $('end-text').textContent = text;
    show('end');
  }

  // --- results --------------------------------------------------------------
  function openReport(r) {
    if (!r || !r.htmlUrl) return;
    app.lastReport = r;
    app.scan = null;
    $('results-title').textContent = r.mode === 'File' ? 'Check of ' + nameOf(r.target) : 'Scan of ' + r.date;
    // The theme travels in the address: the report and the app have different origins
    $('report').src = r.htmlUrl + '#theme=' + theme();
    show('results');
  }

  // --- history and comparison -------------------------------------------------
  function renderHistoryAll(items) {
    app.history = items || [];
    var list = $('hlist');
    if (!app.history.length) { list.innerHTML = '<li><span class="muted">No saved scans. Scans will show up here, scheduled ones included.</span></li>'; return; }
    list.innerHTML = app.history.map(function (r, i) {
      var what = r.mode === 'File' ? 'Check of ' + nameOf(r.target) : 'PC scan' + (r.admin ? '' : ' (without administrator)');
      var prev = -1;
      if (r.mode !== 'File') for (var j = i + 1; j < app.history.length; j++) if (app.history[j].mode !== 'File') { prev = j; break; }
      return '<li><span class="h-main"><span class="h-what">' + esc(what) + '</span><span class="h-when">' + esc(r.date) + (r.duration ? ' · ' + esc(r.duration) : '') + '</span></span>' +
        stateOf(r) + '<span class="h-btns">' +
        (prev >= 0 ? '<button class="btn" type="button" data-cmp="' + i + '" data-prev="' + prev + '">Compare with the previous one</button>' : '') +
        (r.htmlUrl ? '<button class="btn" type="button" data-hopen="' + i + '">Open</button>' : '') + '</span></li>';
    }).join('');
  }
  function invRow(x) {
    if (x.before != null) {
      return '<div class="c-row inv"><div><div class="c-title"><span class="c-tag">Changed</span>' + esc(x.key) + '</div><div class="c-sub">' + esc(x.category) + '</div>' +
        '<div class="c-sub">Before: ' + esc(x.before) + '</div><div class="c-sub">Now: ' + esc(x.value) + '</div></div></div>';
    }
    return '<div class="c-row inv"><div><div class="c-title">' + esc(x.key) + '</div><div class="c-sub">' + esc(x.category + (x.value ? ' - ' + x.value : '')) + '</div></div></div>';
  }
  function findRow(x) {
    return '<div class="c-row"><span class="pill p-' + esc(x.severity) + '">' + LABEL[x.severity] + '</span><div><div class="c-title">' + esc(x.title) + '</div><div class="c-sub">' + esc(x.category + (x.path ? ' - ' + x.path : '')) + '</div></div></div>';
  }
  function fill(id, arr, row, empty) {
    $(id + '-n').textContent = String(arr.length);
    $(id).innerHTML = arr.length ? arr.map(row).join('') : '<p class="empty">' + empty + '</p>';
  }
  function renderCompare(res) {
    var a = res.older || {}, b = res.newer || {};
    $('cmp-h').textContent = 'What changed from ' + (a.date || '?').split(' ')[0] + ' to ' + (b.date || '?').split(' ')[0];
    $('cmp-sub').textContent = 'Scan of ' + a.date + ' compared with the one of ' + b.date + '. Network connections, which change all the time, are left out.';
    var changed = res.changed || [], nNew = res.newFindings.length, nAdd = res.added.length;
    $('cmp-sum').innerHTML = '<span><b>' + nNew + '</b> new findings</span><span><b>' + res.resolved.length + '</b> gone</span>' +
      '<span><b>' + nAdd + '</b> items added</span><span><b>' + changed.length + '</b> changed</span><span><b>' + res.removed.length + '</b> removed</span>' +
      (a.admin !== b.admin ? '<span>One of the two scans ran without administrator rights: some differences may come from that.</span>' : '');
    fill('cmp-new', res.newFindings, findRow, 'No new findings.');
    fill('cmp-res', res.resolved, findRow, 'No findings gone.');
    fill('cmp-add', res.added.concat(changed), invRow, 'No new or changed items among autostart, services, tasks and browsers.');
    fill('cmp-rem', res.removed, invRow, 'No items removed.');
    show('compare');
  }

  // --- settings ---------------------------------------------------------------
  (function () {
    var h = $('sch-hour'), html = '';
    for (var i = 0; i < 24; i++) html += '<option value="' + i + '">' + (i < 10 ? '0' : '') + i + ':00</option>';
    h.innerHTML = html;
  })();
  function renderSettings(m) {
    $('vt-state').textContent = m.vtKey ? 'Key saved on this PC.' : 'No key: files are not looked up on VirusTotal.';
    $('vt-del').hidden = !m.vtKey;
    var s = m.schedule || {};
    $('sch-on').checked = !!s.enabled;
    $('sch-day').value = String(s.day != null ? s.day : 0);
    $('sch-hour').value = String(s.hour != null ? s.hour : 20);
    var bk = m.backups || [];
    $('backups').innerHTML = bk.length ? bk.map(function (b, i) {
      var when = String(b.date || '').replace('T', ' ').slice(0, 16);
      return '<li><span><span class="s-what">' + esc(b.title) + '</span><span class="s-when">' + esc(when) + ' · ' + esc(KIND[b.kind] || b.kind) + '</span></span>' +
        (b.undone ? '<span class="s-done">Undone</span>' : '<button class="btn" type="button" data-undo="' + i + '">Undo</button>') + '</li>';
    }).join('') : '<li class="s-empty">No changes. "Disable" shows up in the results, on the items that can be undone.</li>';
    app.backups = bk;
    var ig = m.ignored || [];
    $('ignored').innerHTML = ig.length ? ig.map(function (x) {
      return '<li><span><span class="s-what">' + esc(x.title) + '</span><span class="s-when">' + esc((x.category || '') + (x.date ? ' · since ' + x.date : '')) + '</span></span>' +
        '<button class="btn" type="button" data-unignore="' + esc(x.id) + '">Restore</button></li>';
    }).join('') : '<li class="s-empty">No ignored items.</li>';
  }
  var KIND = { RegistryValue: 'startup entry', File: 'file moved', ScheduledTask: 'task disabled', Service: 'service disabled' };
  $('vt-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var k = $('vt-key').value.trim();
    if (!k) return;
    host.send({ type: 'saveVtKey', key: k });
    $('vt-key').value = '';
  });
  $('vt-del').addEventListener('click', function () { host.send({ type: 'deleteVtKey' }); });
  function sendSchedule() { host.send({ type: 'setSchedule', enabled: $('sch-on').checked, day: +$('sch-day').value, hour: +$('sch-hour').value }); }
  $('sch-on').addEventListener('change', sendSchedule);
  $('sch-day').addEventListener('change', function () { if ($('sch-on').checked) sendSchedule(); });
  $('sch-hour').addEventListener('change', function () { if ($('sch-on').checked) sendSchedule(); });

  var toastTimer;
  function toast(text, ok) {
    var t = $('toast');
    t.textContent = text; t.className = 'toast' + (ok === false ? ' bad' : ''); t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, ok === false ? 8000 : 5000);
  }

  // The report (another origin, in the iframe) asks for actions with postMessage: accepted only from there
  var REPORT_ORIGIN = 'https://report.checkbackdoor.example';
  window.addEventListener('message', function (e) {
    if (e.origin !== REPORT_ORIGIN || !e.data || e.data.source !== 'checkbackdoor-report' || !app.lastReport) return;
    host.send({ type: 'findingAction', action: String(e.data.action), id: String(e.data.id), report: app.lastReport.jsonPath });
  });
  function toReport(m) {
    var f = $('report');
    if (f && f.contentWindow) f.contentWindow.postMessage({ source: 'checkbackdoor-app', id: m.id, action: m.action, text: m.text, done: !!m.done }, REPORT_ORIGIN);
  }

  // --- actions ----------------------------------------------------------------
  d.addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.nav) {
      var n = b.dataset.nav;
      if (app.scan && n !== 'home') return toast('Wait for the current scan to finish.', false);
      if (n === 'home') { show('home'); host.send({ type: 'refresh' }); }
      if (n === 'history') { show('history'); host.send({ type: 'history' }); }
      if (n === 'settings') { show('settings'); host.send({ type: 'settings' }); }
      return;
    }
    if (b.dataset.hopen != null) return openReport(app.history[+b.dataset.hopen]);
    if (b.dataset.cmp != null) return host.send({ type: 'compare', newer: app.history[+b.dataset.cmp].jsonPath, older: app.history[+b.dataset.prev].jsonPath });
    if (b.dataset.undo != null) { b.disabled = true; b.textContent = 'Undoing...'; return host.send({ type: 'undo', file: app.backups[+b.dataset.undo].file }); }
    if (b.dataset.unignore != null) return host.send({ type: 'unignore', id: b.dataset.unignore });
    if (b.dataset.open != null) return openReport(app.recent[+b.dataset.open]);
    var a = b.dataset.action;
    if (!a) return;
    if (a === 'home') { app.scan = null; show('home'); host.send({ type: 'refresh' }); return; }
    if (a === 'cancelScan') { if (app.scan) { app.scan.cancelling = true; } b.disabled = true; b.textContent = 'Cancelling...'; $('scan-sub').textContent = 'Cancelling: the current check finishes, then it stops.'; }
    if (a === 'showInFolder') { if (app.lastReport) host.send({ type: 'showInFolder', path: app.lastReport.htmlPath }); return; }
    host.send({ type: a });
  });
  $('theme').addEventListener('click', function () {
    var next = theme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('checkbackdoor-theme', next); } catch (e) {}
    if (!$('view-results').hidden && app.lastReport) $('report').src = app.lastReport.htmlUrl + '#theme=' + next;
  });

  // Drag and drop: without preventDefault WebView2 would open the dropped file
  var zone = $('dropzone');
  ['dragenter', 'dragover'].forEach(function (t) { d.addEventListener(t, function (e) { e.preventDefault(); if (zone.contains(e.target) || e.target === zone || $('drop').contains(e.target)) zone.classList.add('over'); }); });
  d.addEventListener('dragleave', function (e) { if (!$('drop').contains(e.relatedTarget)) zone.classList.remove('over'); });
  d.addEventListener('drop', function (e) {
    e.preventDefault(); zone.classList.remove('over');
    if (!$('drop').contains(e.target) || !e.dataTransfer || !e.dataTransfer.files.length) return;
    host.dropFile(e.dataTransfer.files);
  });

  // --- messages from the window ----------------------------------------------
  host.onMessage(function (m) {
    switch (m.type) {
      case 'state':
        app.recent = m.recent || []; app.isAdmin = !!m.isAdmin;
        $('scope').textContent = (m.computer || '') + (m.user ? ' · ' + m.user : '');
        $('engine-missing').hidden = m.engineFound !== false;
        if (!$('view-home').hidden) renderHome();
        break;
      case 'launched': startView(m.mode, m.target); break;
      case 'engine': onEngine(m.event || {}, m.summary); break;
      case 'aborted': endView('Scan interrupted', m.message || ''); break;
      case 'history': renderHistoryAll(m.items); break;
      case 'compare': renderCompare(m.result || {}); break;
      case 'settings': renderSettings(m); break;
      case 'notice': toast(m.text, m.ok); break;
      case 'actionResult': toReport(m); if (m.text && /^Not |no longer exists|cannot be/.test(m.text)) toast(m.text, false); break;
    }
  });
  renderHome();
  host.send({ type: 'ready' });

  // --- bridge with the app ------------------------------------------------------
  function realHost() {
    return {
      send: function (m) { webview.postMessage(m); },
      onMessage: function (fn) { webview.addEventListener('message', function (e) { fn(e.data); }); },
      // The path of the dropped file reaches the app only as an additional object
      dropFile: function (files) { webview.postMessageWithAdditionalObjects({ type: 'checkDropped' }, files); }
    };
  }

  // Demo engine to see the interface in a browser: ?demo=empty|scan
  function demoHost() {
    var listeners = [], q = window.CB_DEMO || new URLSearchParams(location.search).get('demo') || '';
    var emit = function (m) { setTimeout(function () { listeners.forEach(function (fn) { fn(m); }); }, 0); };
    var recent = q === 'empty' ? [] : [
      { mode: 'Scan', date: '2026-11-10 22:45', duration: '2 min 19 s', admin: true, examined: 6805, counts: { High: 1, Medium: 5, Low: 5, Info: 3 }, htmlUrl: 'about:blank' },
      { mode: 'File', target: 'C:\\Downloads\\game_setup.exe', date: '2026-11-10 21:12', duration: '2 s', examined: 1, counts: { High: 1, Medium: 0, Low: 0, Info: 0 }, htmlUrl: 'about:blank' },
      { mode: 'Scan', date: '2026-10-28 20:58', duration: '2 min 31 s', admin: false, examined: 6795, counts: { High: 0, Medium: 6, Low: 5, Info: 3 }, htmlUrl: 'about:blank' }
    ];
    var checks = [['Security', 'Windows defenses'], ['Persistence', 'Autostart locations'], ['ScheduledTasks', 'Scheduled tasks'], ['Services', 'Services, drivers and Safe Mode'], ['Wmi', 'Permanent WMI subscriptions'], ['Processes', 'Running processes'], ['Network', 'Network'], ['Browser', 'Browsers'], ['Injections', 'App injections'], ['Accounts', 'User accounts and remote access'], ['Certificates', 'Root certificates'], ['FileSystem', 'Suspicious files']];
    var demoFindings = { Persistence: { Id: 'a1', Severity: 'Medium', Category: 'Autostart', Title: 'Example Updater', Reasons: ['Not digitally signed'] },
      Browser: { Id: 'b1', Severity: 'High', Category: 'Browsers', Title: 'Microsoft Edge extension: Example Deals', Reasons: ['The browser flagged it as malicious'] },
      Network: { Id: 'c1', Severity: 'Medium', Category: 'Network', Title: 'Remote control software running: RemoteHelp.exe', Reasons: ['Legitimate remote support programs are often installed secretly'] } };
    function runDemo(stopAt) {
      emit({ type: 'launched', mode: 'Scan' });
      var ev = [{ type: 'scan.started', data: { admin: true, checks: checks.map(function (c) { return { id: c[0], label: c[1] }; }) } }];
      checks.forEach(function (c, i) {
        if (stopAt != null && i > stopAt) return;
        ev.push({ type: 'check.started', data: { id: c[0], label: c[1] } });
        if (stopAt != null && i === stopAt) return;
        if (demoFindings[c[0]]) ev.push({ type: 'finding', data: { finding: demoFindings[c[0]] } });
        ev.push({ type: 'check.completed', data: { id: c[0], status: 'ok', findings: demoFindings[c[0]] ? 1 : 0 } });
      });
      ev.forEach(function (e, i) { setTimeout(function () { emit({ type: 'engine', event: e }); }, 150 + i * 60); });
    }
    if (q === 'scan') setTimeout(function () { runDemo(7); }, 100);
    return {
      send: function (m) {
        if (m.type === 'ready' || m.type === 'refresh') emit({ type: 'state', computer: 'DEMO-PC', user: 'DEMO-PC\\user', isAdmin: false, engineFound: true, recent: recent });
        if (m.type === 'startScan') runDemo(7);
        if (m.type === 'cancelScan') setTimeout(function () { emit({ type: 'engine', event: { type: 'scan.cancelled', data: {} } }); }, 600);
        if (m.type === 'history') emit({ type: 'history', items: recent.map(function (r, i) { return Object.assign({ jsonPath: 'demo-' + i }, r); }) });
        if (m.type === 'compare') emit({ type: 'compare', result: { older: recent[2], newer: recent[0],
          newFindings: [{ severity: 'High', category: 'Browsers', title: 'Microsoft Edge extension: Example Deals' }, { severity: 'Medium', category: 'Autostart', title: 'Updater', path: 'C:\\Users\\user\\AppData\\Roaming\\upd\\upd.exe' }],
          resolved: [{ severity: 'Medium', category: 'Network', title: 'Remote control software running: RemoteControl.exe' }],
          added: [{ category: 'Autostart', key: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Updater', value: '"C:\\Users\\user\\AppData\\Roaming\\upd\\upd.exe" -s' }, { category: 'Scheduled tasks', key: 'Task: \\GameUpdate | GameUpdate', value: 'C:\\ProgramData\\gu\\gu.exe' }],
          changed: [{ category: 'Windows defenses', key: 'Antivirus | Example Antivirus', before: 'C:\\Program Files\\Example Antivirus\\8.1\\av.exe', value: 'C:\\Program Files\\Example Antivirus\\8.2\\av.exe' }],
          removed: [] } });
        if (m.type === 'settings') emit({ type: 'settings', vtKey: false, schedule: { enabled: false, day: 0, hour: 20 },
          ignored: [{ id: 'c1', title: 'Remote control software running: RemoteHelp.exe', category: 'Network', date: '2026-11-10 22:50' }],
          backups: [{ file: 'b1', title: 'Updater', date: '2026-11-10T22:51:00', kind: 'RegistryValue', undone: false }, { file: 'b2', title: 'update.vbs', date: '2026-11-09T19:02:00', kind: 'File', undone: true }] });
        if (m.type === 'saveVtKey' || m.type === 'setSchedule' || m.type === 'undo') emit({ type: 'notice', text: 'Demo: no real change.', ok: true });
      },
      onMessage: function (fn) { listeners.push(fn); },
      dropFile: function () {}
    };
  }
})();
