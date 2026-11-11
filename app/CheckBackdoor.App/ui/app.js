// CheckBackdoor - interfaccia. Parla con la finestra (MainWindow.xaml.cs) tramite
// messaggi { type, ... } e mostra gli eventi del motore (docs/EVENTI.md).
// Fuori dall'app (in un browser) usa un motore dimostrativo con dati finti.
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
  var LABEL = { Alto: 'Alto', Medio: 'Da verificare', Basso: 'Basso', Info: 'Info' };
  // Una frase per area: mentre aspetta, chi usa l'app capisce cosa si sta cercando
  var EXPLAIN = {
    Security: 'Se Defender è attivo, se qualcuno ha aggiunto esclusioni (il trucco più comune dei crack) e se Windows Update o il firewall sono stati spenti.',
    Persistence: 'Le chiavi di registro e le cartelle da cui i programmi partono da soli a ogni accensione: è lì che una backdoor si assicura di sopravvivere al riavvio.',
    ScheduledTasks: "Le attività pianificate, comprese quelle nascoste apposta: miner e RAT le usano per ripartire anche dopo che il gioco è stato disinstallato.",
    Services: 'I servizi e i driver: girano con i privilegi massimi o nel cuore di Windows, quindi sono la forma di persistenza più pericolosa.',
    Wmi: 'Le sottoscrizioni WMI: un modo di avviarsi "senza file" che non compare tra i programmi in esecuzione automatica.',
    Processes: 'I programmi in esecuzione adesso: nomi che imitano quelli di Windows, comandi offuscati e consumo di CPU tipico dei miner.',
    Network: 'Porte aperte, connessioni verso internet, file hosts, proxy e programmi di controllo remoto.',
    Browser: 'Le estensioni dei browser: quelle segnalate come malware, caricate di nascosto o imposte da un criterio. Non legge cronologia, cookie o password.',
    Injections: 'Il codice di Discord e dei wallet di criptovalute: alcuni stealer lo modificano per rubare il token o la frase di recupero.',
    Accounts: 'Account amministratore sconosciuti o nascosti e accesso remoto al PC.',
    Certificates: 'Certificati radice aggiunti, che permetterebbero di leggere il traffico protetto (HTTPS).',
    FileSystem: 'I file in AppData, Temp e ProgramData, dove i malware si installano senza chiedere permessi. È il passo più lungo.',
    Timeline: 'I registri di Windows degli ultimi 30 giorni: servizi installati e poi spariti, Defender spento o con esclusioni, minacce trovate, account creati, script PowerShell sospetti e programmi avviati da Download e Temp.',
    File: 'Firma digitale, provenienza, struttura dell\'eseguibile e trucchi per sfuggire agli antivirus. Il file viene solo letto.',
    VirusTotal: 'Le impronte dei file segnalati vengono confrontate con VirusTotal: viene inviata solo l\'impronta, mai il file.',
    Compare: 'Il confronto con la verifica precedente, per vedere cosa è cambiato.'
  };

  var app = { recent: [], isAdmin: false, scan: null, lastReport: null };

  // --- utilita' ---------------------------------------------------------
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return '&#' + c.charCodeAt(0) + ';'; }); }
  // Il motore scrive in ASCII ("Attivita'", "e'"): qui tornano le lettere accentate
  var ACC = { a: 'à', e: 'è', i: 'ì', o: 'ò', u: 'ù', E: 'È' };
  function prose(s) { return String(s == null ? '' : s).replace(/([A-Za-z])([aeiouE])'(?=$|[\s,.;:!?)])/g, function (m, p, v) { return p + ACC[v]; }).replace(/(^|\s)E'(?=\s)/g, '$1È').replace(/(^|[\s(])e'(?=$|[\s,.;:!?)])/g, '$1è'); }
  function plural(n, one, many) { return n === 1 ? '1 ' + one : n.toLocaleString('it-IT') + ' ' + many; }
  function show(view) {
    ['home', 'scan', 'end', 'results', 'history', 'compare', 'settings'].forEach(function (v) { $('view-' + v).hidden = v !== view; });
    var section = { history: 'history', compare: 'history', settings: 'settings' }[view] || 'home';
    [].slice.call(d.querySelectorAll('.nav-b')).forEach(function (b) {
      if (b.getAttribute('data-nav') === section) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    // La vista attiva va subito dopo la barra: il suo titolo e' il primo della pagina
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
      if (c.Alto) return 'Non aprire il file controllato';
      if (c.Medio) return 'File da verificare prima di aprirlo';
      return 'Nessun indizio nel file controllato';
    }
    if (c.Alto) return (c.Alto === 1 ? 'Un indizio' : c.Alto + ' indizi') + ' ad alto rischio da controllare';
    if (c.Medio) return 'Nessun indizio grave, ' + plural(c.Medio, 'elemento', 'elementi') + ' da verificare';
    return 'Nessun indizio di backdoor';
  }
  function stateOf(r) {
    var c = r.counts || {};
    if (c.Alto) return '<span class="h-state s-alto">' + ICON.risk + c.Alto + ' a rischio</span>';
    if (c.Medio) return '<span class="h-state s-medio">' + ICON.review + c.Medio + ' da verificare</span>';
    return '<span class="h-state">' + ICON.check + 'Nessun indizio</span>';
  }
  function nameOf(path) { return String(path || '').split(/[\\/]/).pop(); }

  function renderHome() {
    var scans = app.recent.filter(function (r) { return r.mode !== 'File'; });
    var last = scans[0];
    $('home-sub').textContent = last ? 'Ultima verifica del PC il ' + last.date + (last.admin ? '' : ' (senza privilegi di amministratore)') : 'Nessuna verifica ancora';
    var p = $('last');
    if (!last) {
      p.className = 'verify first-run';
      p.innerHTML = '<h2 id="last-h" class="verdict">Non hai ancora verificato questo PC</h2>' +
        '<p class="verdict-text">La verifica legge i punti in cui una backdoor si nasconde, senza modificare nulla, e dura due o tre minuti. Windows chiederà i privilegi di amministratore: servono per leggere le esclusioni di Defender e i processi di sistema.</p>' +
        '<div class="verify-actions"><button class="btn btn-primary" type="button" data-action="startScan">Avvia la verifica</button></div>';
      return renderHistory();
    }
    var c = last.counts, total = last.examined || 0, flagged = c.Alto + c.Medio, ok = Math.max(total - flagged, 0);
    p.className = 'verify';
    p.innerHTML = '<div class="verify-top"><h2 id="last-h" class="verdict">' + esc(verdictOf(last)) + '</h2>' +
      '<span class="done">' + ICON.check + 'Verifica del ' + esc(last.date) + '</span></div>' +
      '<div class="meter" role="img" aria-label="' + total + ' elementi verificati, ' + c.Alto + ' a rischio alto, ' + c.Medio + ' da verificare">' +
      '<span class="m-ok" style="flex-grow:' + ok + '"></span>' + (c.Medio ? '<span class="m-medio" style="flex-grow:' + c.Medio + '"></span>' : '') +
      (c.Alto ? '<span class="m-alto" style="flex-grow:' + c.Alto + '"></span>' : '') + '</div>' +
      '<p class="meter-legend"><span><span class="dot d-ok"></span><b>' + ok.toLocaleString('it-IT') + '</b> superati, su ' + total.toLocaleString('it-IT') + ' elementi verificati</span>' +
      '<span><span class="dot d-medio"></span><b>' + c.Medio + '</b> da verificare</span><span><span class="dot d-alto"></span><b>' + c.Alto + '</b> a rischio alto</span></p>' +
      (last.htmlUrl ? '<div class="verify-actions"><button class="btn" type="button" data-open="0">Apri i risultati</button></div>' : '');
    p.querySelector('[data-open]') && (p.querySelector('[data-open]').dataset.open = String(app.recent.indexOf(last)));
    renderHistory();
  }

  function renderHistory() {
    var list = $('hist');
    var items = app.recent.slice(0, 4);
    if (!items.length) {
      list.innerHTML = '<li class="hist-empty">Le verifiche e i file controllati compariranno qui. La verifica del PC controlla:' +
        '<ul><li>le difese di Windows e le esclusioni di Defender</li><li>i programmi che partono da soli, i servizi e le attività pianificate</li>' +
        '<li>le estensioni dei browser e il codice di Discord e dei wallet</li><li>i file nascosti nelle cartelle dove i malware si installano</li></ul></li>';
      return;
    }
    list.innerHTML = items.map(function (r, i) {
      var what = r.mode === 'File' ? 'Controllo di ' + nameOf(r.target) : 'Verifica del PC';
      return '<li><button type="button" data-open="' + i + '"' + (r.htmlUrl ? '' : ' disabled') + '><span class="h-what">' + esc(what) + '</span>' +
        '<span class="h-when">' + esc(r.date) + (r.duration ? ' · ' + esc(r.duration) : '') + '</span>' + stateOf(r) + '</button></li>';
    }).join('');
  }

  // --- verifica in corso ---------------------------------------------------
  function startView(mode, target) {
    app.scan = { mode: mode, target: target, checks: [], byId: {}, findings: [], counts: { Alto: 0, Medio: 0, Basso: 0, Info: 0 }, started: Date.now(), cancelling: false };
    $('scan-title').textContent = mode === 'File' ? 'Controllo di ' + nameOf(target) : 'Verifica in corso';
    $('scan-sub').textContent = 'Avvio del motore di scansione...';
    $('progress-h').textContent = 'Avvio della verifica';
    $('uac').hidden = true;
    $('cancel').disabled = false; $('cancel').textContent = 'Annulla';
    $('areas').innerHTML = ''; $('found').innerHTML = '<p class="empty">Nessuna segnalazione finora.</p>';
    $('found-count').textContent = '0';
    setProgress(0);
    renderCounts();
    show('scan');
    tick();
  }
  function tick() {
    if (!app.scan || $('view-scan').hidden) return;
    var s = Math.floor((Date.now() - app.scan.started) / 1000);
    $('elapsed').textContent = 'Tempo trascorso: ' + (s >= 60 ? Math.floor(s / 60) + ' min ' : '') + (s % 60) + ' s';
    setTimeout(tick, 1000);
  }
  function setProgress(pct) {
    $('meter-fill').style.width = pct + '%';
    $('meter').setAttribute('aria-valuenow', String(Math.round(pct)));
  }
  function renderCounts() {
    var c = app.scan.counts;
    $('live-counts').innerHTML = '<span><span class="dot d-alto"></span><b>' + c.Alto + '</b> a rischio alto</span>' +
      '<span><span class="dot d-medio"></span><b>' + c.Medio + '</b> da verificare</span><span><b>' + c.Basso + '</b> a rischio basso</span>';
  }
  function areaRow(ch) {
    var mark = { pending: '<span class="pend"></span>', running: '<span class="spin"></span>', ok: ICON.check, error: ICON.risk }[ch.state];
    var state = ch.state === 'running' ? 'in corso' : ch.state === 'ok' ? (ch.findings ? plural(ch.findings, 'segnalazione', 'segnalazioni') : 'verificata') : ch.state === 'error' ? 'errore' : '';
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
    $('progress-h').textContent = total ? done + ' di ' + total + ' aree verificate' : 'Avvio della verifica';
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
      return '<div class="f-row"><span class="pill p-' + x.Severity + '">' + LABEL[x.Severity] + '</span><div><div class="f-title">' + esc(prose(x.Title)) + '</div><div class="f-sub">' + esc(prose(x.Category + (why ? ' - ' + why : ''))) + '</div></div></div>';
    }).join('') : '<p class="empty">Nessuna segnalazione finora.</p>';
    renderCounts();
  }

  function onEngine(evt, summary) {
    var s = app.scan, data = evt.data || {};
    if (!s) return;
    switch (evt.type) {
      case 'scan.elevating':
        $('uac').hidden = false;
        $('scan-sub').textContent = 'In attesa della conferma di Windows...';
        break;
      case 'scan.started':
        $('uac').hidden = true;
        s.checks = []; s.byId = {};
        (data.checks || []).forEach(function (c) { addCheck(c.id, c.label); });
        $('scan-sub').textContent = data.admin ? 'Verifica completa, con privilegi di amministratore' : (s.mode === 'File' ? 'Il file viene solo letto, mai eseguito' : 'Senza privilegi di amministratore: alcuni controlli saranno incompleti');
        renderAreas(); progressText();
        break;
      case 'check.started':
        var ch = s.byId[data.id] || addCheck(data.id, data.label);
        ch.state = 'running';
        if (!s.cancelling) $('scan-sub').textContent = 'In corso: ' + ch.short;
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
        endView('Verifica annullata', 'Non è stato prodotto nessun report. Puoi avviarne una nuova quando vuoi.');
        break;
      case 'scan.failed':
        var why = (data.message || 'sconosciuto').replace(/\.\s*$/, '');
        endView('Verifica interrotta', 'Si è verificato un errore: ' + why + '.');
        break;
    }
  }
  function endView(title, text) {
    app.scan = null;
    $('end-h').textContent = title; $('end-text').textContent = text;
    show('end');
  }

  // --- risultati -----------------------------------------------------------
  function openReport(r) {
    if (!r || !r.htmlUrl) return;
    app.lastReport = r;
    app.scan = null;
    $('results-title').textContent = r.mode === 'File' ? 'Controllo di ' + nameOf(r.target) : 'Verifica del ' + r.date;
    // Il tema passa nell'indirizzo: il report e l'app hanno origini diverse
    $('report').src = r.htmlUrl + '#theme=' + theme();
    show('results');
  }

  // --- storico e confronto ---------------------------------------------------
  function renderHistoryAll(items) {
    app.history = items || [];
    var list = $('hlist');
    if (!app.history.length) { list.innerHTML = '<li><span class="muted">Nessuna verifica salvata. Le verifiche compariranno qui, anche quelle programmate.</span></li>'; return; }
    list.innerHTML = app.history.map(function (r, i) {
      var what = r.mode === 'File' ? 'Controllo di ' + nameOf(r.target) : 'Verifica del PC' + (r.admin ? '' : ' (senza amministratore)');
      var prev = -1;
      if (r.mode !== 'File') for (var j = i + 1; j < app.history.length; j++) if (app.history[j].mode !== 'File') { prev = j; break; }
      return '<li><span class="h-main"><span class="h-what">' + esc(what) + '</span><span class="h-when">' + esc(r.date) + (r.duration ? ' · ' + esc(r.duration) : '') + '</span></span>' +
        stateOf(r) + '<span class="h-btns">' +
        (prev >= 0 ? '<button class="btn" type="button" data-cmp="' + i + '" data-prev="' + prev + '">Confronta con la precedente</button>' : '') +
        (r.htmlUrl ? '<button class="btn" type="button" data-hopen="' + i + '">Apri</button>' : '') + '</span></li>';
    }).join('');
  }
  function invRow(x) {
    if (x.before != null) {
      return '<div class="c-row inv"><div><div class="c-title"><span class="c-tag">Modificato</span>' + esc(x.key) + '</div><div class="c-sub">' + esc(prose(x.category)) + '</div>' +
        '<div class="c-sub">Prima: ' + esc(x.before) + '</div><div class="c-sub">Ora: ' + esc(x.value) + '</div></div></div>';
    }
    return '<div class="c-row inv"><div><div class="c-title">' + esc(x.key) + '</div><div class="c-sub">' + esc(prose(x.category) + (x.value ? ' - ' + x.value : '')) + '</div></div></div>';
  }
  function findRow(x) {
    return '<div class="c-row"><span class="pill p-' + esc(x.severity) + '">' + LABEL[x.severity] + '</span><div><div class="c-title">' + esc(prose(x.title)) + '</div><div class="c-sub">' + esc(prose(x.category) + (x.path ? ' - ' + x.path : '')) + '</div></div></div>';
  }
  function fill(id, arr, row, empty) {
    $(id + '-n').textContent = String(arr.length);
    $(id).innerHTML = arr.length ? arr.map(row).join('') : '<p class="empty">' + empty + '</p>';
  }
  function renderCompare(res) {
    var a = res.older || {}, b = res.newer || {};
    $('cmp-h').textContent = 'Cosa è cambiato dal ' + (a.date || '?').split(' ')[0] + ' al ' + (b.date || '?').split(' ')[0];
    $('cmp-sub').textContent = 'Verifica del ' + a.date + ' confrontata con quella del ' + b.date + '. Le connessioni di rete, che cambiano di continuo, restano fuori.';
    var changed = res.changed || [], nNew = res.newFindings.length, nAdd = res.added.length;
    $('cmp-sum').innerHTML = '<span><b>' + nNew + '</b> segnalazioni nuove</span><span><b>' + res.resolved.length + '</b> sparite</span>' +
      '<span><b>' + nAdd + '</b> elementi comparsi</span><span><b>' + changed.length + '</b> modificati</span><span><b>' + res.removed.length + '</b> rimossi</span>' +
      (a.admin !== b.admin ? '<span>Una delle due verifiche è senza amministratore: alcune differenze possono dipendere da questo.</span>' : '');
    fill('cmp-new', res.newFindings, findRow, 'Nessuna segnalazione nuova.');
    fill('cmp-res', res.resolved, findRow, 'Nessuna segnalazione sparita.');
    fill('cmp-add', res.added.concat(changed), invRow, 'Nessun elemento nuovo o modificato tra avvio automatico, servizi, attività e browser.');
    fill('cmp-rem', res.removed, invRow, 'Nessun elemento rimosso.');
    show('compare');
  }

  // --- impostazioni ------------------------------------------------------------
  (function () {
    var h = $('sch-hour'), html = '';
    for (var i = 0; i < 24; i++) html += '<option value="' + i + '">' + (i < 10 ? '0' : '') + i + ':00</option>';
    h.innerHTML = html;
  })();
  function renderSettings(m) {
    $('vt-state').textContent = m.vtKey ? 'Chiave salvata su questo PC.' : 'Nessuna chiave: i file non vengono controllati su VirusTotal.';
    $('vt-del').hidden = !m.vtKey;
    var s = m.schedule || {};
    $('sch-on').checked = !!s.enabled;
    $('sch-day').value = String(s.day != null ? s.day : 0);
    $('sch-hour').value = String(s.hour != null ? s.hour : 20);
    var bk = m.backups || [];
    $('backups').innerHTML = bk.length ? bk.map(function (b, i) {
      var when = String(b.date || '').replace('T', ' ').slice(0, 16);
      return '<li><span><span class="s-what">' + esc(b.title) + '</span><span class="s-when">' + esc(when) + ' · ' + esc(KIND[b.kind] || b.kind) + '</span></span>' +
        (b.undone ? '<span class="s-done">Annullata</span>' : '<button class="btn" type="button" data-undo="' + i + '">Annulla</button>') + '</li>';
    }).join('') : '<li class="s-empty">Nessuna modifica. "Disattiva" compare nei risultati, sugli elementi che si possono annullare.</li>';
    app.backups = bk;
    var ig = m.ignored || [];
    $('ignored').innerHTML = ig.length ? ig.map(function (x) {
      return '<li><span><span class="s-what">' + esc(prose(x.title)) + '</span><span class="s-when">' + esc(prose(x.category || '') + (x.date ? ' · dal ' + x.date : '')) + '</span></span>' +
        '<button class="btn" type="button" data-unignore="' + esc(x.id) + '">Ripristina</button></li>';
    }).join('') : '<li class="s-empty">Nessun elemento ignorato.</li>';
  }
  var KIND = { RegistryValue: 'voce di avvio', File: 'file spostato', ScheduledTask: 'attività disattivata', Service: 'servizio disattivato' };
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

  // Il report (altra origine, nell'iframe) chiede le azioni con postMessage: si accettano solo da li'
  var REPORT_ORIGIN = 'https://report.checkbackdoor.example';
  window.addEventListener('message', function (e) {
    if (e.origin !== REPORT_ORIGIN || !e.data || e.data.source !== 'checkbackdoor-report' || !app.lastReport) return;
    host.send({ type: 'findingAction', action: String(e.data.action), id: String(e.data.id), report: app.lastReport.jsonPath });
  });
  function toReport(m) {
    var f = $('report');
    if (f && f.contentWindow) f.contentWindow.postMessage({ source: 'checkbackdoor-app', id: m.id, action: m.action, text: m.text, done: !!m.done }, REPORT_ORIGIN);
  }

  // --- azioni ---------------------------------------------------------------
  d.addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.nav) {
      var n = b.dataset.nav;
      if (app.scan && n !== 'home') return toast('Attendi la fine della verifica in corso.', false);
      if (n === 'home') { show('home'); host.send({ type: 'refresh' }); }
      if (n === 'history') { show('history'); host.send({ type: 'history' }); }
      if (n === 'settings') { show('settings'); host.send({ type: 'settings' }); }
      return;
    }
    if (b.dataset.hopen != null) return openReport(app.history[+b.dataset.hopen]);
    if (b.dataset.cmp != null) return host.send({ type: 'compare', newer: app.history[+b.dataset.cmp].jsonPath, older: app.history[+b.dataset.prev].jsonPath });
    if (b.dataset.undo != null) { b.disabled = true; b.textContent = 'Annullamento...'; return host.send({ type: 'undo', file: app.backups[+b.dataset.undo].file }); }
    if (b.dataset.unignore != null) return host.send({ type: 'unignore', id: b.dataset.unignore });
    if (b.dataset.open != null) return openReport(app.recent[+b.dataset.open]);
    var a = b.dataset.action;
    if (!a) return;
    if (a === 'home') { app.scan = null; show('home'); host.send({ type: 'refresh' }); return; }
    if (a === 'cancelScan') { if (app.scan) { app.scan.cancelling = true; } b.disabled = true; b.textContent = 'Annullamento...'; $('scan-sub').textContent = 'Annullamento: termina il controllo in corso, poi si ferma.'; }
    if (a === 'showInFolder') { if (app.lastReport) host.send({ type: 'showInFolder', path: app.lastReport.htmlPath }); return; }
    host.send({ type: a });
  });
  $('theme').addEventListener('click', function () {
    var next = theme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('checkbackdoor-theme', next); } catch (e) {}
    if (!$('view-results').hidden && app.lastReport) $('report').src = app.lastReport.htmlUrl + '#theme=' + next;
  });

  // Trascinamento: senza preventDefault WebView2 aprirebbe il file trascinato
  var zone = $('dropzone');
  ['dragenter', 'dragover'].forEach(function (t) { d.addEventListener(t, function (e) { e.preventDefault(); if (zone.contains(e.target) || e.target === zone || $('drop').contains(e.target)) zone.classList.add('over'); }); });
  d.addEventListener('dragleave', function (e) { if (!$('drop').contains(e.relatedTarget)) zone.classList.remove('over'); });
  d.addEventListener('drop', function (e) {
    e.preventDefault(); zone.classList.remove('over');
    if (!$('drop').contains(e.target) || !e.dataTransfer || !e.dataTransfer.files.length) return;
    host.dropFile(e.dataTransfer.files);
  });

  // --- messaggi dalla finestra -------------------------------------------------
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
      case 'aborted': endView('Verifica interrotta', m.message || ''); break;
      case 'history': renderHistoryAll(m.items); break;
      case 'compare': renderCompare(m.result || {}); break;
      case 'settings': renderSettings(m); break;
      case 'notice': toast(prose(m.text), m.ok); break;
      case 'actionResult': m.text = prose(m.text); toReport(m); if (m.text && /^Non |non esiste/.test(m.text)) toast(m.text, false); break;
    }
  });
  renderHome();
  host.send({ type: 'ready' });

  // --- ponte con l'app --------------------------------------------------------
  function realHost() {
    return {
      send: function (m) { webview.postMessage(m); },
      onMessage: function (fn) { webview.addEventListener('message', function (e) { fn(e.data); }); },
      // Il percorso del file trascinato arriva all'app solo come oggetto aggiuntivo
      dropFile: function (files) { webview.postMessageWithAdditionalObjects({ type: 'checkDropped' }, files); }
    };
  }

  // Motore dimostrativo per vedere l'interfaccia in un browser: ?demo=vuoto|scan
  function demoHost() {
    var listeners = [], q = window.CB_DEMO || new URLSearchParams(location.search).get('demo') || '';
    var emit = function (m) { setTimeout(function () { listeners.forEach(function (fn) { fn(m); }); }, 0); };
    var recent = q === 'vuoto' ? [] : [
      { mode: 'Scan', date: '10/11/2026 22:45', duration: '2 min 19 s', admin: true, examined: 6805, counts: { Alto: 1, Medio: 5, Basso: 5, Info: 3 }, htmlUrl: 'about:blank' },
      { mode: 'File', target: 'C:\\Download\\setup_gioco.exe', date: '10/11/2026 21:12', duration: '2 s', examined: 1, counts: { Alto: 1, Medio: 0, Basso: 0, Info: 0 }, htmlUrl: 'about:blank' },
      { mode: 'Scan', date: '28/10/2026 20:58', duration: '2 min 31 s', admin: false, examined: 6795, counts: { Alto: 0, Medio: 6, Basso: 5, Info: 3 }, htmlUrl: 'about:blank' }
    ];
    var checks = [['Security', 'Difese di Windows'], ['Persistence', 'Punti di avvio automatico'], ['ScheduledTasks', 'Attività pianificate'], ['Services', 'Servizi, driver e Modalità provvisoria'], ['Wmi', 'Sottoscrizioni WMI permanenti'], ['Processes', 'Processi in esecuzione'], ['Network', 'Rete'], ['Browser', 'Browser'], ['Injections', 'Iniezioni nelle app'], ['Accounts', 'Account utente e accesso remoto'], ['Certificates', 'Certificati radice'], ['FileSystem', 'File sospetti']];
    var demoFindings = { Persistence: { Id: 'a1', Severity: 'Medio', Category: 'Avvio automatico', Title: 'Aggiornatore Esempio', Reasons: ['Non firmato digitalmente'] },
      Browser: { Id: 'b1', Severity: 'Alto', Category: 'Browser', Title: 'Estensione di Microsoft Edge: Sconti Esempio', Reasons: ["Il browser l'ha segnalata come dannosa"] },
      Network: { Id: 'c1', Severity: 'Medio', Category: 'Rete', Title: 'Software di controllo remoto in esecuzione: AssistenzaRemota.exe', Reasons: ['Programmi legittimi di assistenza remota vengono spesso installati di nascosto'] } };
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
        if (m.type === 'ready' || m.type === 'refresh') emit({ type: 'state', computer: 'PC-DEMO', user: 'PC-DEMO\\utente', isAdmin: false, engineFound: true, recent: recent });
        if (m.type === 'startScan') runDemo(7);
        if (m.type === 'cancelScan') setTimeout(function () { emit({ type: 'engine', event: { type: 'scan.cancelled', data: {} } }); }, 600);
        if (m.type === 'history') emit({ type: 'history', items: recent.map(function (r, i) { return Object.assign({ jsonPath: 'demo-' + i }, r); }) });
        if (m.type === 'compare') emit({ type: 'compare', result: { older: recent[2], newer: recent[0],
          newFindings: [{ severity: 'Alto', category: 'Browser', title: 'Estensione di Microsoft Edge: Sconti Esempio' }, { severity: 'Medio', category: 'Avvio automatico', title: 'Updater', path: 'C:\\Users\\utente\\AppData\\Roaming\\upd\\upd.exe' }],
          resolved: [{ severity: 'Medio', category: 'Rete', title: 'Software di controllo remoto in esecuzione: ControlloRemoto.exe' }],
          added: [{ category: 'Avvio automatico', key: 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Updater', value: '"C:\\Users\\utente\\AppData\\Roaming\\upd\\upd.exe" -s' }, { category: "Attivita' pianificate", key: "Attivita': \\GameUpdate | GameUpdate", value: 'C:\\ProgramData\\gu\\gu.exe' }],
          changed: [{ category: 'Difese di Windows', key: 'Antivirus | Antivirus Esempio', before: 'C:\\Program Files\\Antivirus Esempio\\8.1\\av.exe', value: 'C:\\Program Files\\Antivirus Esempio\\8.2\\av.exe' }],
          removed: [] } });
        if (m.type === 'settings') emit({ type: 'settings', vtKey: false, schedule: { enabled: false, day: 0, hour: 20 },
          ignored: [{ id: 'c1', title: 'Software di controllo remoto in esecuzione: AssistenzaRemota.exe', category: 'Rete', date: '10/11/2026 22:50' }],
          backups: [{ file: 'b1', title: 'Updater', date: '2026-11-10T22:51:00', kind: 'RegistryValue', undone: false }, { file: 'b2', title: 'aggiorna.vbs', date: '2026-11-09T19:02:00', kind: 'File', undone: true }] });
        if (m.type === 'saveVtKey' || m.type === 'setSchedule' || m.type === 'undo') emit({ type: 'notice', text: 'Demo: nessuna modifica reale.', ok: true });
      },
      onMessage: function (fn) { listeners.push(fn); },
      dropFile: function () {}
    };
  }
})();
