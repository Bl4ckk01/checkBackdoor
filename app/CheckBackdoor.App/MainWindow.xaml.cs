using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;

namespace CheckBackdoor.App;

/// <summary>
/// Finestra che ospita l'interfaccia (HTML in ui\) e la collega al motore. L'interfaccia
/// manda messaggi { type, ... }; la finestra risponde e inoltra gli eventi della scansione.
/// </summary>
public partial class MainWindow : Window
{
    const string AppHost = "app.checkbackdoor.example";
    // Unici siti esterni che i report linkano: si aprono nel browser predefinito
    static readonly HashSet<string> ExternalHosts = new(StringComparer.OrdinalIgnoreCase)
        { "www.virustotal.com", "virustotal.com", "attack.mitre.org" };

    ScanRunner? _runner;

    public MainWindow()
    {
        InitializeComponent();
        var dark = IsSystemDark();
        Background = new SolidColorBrush(dark ? Color.FromRgb(0x0c, 0x0d, 0x0e) : Color.FromRgb(0xf2, 0xf4, 0xf7));
        SourceInitialized += (_, _) => UseDarkTitleBar(dark);
        Loaded += async (_, _) => await InitializeWebAsync();
        Closing += (_, _) => _runner?.Dispose();
    }

    async Task InitializeWebAsync()
    {
        // Succede se CheckBackdoor.exe viene copiato da solo, senza le cartelle accanto:
        // meglio spiegarlo che chiudersi con un errore di WebView2.
        if (!Directory.Exists(AppPaths.UiDir))
        {
            MessageBox.Show(this, $"Manca la cartella dell'interfaccia:\n{AppPaths.UiDir}\n\nCheckBackdoor.exe deve restare insieme alle cartelle ui ed engine con cui è stato compilato. Avvia il programma dalla sua cartella invece di copiarlo da solo.",
                "CheckBackdoor", MessageBoxButton.OK, MessageBoxImage.Warning);
            Close();
            return;
        }
        try
        {
            AppPaths.EnsureDataDirs();
            var env = await CoreWebView2Environment.CreateAsync(null, AppPaths.WebViewDataDir);
            await Web.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            MessageBox.Show(this, "Per l'interfaccia serve Microsoft Edge WebView2, incluso in Windows 11. Installalo da microsoft.com/edge/webview2 e riapri CheckBackdoor.",
                "CheckBackdoor", MessageBoxButton.OK, MessageBoxImage.Warning);
            Close();
            return;
        }

        var core = Web.CoreWebView2;
        var s = core.Settings;
        s.AreDevToolsEnabled = Debugger.IsAttached || Environment.GetEnvironmentVariable("CHECKBACKDOOR_DEVTOOLS") == "1";
        s.AreDefaultContextMenusEnabled = s.AreDevToolsEnabled;
        s.IsStatusBarEnabled = false;
        s.AreHostObjectsAllowed = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = s.AreDevToolsEnabled;

        core.SetVirtualHostNameToFolderMapping(AppHost, AppPaths.UiDir, CoreWebView2HostResourceAccessKind.Deny);
        // I report si aprono nell'iframe della pagina dell'app, che ha un'altra origine: con
        // "Deny" WebView2 bloccherebbe anche quello. "DenyCors" lo permette, ma impedisce a
        // qualsiasi pagina di leggerne il contenuto con fetch/XHR.
        core.SetVirtualHostNameToFolderMapping(ReportStore.ReportHost, AppPaths.ReportsDir, CoreWebView2HostResourceAccessKind.DenyCors);

        core.NavigationStarting += (_, e) => GuardNavigation(e.Uri, () => e.Cancel = true);
        core.FrameNavigationStarting += (_, e) => GuardNavigation(e.Uri, () => e.Cancel = true);
        core.NewWindowRequested += (_, e) => { e.Handled = true; OpenExternal(e.Uri); };
        core.WebMessageReceived += OnWebMessage;

        Web.Source = new Uri($"https://{AppHost}/index.html");
    }

    // L'interfaccia puo' caricare solo le sue pagine e i report; tutto il resto e' bloccato
    static void GuardNavigation(string uri, Action cancel)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u)) { cancel(); return; }
        if (u.Scheme == "about") return;
        if (u.Scheme == Uri.UriSchemeHttps && (u.Host == AppHost || u.Host == ReportStore.ReportHost)) return;
        cancel();
        OpenExternal(uri);
    }

    static void OpenExternal(string uri)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps && ExternalHosts.Contains(u.Host))
            Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true });
    }

    void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        JsonNode? msg;
        try { msg = JsonNode.Parse(e.WebMessageAsJson); } catch (JsonException) { return; }
        switch ((string?)msg?["type"])
        {
            case "ready":
            case "refresh":
                SendState();
                break;
            case "startScan":
                StartScan(null);
                break;
            case "pickFile":
                var fileDialog = new OpenFileDialog { Title = "Scegli il file da controllare", CheckFileExists = true };
                if (fileDialog.ShowDialog(this) == true) StartScan(fileDialog.FileName);
                break;
            case "pickFolder":
                var folderDialog = new OpenFolderDialog { Title = "Scegli la cartella da controllare" };
                if (folderDialog.ShowDialog(this) == true) StartScan(folderDialog.FolderName);
                break;
            case "checkDropped":
                // Il file trascinato arriva come oggetto aggiuntivo: e' l'unico modo per conoscerne il percorso
                if (e.AdditionalObjects?.Count > 0 && e.AdditionalObjects[0] is CoreWebView2File dropped) StartScan(dropped.Path);
                break;
            case "cancelScan":
                _runner?.RequestCancel();
                break;
            case "openReports":
                Process.Start("explorer.exe", $"\"{AppPaths.ReportsDir}\"");
                break;
            case "showInFolder":
                var path = (string?)msg?["path"];
                if (path is not null && File.Exists(path) && AppPaths.IsInside(path, AppPaths.ReportsDir))
                    Process.Start("explorer.exe", $"/select,\"{path}\"");
                break;
            case "history":
                Post(new JsonObject { ["type"] = "history", ["items"] = ReportStore.Recent(AppPaths.ReportsDir, 60) });
                break;
            case "compare":
                SendCompare((string?)msg?["older"], (string?)msg?["newer"]);
                break;
            case "settings":
                SendSettings();
                break;
            case "saveVtKey":
                var key = ((string?)msg?["key"])?.Trim();
                if (!Secrets.IsValidVirusTotalKey(key)) { Post(Notice("La chiave di VirusTotal è fatta di 64 caratteri tra 0-9 e a-f: controlla di averla copiata tutta.", false)); break; }
                Secrets.SaveVirusTotalKey(key!.ToLowerInvariant());
                Post(Notice("Chiave salvata, cifrata per il tuo utente Windows. Dalla prossima verifica i file segnalati vengono controllati su VirusTotal.", true));
                SendSettings();
                break;
            case "deleteVtKey":
                Secrets.DeleteVirusTotalKey();
                Post(Notice("Chiave di VirusTotal rimossa da questo PC.", true));
                SendSettings();
                break;
            case "setSchedule":
                SetSchedule(msg?["enabled"]?.GetValue<bool>() == true, (int?)msg?["day"] ?? 0, (int?)msg?["hour"] ?? 20);
                break;
            case "unignore":
                if ((string?)msg?["id"] is string unId) { IgnoreStore.Remove(unId); SendSettings(); }
                break;
            case "undo":
                _ = UndoAsync((string?)msg?["file"]);
                break;
            case "findingAction":
                _ = FindingActionAsync((string?)msg?["action"], (string?)msg?["id"], (string?)msg?["report"]);
                break;
        }
    }

    static JsonObject Notice(string text, bool ok) => new() { ["type"] = "notice", ["text"] = text, ["ok"] = ok };

    void SendCompare(string? older, string? newer)
    {
        if (older is null || newer is null || !AppPaths.IsInside(older, AppPaths.ReportsDir) || !AppPaths.IsInside(newer, AppPaths.ReportsDir)
            || !File.Exists(older) || !File.Exists(newer)) return;
        try { Post(new JsonObject { ["type"] = "compare", ["result"] = ReportStore.Compare(older, newer) }); }
        catch (Exception ex) { Post(Notice("Confronto non riuscito: " + ex.Message, false)); }
    }

    void SendSettings()
    {
        var settings = SettingsStore.Load();
        Post(new JsonObject
        {
            ["type"] = "settings",
            ["vtKey"] = Secrets.HasVirusTotalKey,
            ["schedule"] = new JsonObject
            {
                ["enabled"] = Scheduler.Exists(),
                ["day"] = (int?)settings["scheduleDay"] ?? 0,
                ["hour"] = (int?)settings["scheduleHour"] ?? 20,
            },
            ["ignored"] = IgnoreStore.Items().DeepClone(),
            ["backups"] = BackupStore.List(),
        });
    }

    void SetSchedule(bool enabled, int day, int hour)
    {
        var settings = SettingsStore.Load();
        settings["scheduleDay"] = day; settings["scheduleHour"] = hour;
        SettingsStore.Save(settings);
        bool ok = true;
        if (enabled) ok = Scheduler.Create(day, hour); else Scheduler.Delete();
        Post(Notice(!ok ? "Non sono riuscito a creare l'attività pianificata."
            : enabled ? "Verifica programmata: i risultati compariranno nello storico." : "Verifica programmata disattivata.", ok));
        SendSettings();
    }

    async Task UndoAsync(string? file)
    {
        if (file is null || !BackupStore.IsBackupFile(file) || !File.Exists(file)) return;
        var r = await ActionRunner.UndoAsync(file);
        Post(Notice((string?)r["message"] ?? "", r["ok"]?.GetValue<bool>() == true));
        SendSettings();
    }

    // Le azioni arrivano dal report mostrato nell'app: id e percorso del report si verificano,
    // e cosa fare si legge dal file del report, non dal messaggio.
    async Task FindingActionAsync(string? action, string? id, string? report)
    {
        if (action is null || id is null || report is null || !AppPaths.IsInside(report, AppPaths.ReportsDir) || !File.Exists(report)) return;
        var f = ReportStore.FindFinding(report, id);
        if (f is null) return;
        var title = (string?)f["Title"] ?? "elemento";
        void Reply(string text, bool done) => Post(new JsonObject { ["type"] = "actionResult", ["id"] = id, ["action"] = action, ["text"] = text, ["done"] = done });

        switch (action)
        {
            case "reveal":
                var p = (string?)f["Path"];
                if (p is not null && File.Exists(p)) Process.Start("explorer.exe", $"/select,\"{p}\"");
                else Reply("Il file non esiste più.", false);
                break;
            case "ignore":
                IgnoreStore.Add(id, title, (string?)f["Category"], (string?)f["Sha256"]);
                Reply("Sarà ignorato nelle prossime verifiche. Puoi ripristinarlo dalle impostazioni.", true);
                break;
            case "disable":
                if (f["Remedy"] is not JsonObject remedy) { Reply("Questo elemento non si può disattivare da qui.", false); break; }
                var what = (string?)remedy["Kind"] switch
                {
                    "RegistryValue" => "La voce verrà tolta dalle chiavi di avvio (il suo contenuto resta nel backup).",
                    "File" => "Il file verrà spostato nella cartella dei backup di CheckBackdoor, non cancellato.",
                    "ScheduledTask" => "L'attivita' pianificata verrà disattivata, non eliminata.",
                    "Service" => "Il servizio verrà impostato su Disabilitato e fermato.",
                    _ => "",
                };
                var admin = remedy["Admin"]?.GetValue<bool>() != false;
                // Titolo e bersaglio arrivano dallo stesso file del report: si mostra anche cio' che
                // verra' toccato davvero, cosi' un titolo ingannevole non basta a far disattivare altro
                var target = (string?)remedy["Kind"] switch
                {
                    "RegistryValue" => $"{(string?)remedy["Key"]}\nvoce: {(string?)remedy["Name"]}",
                    "File" => (string?)remedy["Path"],
                    "ScheduledTask" => $"attività {(string?)remedy["Path"]}{(string?)remedy["Name"]}",
                    "Service" => $"servizio {(string?)remedy["Name"]}",
                    _ => null,
                };
                if (target is not null) what += $"\n\nElemento che verrà modificato:\n{target}\n";
                var answer = MessageBox.Show(this, $"Disattivare \"{title}\"?\n\n{what}\nPotrai annullare in qualsiasi momento dalle impostazioni." +
                    (admin ? "\n\nWindows chiederà i privilegi di amministratore." : ""), "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer != MessageBoxResult.Yes) break;
                Reply("Disattivazione in corso...", false);
                var request = new JsonObject { ["FindingId"] = id, ["Title"] = title, ["Remedy"] = remedy.DeepClone() };
                var r = await ActionRunner.DisableAsync(request, admin);
                var ok = r["ok"]?.GetValue<bool>() == true;
                Reply(ok ? "Disattivato. Si annulla dalle impostazioni." : "Non disattivato: " + (string?)r["message"], ok);
                break;
        }
    }

    void SendState()
    {
        Post(new JsonObject
        {
            ["type"] = "state",
            ["version"] = typeof(MainWindow).Assembly.GetName().Version?.ToString(3),
            ["computer"] = Environment.MachineName,
            ["user"] = $"{Environment.UserDomainName}\\{Environment.UserName}",
            ["isAdmin"] = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
            ["engineFound"] = File.Exists(AppPaths.EngineScript),
            ["scanning"] = _runner?.IsRunning == true,
            ["recent"] = ReportStore.Recent(AppPaths.ReportsDir),
        });
    }

    void StartScan(string? file)
    {
        if (_runner?.IsRunning == true) return;
        _runner?.Dispose();
        _runner = new ScanRunner();
        _runner.EventReceived += line => Dispatcher.Invoke(() => ForwardEvent(line));
        _runner.Aborted += message => Dispatcher.Invoke(() => Post(new JsonObject { ["type"] = "aborted", ["message"] = message }));
        try
        {
            // Elementi ignorati e chiave di VirusTotal (cifrata): il motore li legge dai file
            var extra = new List<string> { "-AllowlistFile", AppPaths.IgnoredFile, "-VirusTotalKeyFile", AppPaths.VirusTotalKeyFile };
            if (file is not null) extra.AddRange(["-File", file]);
            _runner.Start(AppPaths.EngineScript, AppPaths.ReportsDir, AppPaths.RunsDir, extra);
            Post(new JsonObject { ["type"] = "launched", ["mode"] = file is null ? "Scan" : "File", ["target"] = file });
        }
        catch (Exception ex)
        {
            Post(new JsonObject { ["type"] = "aborted", ["message"] = "La verifica non è partita: " + ex.Message });
        }
    }

    void ForwardEvent(string line)
    {
        JsonNode? evt;
        try { evt = JsonNode.Parse(line); } catch (JsonException) { return; }
        var msg = new JsonObject { ["type"] = "engine", ["event"] = evt };
        // A fine verifica l'interfaccia riceve anche il riassunto e l'indirizzo del report
        if ((string?)evt?["type"] == "scan.completed" && (string?)evt?["data"]?["report"]?["json"] is string json)
            msg["summary"] = ReportStore.Summarize(json);
        Post(msg);
    }

    void Post(JsonNode message) => Web.CoreWebView2?.PostWebMessageAsJson(message.ToJsonString());

    static bool IsSystemDark()
    {
        var v = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1);
        return v is int i && i == 0;
    }

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    void UseDarkTitleBar(bool dark)
    {
        int on = dark ? 1 : 0;
        _ = DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref on, sizeof(int));
    }
}
