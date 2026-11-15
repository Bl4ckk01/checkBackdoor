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
/// Window that hosts the interface (HTML in ui\) and connects it to the engine. The interface
/// sends { type, ... } messages; the window replies and forwards the scan events.
/// </summary>
public partial class MainWindow : Window
{
    const string AppHost = "app.checkbackdoor.example";
    // The only external sites the reports link to: they open in the default browser
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
        // Happens if CheckBackdoor.exe is copied alone, without the folders next to it:
        // better to explain it than to close with a WebView2 error.
        if (!Directory.Exists(AppPaths.UiDir))
        {
            MessageBox.Show(this, $"The interface folder is missing:\n{AppPaths.UiDir}\n\nCheckBackdoor.exe must stay together with the ui and engine folders it was built with. Start the program from its folder instead of copying it alone.",
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
            MessageBox.Show(this, "The interface needs Microsoft Edge WebView2, included in Windows 11. Install it from microsoft.com/edge/webview2 and open CheckBackdoor again.",
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
        // Reports open in the iframe of the app page, which has another origin: with "Deny"
        // WebView2 would block that too. "DenyCors" allows it, but stops any page from
        // reading their content with fetch/XHR.
        core.SetVirtualHostNameToFolderMapping(ReportStore.ReportHost, AppPaths.ReportsDir, CoreWebView2HostResourceAccessKind.DenyCors);

        core.NavigationStarting += (_, e) => GuardNavigation(e.Uri, () => e.Cancel = true);
        core.FrameNavigationStarting += (_, e) => GuardNavigation(e.Uri, () => e.Cancel = true);
        core.NewWindowRequested += (_, e) => { e.Handled = true; OpenExternal(e.Uri); };
        core.WebMessageReceived += OnWebMessage;

        Web.Source = new Uri($"https://{AppHost}/index.html");
    }

    // The interface can load only its own pages and the reports; everything else is blocked
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
                SendQuarantine();
                break;
            case "startScan":
                StartScan(null);
                break;
            case "pickFile":
                var fileDialog = new OpenFileDialog { Title = "Choose the file to check", CheckFileExists = true };
                if (fileDialog.ShowDialog(this) == true) StartScan(fileDialog.FileName);
                break;
            case "pickFolder":
                var folderDialog = new OpenFolderDialog { Title = "Choose the folder to check" };
                if (folderDialog.ShowDialog(this) == true) StartScan(folderDialog.FolderName);
                break;
            case "checkDropped":
                // The dropped file arrives as an additional object: the only way to know its path
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
                if (!Secrets.IsValidVirusTotalKey(key)) { Post(Notice("The VirusTotal key is 64 characters from 0-9 and a-f: make sure you copied all of it.", false)); break; }
                Secrets.SaveVirusTotalKey(key!.ToLowerInvariant());
                Post(Notice("Key saved, encrypted for your Windows user. From the next scan the flagged files are looked up on VirusTotal.", true));
                SendSettings();
                break;
            case "deleteVtKey":
                Secrets.DeleteVirusTotalKey();
                Post(Notice("VirusTotal key removed from this PC.", true));
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
            case "quarantine":
                SendQuarantine();
                break;
            case "purge":
                _ = PurgeAsync((string?)msg?["file"]);
                break;
            case "findingAction":
                _ = FindingActionThenRefreshAsync((string?)msg?["action"], (string?)msg?["id"], (string?)msg?["report"]);
                break;
        }
    }

    static JsonObject Notice(string text, bool ok) => new() { ["type"] = "notice", ["text"] = text, ["ok"] = ok };

    void SendCompare(string? older, string? newer)
    {
        if (older is null || newer is null || !AppPaths.IsInside(older, AppPaths.ReportsDir) || !AppPaths.IsInside(newer, AppPaths.ReportsDir)
            || !File.Exists(older) || !File.Exists(newer)) return;
        try { Post(new JsonObject { ["type"] = "compare", ["result"] = ReportStore.Compare(older, newer) }); }
        catch (Exception ex) { Post(Notice("Comparison failed: " + ex.Message, false)); }
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
        Post(Notice(!ok ? "Could not create the scheduled task."
            : enabled ? "Scheduled scan on: the results will show up in the history." : "Scheduled scan turned off.", ok));
        SendSettings();
    }

    async Task UndoAsync(string? file)
    {
        if (file is null || !BackupStore.IsBackupFile(file) || !File.Exists(file)) return;
        var r = await ActionRunner.UndoAsync(file);
        Post(Notice((string?)r["message"] ?? "", r["ok"]?.GetValue<bool>() == true));
        SendSettings();
        SendQuarantine();
    }

    // The quarantine page: the list, and the number next to "Backup" in the bar (the button
    // shows up only when something is in quarantine)
    void SendQuarantine() => Post(new JsonObject { ["type"] = "quarantine", ["items"] = BackupStore.Quarantine() });

    async Task PurgeAsync(string? file)
    {
        if (file is null || !BackupStore.IsBackupFile(file) || !File.Exists(file)) return;
        var item = BackupStore.Quarantine().OfType<JsonObject>().FirstOrDefault(x => string.Equals((string?)x["file"], file, StringComparison.OrdinalIgnoreCase));
        if (item is null) { SendQuarantine(); return; }
        var what = item["folder"]?.GetValue<bool>() == true ? "folder" : "file";
        var text = $"Delete \"{(string?)item["title"]}\" for good?\n\nThe {what} in quarantine will be deleted and cannot be recovered: Restore will no longer be possible.\n\n" +
            $"It was in:\n{(string?)item["path"]}" + (BackupStore.NeedsAdmin(file) ? "\n\nWindows will ask for administrator rights." : "");
        if (MessageBox.Show(this, text, "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) { SendQuarantine(); return; }
        var r = await ActionRunner.PurgeAsync(file);
        var ok = r["ok"]?.GetValue<bool>() == true;
        Post(Notice(ok ? "Deleted for good." : "Not deleted: " + (string?)r["message"], ok));
        SendQuarantine();
        SendSettings();
    }

    // Items already fixed from each report in this session: "Fix all" does not ask for them again
    readonly Dictionary<string, HashSet<string>> _fixed = new(StringComparer.OrdinalIgnoreCase);
    HashSet<string> FixedIn(string report)
    {
        if (!_fixed.TryGetValue(report, out var set)) _fixed[report] = set = new(StringComparer.OrdinalIgnoreCase);
        return set;
    }

    // After an action something may have gone into quarantine: the "Backup" button follows
    async Task FindingActionThenRefreshAsync(string? action, string? id, string? report)
    {
        await FindingActionAsync(action, id, report);
        if (action is "disable" or "delete" or "fixAll") SendQuarantine();
    }

    // Actions come from the report shown in the app: the id and the report path are checked,
    // and what to do is read from the report file, not from the message.
    async Task FindingActionAsync(string? action, string? id, string? report)
    {
        if (action is null || id is null || report is null || !AppPaths.IsInside(report, AppPaths.ReportsDir) || !File.Exists(report)) return;
        if (action == "fixAll") { await FixAllAsync(report); return; }
        var f = ReportStore.FindFinding(report, id);
        if (f is null) return;
        var title = (string?)f["Title"] ?? "item";
        void Reply(string text, bool done) => Post(new JsonObject { ["type"] = "actionResult", ["id"] = id, ["action"] = action, ["text"] = text, ["done"] = done });

        switch (action)
        {
            case "reveal":
                // Some findings point to a folder (a browser extension, for example): File Explorer selects it too
                var p = (string?)f["Path"];
                if (p is not null && (File.Exists(p) || Directory.Exists(p))) Process.Start("explorer.exe", $"/select,\"{p.TrimEnd('\\')}\"");
                else Reply("It no longer exists: it was moved or deleted after the scan.", false);
                break;
            case "ignore":
                IgnoreStore.Add(id, title, (string?)f["Category"], (string?)f["Sha256"]);
                Reply("It will be ignored in future scans. You can restore it from the settings.", true);
                break;
            case "disable":
            {
                if (f["Remedy"] is not JsonObject remedy) { Reply("This item cannot be changed from here.", false); break; }
                var d = Describe(remedy);
                var admin = remedy["Admin"]?.GetValue<bool>() != false;
                // Title and target come from the same report file: what will really be touched is
                // shown too, so a misleading title is not enough to get something else changed
                var text = $"{d.Verb} \"{title}\"?\n\n{d.What}\n\nItem that will be changed:\n{d.Target}\n\n" +
                    (d.Undoable ? "You can undo it any time from the settings." : "This cannot be undone.") +
                    (admin ? "\n\nWindows will ask for administrator rights." : "");
                if (MessageBox.Show(this, text, "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) break;
                Reply("Working...", false);
                var request = new JsonObject { ["FindingId"] = id, ["Title"] = title, ["Remedy"] = remedy.DeepClone() };
                var r = await ActionRunner.DisableAsync(request, admin);
                var ok = r["ok"]?.GetValue<bool>() == true;
                if (ok) FixedIn(report).Add(id);
                Reply(ok ? (string?)r["message"] ?? "Done." : "Not done: " + (string?)r["message"], ok);
                break;
            }
            case "delete":
            {
                if (f["Remedy"] is not JsonObject remedy || !IsDeletable(remedy)) { Reply("Only files and browser extensions can be deleted from here.", false); break; }
                var admin = remedy["Admin"]?.GetValue<bool>() != false;
                var ext = (string?)remedy["Kind"] == "BrowserExtension";
                var text = $"Delete \"{title}\" for good?\n\n" +
                    (ext ? $"The extension folder will be deleted and cannot be recovered, not even with Undo. Close {(string?)remedy["Browser"]} first.\n\n"
                         : "The file will be deleted and cannot be recovered, not even with Undo.\n\n") +
                    "CheckBackdoor can be wrong: an item flagged as suspicious may be legitimate (a false positive). " +
                    $"If you are not sure, choose \"{(ext ? "Remove extension" : "Quarantine")}\" instead: it moves it away and can be undone.\n\n" +
                    $"What will be deleted:\n{(string?)remedy["Path"]}" + (admin ? "\n\nWindows will ask for administrator rights." : "");
                if (MessageBox.Show(this, text, "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) break;
                Reply("Deleting...", false);
                var request = new JsonObject { ["FindingId"] = id, ["Title"] = title, ["Remedy"] = remedy.DeepClone(), ["Mode"] = "Delete" };
                var r = await ActionRunner.DisableAsync(request, admin);
                var ok = r["ok"]?.GetValue<bool>() == true;
                if (ok) FixedIn(report).Add(id);
                Reply(ok ? (string?)r["message"] ?? "Deleted." : "Not deleted: " + (string?)r["message"], ok);
                break;
            }
        }
    }

    // "Fix all": the high and medium-risk items with an action, all at once. Files are deleted,
    // everything else disabled. One confirmation, with a clear warning, and one Windows prompt.
    async Task FixAllAsync(string report)
    {
        void Reply(string id, string action, string text, bool done) =>
            Post(new JsonObject { ["type"] = "actionResult", ["id"] = id, ["action"] = action, ["text"] = text, ["done"] = done });
        var ignored = IgnoreStore.Items().Select(x => (string?)x?["id"]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var done = FixedIn(report);
        var items = ReportStore.FixableFindings(report).Where(f => (string?)f["Id"] is string i && !ignored.Contains(i) && !done.Contains(i)).ToList();
        if (items.Count == 0) { Reply("all", "fixAll", "Nothing left to fix.", false); return; }

        static bool IsFile(JsonObject f) => f["Remedy"] is JsonObject r && IsDeletable(r);
        var files = items.Count(IsFile);
        var lines = items.Take(12).Select(f => $"- {(IsFile(f) ? "delete" : Describe((JsonObject)f["Remedy"]!).Verb.ToLowerInvariant())}: {(string?)f["Title"]}");
        var more = items.Count > 12 ? $"\n...and {items.Count - 12} more." : "";
        var browsers = items.Select(f => (string?)f["Remedy"]?["Browser"]).Where(b => b is not null).Distinct().ToList();
        var text = $"Fix all {items.Count} items?\n\n" +
            (files > 0 ? $"- {files} suspicious {(files == 1 ? "file or extension" : "files and extensions")} will be DELETED for good (no Undo);\n" : "") +
            (browsers.Count > 0 ? $"- close {string.Join(", ", browsers)} first, or their extensions will not be removed;\n" : "") +
            "- everything else will be disabled, removed or ended (most of it can be undone from the settings).\n\n" +
            "WARNING: this is not safe. CheckBackdoor can be wrong: some of these items may be legitimate programs " +
            "(false positives), and deleting or disabling them can break programs or parts of Windows. Read the list first, " +
            "and if you are not sure, fix the items one by one.\n\n" +
            string.Join("\n", lines) + more + "\n\nWindows will ask for administrator rights.";
        if (MessageBox.Show(this, text, "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;

        Reply("all", "fixAll", "Fixing...", false);
        var requests = new JsonArray();
        foreach (var f in items)
        {
            var req = new JsonObject { ["FindingId"] = (string?)f["Id"], ["Title"] = (string?)f["Title"], ["Remedy"] = f["Remedy"]!.DeepClone() };
            if (IsFile(f)) req["Mode"] = "Delete";
            requests.Add(req);
        }
        var r = await ActionRunner.DisableAsync(requests, true);
        var ok = r["ok"]?.GetValue<bool>() == true;
        if (r["items"] is JsonArray results)
            foreach (var it in results.OfType<JsonObject>())
            {
                var itemId = (string?)it["findingId"] ?? "";
                var itemOk = it["ok"]?.GetValue<bool>() == true;
                if (itemOk) done.Add(itemId);
                var file = items.FirstOrDefault(x => string.Equals((string?)x["Id"], itemId, StringComparison.OrdinalIgnoreCase)) is { } src && IsFile(src);
                Reply(itemId, file ? "delete" : "disable", itemOk ? (string?)it["message"] ?? "Done." : "Not done: " + (string?)it["message"], itemOk);
            }
        Reply("all", "fixAll", (string?)r["message"] ?? "", ok);
        Post(Notice(ok ? $"{(string?)r["message"]} Check the results of each item in the list." : "Nothing was fixed: " + (string?)r["message"], ok));
        SendSettings();
    }

    // Kinds that "Delete" and "Fix all" delete for good
    static bool IsDeletable(JsonObject remedy) => (string?)remedy["Kind"] is "File" or "QuarantineFile" or "BrowserExtension";

    // What an action does, for the confirmation: the verb of its button, what happens, and
    // the item that will really be touched
    static (string Verb, string What, string Target, bool Undoable) Describe(JsonObject remedy)
    {
        string S(string key) => (string?)remedy[key] ?? "";
        return S("Kind") switch
        {
            "RegistryValue" => ("Disable", "The entry will be removed from the startup keys (its content stays in the backup).", $"{S("Key")}\nvalue: {S("Name")}", true),
            "File" => ("Disable", "The file will be moved to the CheckBackdoor backup folder, not deleted.", S("Path"), true),
            "ScheduledTask" => ("Disable", "The scheduled task will be disabled, not deleted.", $"task {S("Path")}{S("Name")}", true),
            "Service" => ("Disable", "The service will be set to Disabled and stopped.", $"service {S("Name")}", true),
            "BrowserExtension" => ("Remove extension", $"The extension folder will be moved to the CheckBackdoor backup folder: {S("Browser")} will no longer load it. Close {S("Browser")} first.", S("Path"), true),
            "QuarantineFile" => ("Quarantine", "The file will be moved to the CheckBackdoor backup folder (quarantine), not deleted.", S("Path"), true),
            "Process" => ("End process", "The process will be ended. Nothing is deleted: if it starts again with Windows, also disable what starts it.", $"process {(int?)remedy["ProcessId"]}: {S("Path")}", false),
            "DefenderExclusion" => ("Remove exclusion", "The exclusion will be removed from Microsoft Defender, which will scan that item again.", $"{S("Type")} exclusion: {S("Value")}", true),
            "Account" => ("Disable account", "The account will be disabled, not deleted: nobody will be able to sign in with it.", $"account {S("Name")} ({S("Sid")})", true),
            "RootCertificate" => ("Remove certificate", "The root certificate will be removed (a copy stays in the backup).",
                S("Store") == "Machine" ? $"computer root certificates, thumbprint {S("Thumbprint")}" : $"root certificates of user {S("Sid")}, thumbprint {S("Thumbprint")}", true),
            _ => ("Disable", "", "", true),
        };
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
            // Ignored items and VirusTotal key (encrypted): the engine reads them from the files
            var extra = new List<string> { "-AllowlistFile", AppPaths.IgnoredFile, "-VirusTotalKeyFile", AppPaths.VirusTotalKeyFile };
            if (file is not null) extra.AddRange(["-File", file]);
            _runner.Start(AppPaths.EngineScript, AppPaths.ReportsDir, AppPaths.RunsDir, extra);
            Post(new JsonObject { ["type"] = "launched", ["mode"] = file is null ? "Scan" : "File", ["target"] = file });
        }
        catch (Exception ex)
        {
            Post(new JsonObject { ["type"] = "aborted", ["message"] = "The scan did not start: " + ex.Message });
        }
    }

    void ForwardEvent(string line)
    {
        JsonNode? evt;
        try { evt = JsonNode.Parse(line); } catch (JsonException) { return; }
        var msg = new JsonObject { ["type"] = "engine", ["event"] = evt };
        // At the end of the scan the interface also gets the summary and the report address
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
