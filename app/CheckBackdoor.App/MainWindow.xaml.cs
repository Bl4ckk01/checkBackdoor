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
    }

    // Actions come from the report shown in the app: the id and the report path are checked,
    // and what to do is read from the report file, not from the message.
    async Task FindingActionAsync(string? action, string? id, string? report)
    {
        if (action is null || id is null || report is null || !AppPaths.IsInside(report, AppPaths.ReportsDir) || !File.Exists(report)) return;
        var f = ReportStore.FindFinding(report, id);
        if (f is null) return;
        var title = (string?)f["Title"] ?? "item";
        void Reply(string text, bool done) => Post(new JsonObject { ["type"] = "actionResult", ["id"] = id, ["action"] = action, ["text"] = text, ["done"] = done });

        switch (action)
        {
            case "reveal":
                var p = (string?)f["Path"];
                if (p is not null && File.Exists(p)) Process.Start("explorer.exe", $"/select,\"{p}\"");
                else Reply("The file no longer exists.", false);
                break;
            case "ignore":
                IgnoreStore.Add(id, title, (string?)f["Category"], (string?)f["Sha256"]);
                Reply("It will be ignored in future scans. You can restore it from the settings.", true);
                break;
            case "disable":
                if (f["Remedy"] is not JsonObject remedy) { Reply("This item cannot be disabled from here.", false); break; }
                var what = (string?)remedy["Kind"] switch
                {
                    "RegistryValue" => "The entry will be removed from the startup keys (its content stays in the backup).",
                    "File" => "The file will be moved to the CheckBackdoor backup folder, not deleted.",
                    "ScheduledTask" => "The scheduled task will be disabled, not deleted.",
                    "Service" => "The service will be set to Disabled and stopped.",
                    _ => "",
                };
                var admin = remedy["Admin"]?.GetValue<bool>() != false;
                // Title and target come from the same report file: what will really be touched is
                // shown too, so a misleading title is not enough to get something else disabled
                var target = (string?)remedy["Kind"] switch
                {
                    "RegistryValue" => $"{(string?)remedy["Key"]}\nvalue: {(string?)remedy["Name"]}",
                    "File" => (string?)remedy["Path"],
                    "ScheduledTask" => $"task {(string?)remedy["Path"]}{(string?)remedy["Name"]}",
                    "Service" => $"service {(string?)remedy["Name"]}",
                    _ => null,
                };
                if (target is not null) what += $"\n\nItem that will be changed:\n{target}\n";
                var answer = MessageBox.Show(this, $"Disable \"{title}\"?\n\n{what}\nYou can undo it any time from the settings." +
                    (admin ? "\n\nWindows will ask for administrator rights." : ""), "CheckBackdoor", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer != MessageBoxResult.Yes) break;
                Reply("Disabling...", false);
                var request = new JsonObject { ["FindingId"] = id, ["Title"] = title, ["Remedy"] = remedy.DeepClone() };
                var r = await ActionRunner.DisableAsync(request, admin);
                var ok = r["ok"]?.GetValue<bool>() == true;
                Reply(ok ? "Disabled. You can undo it from the settings." : "Not disabled: " + (string?)r["message"], ok);
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
