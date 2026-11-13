using System.ComponentModel;
using System.Diagnostics;
using System.Security;
using System.Text;
using System.Text.Json.Nodes;

namespace CheckBackdoor.App;

/// <summary>
/// Runs Actions.ps1 ("Disable" with a backup, "Undo"). When the change touches parts of the
/// system (HKLM, tasks, services) it starts it as administrator: Windows shows its prompt,
/// and the result comes back in a JSON file.
/// </summary>
public static class ActionRunner
{
    public static Task<JsonObject> DisableAsync(JsonObject request, bool admin)
    {
        Directory.CreateDirectory(AppPaths.RunsDir);
        var req = Path.Combine(AppPaths.RunsDir, $"action-{Guid.NewGuid():N}.json");
        var bytes = new UTF8Encoding(false).GetBytes(request.ToJsonString());
        File.WriteAllBytes(req, bytes);
        // The hash travels on the command line, which cannot change after the Windows
        // confirmation: if another program replaces the request file, the script refuses
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        return RunAsync(["-RequestFile", req, "-RequestSha256", sha, "-BackupDir", AppPaths.BackupDir], admin, req);
    }

    public static Task<JsonObject> UndoAsync(string backupFile) =>
        RunAsync(["-BackupFile", backupFile], BackupStore.NeedsAdmin(backupFile), null);

    static async Task<JsonObject> RunAsync(string[] args, bool admin, string? cleanup)
    {
        var result = Path.Combine(AppPaths.RunsDir, $"result-{Guid.NewGuid():N}.json");
        var all = new List<string> { "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", AppPaths.ActionsScript };
        all.AddRange(args);
        all.Add("-ResultFile"); all.Add(result);
        try
        {
            if (!File.Exists(AppPaths.ActionsScript)) return Fail("Actions.ps1 is missing next to the program: your antivirus probably quarantined it.");
            ProcessStartInfo psi;
            if (admin)
            {
                // "runas" goes through ShellExecute: no ArgumentList, the arguments are quoted by hand
                psi = new ProcessStartInfo(AppPaths.PowerShellExe, string.Join(' ', all.Select(Quote)))
                { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            }
            else
            {
                psi = new ProcessStartInfo(AppPaths.PowerShellExe) { UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in all) psi.ArgumentList.Add(a);
            }
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell did not start.");
            await p.WaitForExitAsync();
            if (!File.Exists(result)) return Fail("The action produced no result.");
            return JsonNode.Parse(File.ReadAllText(result)) as JsonObject ?? Fail("Unreadable result.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return Fail("You cancelled the Windows prompt: nothing was changed.");
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
        finally
        {
            TryDelete(result);
            if (cleanup is not null) TryDelete(cleanup);
        }
    }

    static JsonObject Fail(string message) => new() { ["ok"] = false, ["message"] = message };

    static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch (IOException) { } }

    // CommandLineToArgvW quoting rules: quotes around, \ before quotes
    static string Quote(string a)
    {
        if (a.Length > 0 && !a.Any(c => c == ' ' || c == '"' || c == '\t')) return a;
        var sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (var c in a)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { sb.Append('\\', slashes * 2 + 1); sb.Append('"'); slashes = 0; continue; }
            sb.Append('\\', slashes); slashes = 0; sb.Append(c);
        }
        sb.Append('\\', slashes * 2).Append('"');
        return sb.ToString();
    }
}

/// <summary>
/// Scheduled scan: a Task Scheduler task of the user (without administrator rights)
/// that runs the engine silently once a week.
/// The engine recognizes this task as its own and does not flag it.
/// </summary>
public static class Scheduler
{
    public const string TaskName = @"\CheckBackdoor\Weekly scan";
    static readonly string[] Days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

    public static bool Exists() => Run(["/Query", "/TN", TaskName]) == 0;

    public static void Delete() => Run(["/Delete", "/TN", TaskName, "/F"]);

    /// <summary>day: 0 = Sunday ... 6 = Saturday; hour: 0-23.</summary>
    public static bool Create(int day, int hour)
    {
        day = Math.Clamp(day, 0, 6); hour = Math.Clamp(hour, 0, 23);
        var ps = AppPaths.PowerShellExe;
        var args = string.Join(' ',
            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File", Q(AppPaths.EngineScript),
            "-NoElevate -Quiet -NoOpen -CompareLast -OutputDir", Q(AppPaths.ReportsDir),
            "-AllowlistFile", Q(AppPaths.IgnoredFile), "-VirusTotalKeyFile", Q(AppPaths.VirusTotalKeyFile));
        // A past date on the chosen day: the weekly trigger starts from there
        var start = new DateTime(2026, 1, 4, hour, 0, 0).AddDays(day);   // 2026-01-04 was a Sunday
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>CheckBackdoor weekly scan, read-only. Managed from the app settings.</Description></RegistrationInfo>
              <Triggers><CalendarTrigger><StartBoundary>{start:yyyy-MM-ddTHH:mm:ss}</StartBoundary><ScheduleByWeek><DaysOfWeek><{Days[day]} /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger></Triggers>
              <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
              <Settings><StartWhenAvailable>true</StartWhenAvailable><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Priority>7</Priority></Settings>
              <Actions Context="Author"><Exec><Command>{SecurityElement.Escape(ps)}</Command><Arguments>{SecurityElement.Escape(args)}</Arguments><WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(AppPaths.EngineScript))}</WorkingDirectory></Exec></Actions>
            </Task>
            """;
        Directory.CreateDirectory(AppPaths.RunsDir);
        var file = Path.Combine(AppPaths.RunsDir, $"task-{Guid.NewGuid():N}.xml");
        File.WriteAllText(file, xml, Encoding.Unicode);
        try { return Run(["/Create", "/TN", TaskName, "/XML", file, "/F"]) == 0; }
        finally { File.Delete(file); }
    }

    static string Q(string s) => "\"" + s + "\"";

    static int Run(string[] args)
    {
        var psi = new ProcessStartInfo("schtasks.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
        p.WaitForExit();
        return p.ExitCode;
    }
}
