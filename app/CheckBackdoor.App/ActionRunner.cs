using System.ComponentModel;
using System.Diagnostics;
using System.Security;
using System.Text;
using System.Text.Json.Nodes;

namespace CheckBackdoor.App;

/// <summary>
/// Esegue Azioni.ps1 ("Disattiva" con backup, "Annulla"). Quando la modifica tocca parti del
/// sistema (HKLM, attivita', servizi) lo lancia come amministratore: Windows mostra la sua
/// richiesta, e l'esito torna in un file JSON.
/// </summary>
public static class ActionRunner
{
    public static Task<JsonObject> DisableAsync(JsonObject request, bool admin)
    {
        Directory.CreateDirectory(AppPaths.RunsDir);
        var req = Path.Combine(AppPaths.RunsDir, $"azione-{Guid.NewGuid():N}.json");
        File.WriteAllText(req, request.ToJsonString());
        return RunAsync(["-RequestFile", req, "-BackupDir", AppPaths.BackupDir], admin, req);
    }

    public static Task<JsonObject> UndoAsync(string backupFile) =>
        RunAsync(["-BackupFile", backupFile], BackupStore.NeedsAdmin(backupFile), null);

    static async Task<JsonObject> RunAsync(string[] args, bool admin, string? cleanup)
    {
        var result = Path.Combine(AppPaths.RunsDir, $"esito-{Guid.NewGuid():N}.json");
        var all = new List<string> { "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", AppPaths.ActionsScript };
        all.AddRange(args);
        all.Add("-ResultFile"); all.Add(result);
        try
        {
            if (!File.Exists(AppPaths.ActionsScript)) return Fail("Manca Azioni.ps1 accanto al programma: probabilmente e' in quarantena nell'antivirus.");
            ProcessStartInfo psi;
            if (admin)
            {
                // "runas" passa per ShellExecute: niente ArgumentList, gli argomenti vanno quotati a mano
                psi = new ProcessStartInfo("powershell.exe", string.Join(' ', all.Select(Quote)))
                { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            }
            else
            {
                psi = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in all) psi.ArgumentList.Add(a);
            }
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell non e' partito.");
            await p.WaitForExitAsync();
            if (!File.Exists(result)) return Fail("L'azione non ha prodotto un esito.");
            return JsonNode.Parse(File.ReadAllText(result)) as JsonObject ?? Fail("Esito non leggibile.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return Fail("Hai annullato la richiesta di Windows: non e' stato modificato nulla.");
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

    // Regole di quotatura di CommandLineToArgvW: virgolette intorno, \ prima delle virgolette
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
/// Verifica programmata: un'attivita' di Utilita' di pianificazione dell'utente (senza
/// privilegi di amministratore) che lancia il motore in silenzio una volta a settimana.
/// Il motore riconosce questa attivita' come propria e non la segnala.
/// </summary>
public static class Scheduler
{
    public const string TaskName = @"\CheckBackdoor\Verifica settimanale";
    static readonly string[] Days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

    public static bool Exists() => Run(["/Query", "/TN", TaskName]) == 0;

    public static void Delete() => Run(["/Delete", "/TN", TaskName, "/F"]);

    /// <summary>day: 0 = domenica ... 6 = sabato; hour: 0-23.</summary>
    public static bool Create(int day, int hour)
    {
        day = Math.Clamp(day, 0, 6); hour = Math.Clamp(hour, 0, 23);
        var ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
        var args = string.Join(' ',
            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File", Q(AppPaths.EngineScript),
            "-NoElevate -Quiet -NoOpen -CompareLast -OutputDir", Q(AppPaths.ReportsDir),
            "-AllowlistFile", Q(AppPaths.IgnoredFile), "-VirusTotalKeyFile", Q(AppPaths.VirusTotalKeyFile));
        // Una data passata nel giorno scelto: il trigger settimanale parte da li'
        var start = new DateTime(2026, 1, 4, hour, 0, 0).AddDays(day);   // 4/1/2026 era domenica
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Verifica settimanale di CheckBackdoor, in sola lettura. Si gestisce dalle impostazioni dell'app.</Description></RegistrationInfo>
              <Triggers><CalendarTrigger><StartBoundary>{start:yyyy-MM-ddTHH:mm:ss}</StartBoundary><ScheduleByWeek><DaysOfWeek><{Days[day]} /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger></Triggers>
              <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
              <Settings><StartWhenAvailable>true</StartWhenAvailable><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT2H</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Priority>7</Priority></Settings>
              <Actions Context="Author"><Exec><Command>{SecurityElement.Escape(ps)}</Command><Arguments>{SecurityElement.Escape(args)}</Arguments><WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(AppPaths.EngineScript))}</WorkingDirectory></Exec></Actions>
            </Task>
            """;
        Directory.CreateDirectory(AppPaths.RunsDir);
        var file = Path.Combine(AppPaths.RunsDir, $"attivita-{Guid.NewGuid():N}.xml");
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
