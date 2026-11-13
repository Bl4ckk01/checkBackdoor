using System.Text.Json;
using System.Windows;

namespace CheckBackdoor.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // "--smoke <folder>": a real, quick scan without a window, for automated tests
        if (e.Args.Length >= 2 && e.Args[0] == "--smoke")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(RunSmoke(e.Args[1]));
            return;
        }
        new MainWindow().Show();
    }

    /// <summary>
    /// Starts the engine as the interface would, but without asking for the administrator
    /// and skipping the slow checks. Writes the event types received to smoke.log.
    /// Exit code: 0 if the scan reaches scan.completed, 1 otherwise.
    /// </summary>
    static int RunSmoke(string outDir)
    {
        Directory.CreateDirectory(outDir);
        var log = new List<string>();
        var done = new ManualResetEventSlim();
        int exitCode = 1;
        using var runner = new ScanRunner();
        runner.EventReceived += line =>
        {
            var type = JsonDocument.Parse(line).RootElement.GetProperty("type").GetString();
            lock (log) log.Add(type ?? "?");
            if (type == "scan.completed") { exitCode = 0; done.Set(); }
            else if (type is "scan.failed" or "scan.cancelled") done.Set();
        };
        runner.Aborted += message => { lock (log) log.Add("aborted: " + message); done.Set(); };
        try
        {
            runner.Start(AppPaths.EngineScript, outDir, Path.Combine(outDir, "runs"),
                ["-NoElevate", "-Skip", "FileSystem,Processes,Services,Network,Browser,Injections"]);
            if (!done.Wait(TimeSpan.FromMinutes(5))) log.Add("timeout");
        }
        catch (Exception ex) { log.Add("error: " + ex.Message); }
        lock (log) File.WriteAllLines(Path.Combine(outDir, "smoke.log"), log);
        return exitCode;
    }
}
