using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace CheckBackdoor.App;

/// <summary>
/// Starts the PowerShell engine and follows its event file (docs/EVENTS.md).
/// The engine can restart itself as administrator in a new process: that is why events
/// are read from a file and the pid given by the latest event is watched.
/// </summary>
public sealed class ScanRunner : IDisposable
{
    /// <summary>A complete event line, as written by the engine.</summary>
    public event Action<string>? EventReceived;

    /// <summary>The scan ended without a final event (process closed or never started).</summary>
    public event Action<string>? Aborted;

    public bool IsRunning { get; private set; }
    public string? EventsPath { get; private set; }

    readonly CancellationTokenSource _stop = new();
    Process? _process;

    // Time given to the administrator process to write its first event after the UAC
    // prompt: whoever has to answer the Windows dialog may take a while.
    static readonly TimeSpan ElevationGrace = TimeSpan.FromMinutes(3);

    public void Start(string engineScript, string outputDir, string runsDir, IEnumerable<string>? extraArgs = null)
    {
        if (IsRunning) throw new InvalidOperationException("A scan is already running.");
        if (!File.Exists(engineScript)) throw new FileNotFoundException("Scan engine not found.", engineScript);

        Directory.CreateDirectory(runsDir);
        EventsPath = Path.Combine(runsDir, $"scan-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}.jsonl");
        File.WriteAllText(EventsPath, "");

        var psi = new ProcessStartInfo(AppPaths.PowerShellExe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(engineScript)!,
        };
        foreach (var a in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", engineScript,
                                  "-NoOpen", "-Quiet", "-OutputDir", outputDir, "-EventsFile", EventsPath })
            psi.ArgumentList.Add(a);
        foreach (var a in extraArgs ?? []) psi.ArgumentList.Add(a);

        _process = Process.Start(psi) ?? throw new InvalidOperationException("Cannot start PowerShell.");
        IsRunning = true;
        _ = Task.Run(() => FollowAsync(_process.Id, _stop.Token));
    }

    /// <summary>Asks the engine to stop before the next check (see "Cancelling a scan").</summary>
    public void RequestCancel()
    {
        if (IsRunning && EventsPath is not null) File.WriteAllText(EventsPath + ".cancel", "");
    }

    async Task FollowAsync(int initialPid, CancellationToken ct)
    {
        int watchedPid = initialPid;
        bool elevating = false;
        bool sawDead = false;
        DateTime elevatingSince = default;
        var pending = new StringBuilder();
        var buffer = new char[16 * 1024];

        try
        {
            using var fs = new FileStream(EventsPath!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs, new UTF8Encoding(false));
            while (!ct.IsCancellationRequested)
            {
                int read;
                while ((read = await reader.ReadAsync(buffer, ct)) > 0) pending.Append(buffer, 0, read);

                // Complete lines only: the last one without "\n" may still be being written
                string text = pending.ToString();
                int last = text.LastIndexOf('\n');
                if (last >= 0)
                {
                    pending.Remove(0, last + 1);
                    foreach (var line in text[..last].Split('\n'))
                    {
                        var trimmed = line.Trim();
                        if (trimmed.Length == 0) continue;
                        var (type, pid) = Peek(trimmed);
                        if (pid is int p && p != watchedPid) { watchedPid = p; elevating = false; }
                        if (type == "scan.elevating") { elevating = true; elevatingSince = DateTime.UtcNow; }
                        EventReceived?.Invoke(trimmed);
                        if (type is "scan.completed" or "scan.failed" or "scan.cancelled") { Finish(); return; }
                    }
                }

                if (!IsAlive(watchedPid))
                {
                    // After the UAC prompt the process that asked exits at once: wait for the new one
                    if (elevating && DateTime.UtcNow - elevatingSince < ElevationGrace) { await Task.Delay(300, ct); continue; }
                    // One last read: the final events may have arrived just now
                    if (!sawDead) { sawDead = true; await Task.Delay(500, ct); continue; }
                    Finish();
                    Aborted?.Invoke(elevating
                        ? "The administrator prompt got no answer."
                        : "The scan process closed without finishing the scan.");
                    return;
                }
                await Task.Delay(200, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Finish();
            Aborted?.Invoke("Error reading the scan progress: " + ex.Message);
        }
    }

    static (string? type, int? pid) Peek(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            string? type = root.TryGetProperty("type", out var t) ? t.GetString() : null;
            int? pid = root.TryGetProperty("pid", out var p) && p.TryGetInt32(out var v) ? v : null;
            return (type, pid);
        }
        catch (JsonException) { return (null, null); }
    }

    static bool IsAlive(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException) { return false; }                 // no process with that pid
        catch (System.ComponentModel.Win32Exception) { return true; } // administrator process: not readable, but it exists
        catch (InvalidOperationException) { return false; }
    }

    void Finish()
    {
        IsRunning = false;
        if (EventsPath is not null) File.Delete(EventsPath + ".cancel");
    }

    public void Dispose()
    {
        _stop.Cancel();
        _process?.Dispose();
    }
}
