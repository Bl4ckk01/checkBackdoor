using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace CheckBackdoor.App;

/// <summary>
/// Avvia il motore PowerShell e segue il suo file di eventi (docs/EVENTI.md).
/// Il motore puo' rilanciarsi come amministratore in un nuovo processo: per questo si
/// leggono gli eventi da un file e si sorveglia il pid indicato dall'ultimo evento.
/// </summary>
public sealed class ScanRunner : IDisposable
{
    /// <summary>Una riga di evento completa, cosi' come scritta dal motore.</summary>
    public event Action<string>? EventReceived;

    /// <summary>La scansione si e' chiusa senza un evento finale (processo chiuso o mai partito).</summary>
    public event Action<string>? Aborted;

    public bool IsRunning { get; private set; }
    public string? EventsPath { get; private set; }

    readonly CancellationTokenSource _stop = new();
    Process? _process;

    // Tempo concesso al processo amministratore per scrivere il primo evento dopo la
    // richiesta UAC: chi deve rispondere alla finestra di Windows puo' metterci un po'.
    static readonly TimeSpan ElevationGrace = TimeSpan.FromMinutes(3);

    public void Start(string engineScript, string outputDir, string runsDir, IEnumerable<string>? extraArgs = null)
    {
        if (IsRunning) throw new InvalidOperationException("Una verifica e' gia' in corso.");
        if (!File.Exists(engineScript)) throw new FileNotFoundException("Motore di scansione non trovato.", engineScript);

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

        _process = Process.Start(psi) ?? throw new InvalidOperationException("Impossibile avviare PowerShell.");
        IsRunning = true;
        _ = Task.Run(() => FollowAsync(_process.Id, _stop.Token));
    }

    /// <summary>Chiede al motore di fermarsi prima del prossimo controllo (vedi "Annullare una scansione").</summary>
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

                // Solo righe complete: l'ultima senza "\n" puo' essere ancora in scrittura
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
                    // Dopo la richiesta UAC il processo che l'ha fatta esce subito: si aspetta il nuovo
                    if (elevating && DateTime.UtcNow - elevatingSince < ElevationGrace) { await Task.Delay(300, ct); continue; }
                    // Un ultimo giro di lettura: gli eventi finali potrebbero essere arrivati proprio ora
                    if (!sawDead) { sawDead = true; await Task.Delay(500, ct); continue; }
                    Finish();
                    Aborted?.Invoke(elevating
                        ? "La richiesta dei privilegi di amministratore non ha avuto risposta."
                        : "Il processo di scansione si e' chiuso senza concludere la verifica.");
                    return;
                }
                await Task.Delay(200, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Finish();
            Aborted?.Invoke("Errore nel leggere l'avanzamento della verifica: " + ex.Message);
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
        catch (ArgumentException) { return false; }                 // nessun processo con quel pid
        catch (System.ComponentModel.Win32Exception) { return true; } // processo amministratore: non leggibile, ma esiste
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
