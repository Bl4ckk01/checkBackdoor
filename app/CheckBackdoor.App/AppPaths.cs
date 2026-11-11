namespace CheckBackdoor.App;

/// <summary>Dove si trovano motore, interfaccia e dati dell'utente.</summary>
public static class AppPaths
{
    public static string AppDir { get; } = AppContext.BaseDirectory;

    /// <summary>Il motore copiato accanto all'app in fase di compilazione.</summary>
    public static string EngineScript => Path.Combine(AppDir, "engine", "CheckBackdoor.ps1");

    public static string UiDir => Path.Combine(AppDir, "ui");

    /// <summary>
    /// Report, file di eventi e dati di WebView2 stanno nel profilo dell'utente: l'app
    /// puo' essere installata in una cartella non scrivibile come Program Files.
    /// </summary>
    public static string DataDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CheckBackdoor");

    public static string ReportsDir => Path.Combine(DataDir, "report");
    public static string RunsDir => Path.Combine(DataDir, "runs");
    public static string WebViewDataDir => Path.Combine(DataDir, "WebView2");

    /// <summary>Lo script che disattiva con backup e annulla (modules\Remedy.ps1).</summary>
    public static string ActionsScript => Path.Combine(AppDir, "engine", "Azioni.ps1");

    /// <summary>Backup delle modifiche fatte con "Disattiva": servono per "Annulla".</summary>
    public static string BackupDir => Path.Combine(DataDir, "backup");

    /// <summary>Elementi che l'utente ha scelto di ignorare (lista bianca per ID).</summary>
    public static string IgnoredFile => Path.Combine(DataDir, "ignorati.json");

    /// <summary>Chiave di VirusTotal cifrata con DPAPI per l'utente corrente.</summary>
    public static string VirusTotalKeyFile => Path.Combine(DataDir, "virustotal.key");

    public static string SettingsFile => Path.Combine(DataDir, "impostazioni.json");

    public static void EnsureDataDirs()
    {
        Directory.CreateDirectory(ReportsDir);
        Directory.CreateDirectory(RunsDir);
        Directory.CreateDirectory(BackupDir);
    }

    /// <summary>Vero se il percorso sta dentro la cartella indicata (dopo averlo reso assoluto).</summary>
    public static bool IsInside(string? path, string dir)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }
}
