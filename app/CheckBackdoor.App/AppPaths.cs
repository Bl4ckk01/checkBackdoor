namespace CheckBackdoor.App;

/// <summary>Dove si trovano motore, interfaccia e dati dell'utente.</summary>
public static class AppPaths
{
    public static string AppDir { get; } = AppContext.BaseDirectory;

    /// <summary>Il motore copiato accanto all'app in fase di compilazione.</summary>
    public static string EngineScript => Path.Combine(AppDir, "engine", "CheckBackdoor.ps1");

    /// <summary>
    /// Windows PowerShell con il percorso completo: un semplice "powershell.exe" verrebbe
    /// cercato prima nella cartella dell'app e nel PATH, dove chiunque puo' metterne uno.
    /// </summary>
    public static string PowerShellExe { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");

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
    public static string ActionsScript => Path.Combine(AppDir, "engine", "Actions.ps1");

    /// <summary>Backup delle modifiche fatte con "Disattiva": servono per "Annulla".</summary>
    public static string BackupDir => Path.Combine(DataDir, "backup");

    /// <summary>
    /// Backup delle modifiche fatte come amministratore: una cartella che solo gli
    /// amministratori possono scrivere, cosi' un programma dell'utente non puo' ritoccarli
    /// per far ripristinare altro. La crea e la protegge modules\Remedy.ps1.
    /// </summary>
    public static string ProtectedBackupDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CheckBackdoor", "backup");

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
