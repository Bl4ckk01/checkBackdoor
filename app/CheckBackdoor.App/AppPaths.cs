namespace CheckBackdoor.App;

/// <summary>Where the engine, the interface and the user's data live.</summary>
public static class AppPaths
{
    public static string AppDir { get; } = AppContext.BaseDirectory;

    /// <summary>The engine copied next to the app at build time.</summary>
    public static string EngineScript => Path.Combine(AppDir, "engine", "CheckBackdoor.ps1");

    /// <summary>
    /// Windows PowerShell by its full path: a plain "powershell.exe" would be looked up
    /// first in the app folder and in the PATH, where anyone can put one.
    /// </summary>
    public static string PowerShellExe { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");

    public static string UiDir => Path.Combine(AppDir, "ui");

    /// <summary>
    /// Reports, event files and WebView2 data live in the user's profile: the app can be
    /// installed in a folder that is not writable, such as Program Files.
    /// </summary>
    public static string DataDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CheckBackdoor");

    public static string ReportsDir => Path.Combine(DataDir, "report");
    public static string RunsDir => Path.Combine(DataDir, "runs");
    public static string WebViewDataDir => Path.Combine(DataDir, "WebView2");

    /// <summary>The script that disables with a backup and undoes (modules\Remedy.ps1).</summary>
    public static string ActionsScript => Path.Combine(AppDir, "engine", "Actions.ps1");

    /// <summary>Backups of the changes made with "Disable": "Undo" needs them.</summary>
    public static string BackupDir => Path.Combine(DataDir, "backup");

    /// <summary>
    /// Backups of the changes made as administrator: a folder only administrators can
    /// write, so a program of the user cannot alter them to get something else restored.
    /// modules\Remedy.ps1 creates and protects it.
    /// </summary>
    public static string ProtectedBackupDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CheckBackdoor", "backup");

    /// <summary>Items the user chose to ignore (allowlist by ID).</summary>
    public static string IgnoredFile => Path.Combine(DataDir, "ignored.json");

    /// <summary>VirusTotal key encrypted with DPAPI for the current user.</summary>
    public static string VirusTotalKeyFile => Path.Combine(DataDir, "virustotal.key");

    public static string SettingsFile => Path.Combine(DataDir, "settings.json");

    public static void EnsureDataDirs()
    {
        Directory.CreateDirectory(ReportsDir);
        Directory.CreateDirectory(RunsDir);
        Directory.CreateDirectory(BackupDir);
    }

    /// <summary>True if the path is inside the given folder (after making it absolute).</summary>
    public static bool IsInside(string? path, string dir)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }
}
