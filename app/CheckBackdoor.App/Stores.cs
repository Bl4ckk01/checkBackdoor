using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CheckBackdoor.App;

/// <summary>
/// VirusTotal key encrypted with DPAPI (current user scope): only the same Windows user
/// on the same PC can read it. The engine decrypts it by itself (Read-ProtectedSecret),
/// so it never goes through the command line or environment variables.
/// </summary>
public static class Secrets
{
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("CheckBackdoor.VirusTotal/1");

    public static bool HasVirusTotalKey => File.Exists(AppPaths.VirusTotalKeyFile);

    /// <summary>VirusTotal API keys are 64 hexadecimal digits.</summary>
    public static bool IsValidVirusTotalKey(string? key) =>
        key is { Length: 64 } && key.All(Uri.IsHexDigit);

    public static void SaveVirusTotalKey(string key)
    {
        var blob = Protect(Encoding.UTF8.GetBytes(key));
        Directory.CreateDirectory(AppPaths.DataDir);
        File.WriteAllText(AppPaths.VirusTotalKeyFile, Convert.ToBase64String(blob));
    }

    public static void DeleteVirusTotalKey()
    {
        if (File.Exists(AppPaths.VirusTotalKeyFile)) File.Delete(AppPaths.VirusTotalKeyFile);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DataBlob { public int Size; public IntPtr Data; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptProtectData(ref DataBlob dataIn, string? description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, int flags, ref DataBlob dataOut);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr mem);

    static byte[] Protect(byte[] plain)
    {
        var hPlain = GCHandle.Alloc(plain, GCHandleType.Pinned);
        var hEntropy = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            var input = new DataBlob { Size = plain.Length, Data = hPlain.AddrOfPinnedObject() };
            var entropy = new DataBlob { Size = Entropy.Length, Data = hEntropy.AddrOfPinnedObject() };
            var output = new DataBlob();
            const int UiForbidden = 0x1;
            if (!CryptProtectData(ref input, "CheckBackdoor", ref entropy, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, output.Size);
                return result;
            }
            finally { LocalFree(output.Data); }
        }
        finally { hPlain.Free(); hEntropy.Free(); }
    }
}

/// <summary>
/// Items the user chose to ignore. The engine reads "ids" as an allowlist
/// (-AllowlistFile); the app uses "items" to show and restore them.
/// </summary>
public static class IgnoreStore
{
    public static JsonArray Items()
    {
        var root = Load();
        return root["items"] as JsonArray ?? [];
    }

    /// <summary>
    /// sha256: hash of the file at the time of the choice. The engine stops ignoring the
    /// item if the file changes: "ignore" applies to that file, not to that path.
    /// </summary>
    public static void Add(string id, string? title, string? category, string? sha256)
    {
        var root = Load();
        var items = root["items"] as JsonArray ?? [];
        if (items.Any(i => (string?)i?["id"] == id)) return;
        items.Add(new JsonObject { ["id"] = id, ["title"] = title, ["category"] = category, ["sha256"] = sha256, ["date"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm") });
        Save(items);
    }

    public static void Remove(string id)
    {
        var items = Load()["items"] as JsonArray ?? [];
        var keep = new JsonArray();
        foreach (var i in items.ToList()) if ((string?)i?["id"] != id) keep.Add(i?.DeepClone());
        Save(keep);
    }

    static JsonObject Load()
    {
        try
        {
            if (File.Exists(AppPaths.IgnoredFile) && JsonNode.Parse(File.ReadAllText(AppPaths.IgnoredFile)) is JsonObject o) return o;
        }
        catch (JsonException) { }
        return new JsonObject { ["ids"] = new JsonArray(), ["items"] = new JsonArray() };
    }

    static void Save(JsonArray items)
    {
        var ids = new JsonArray();
        foreach (var i in items) if ((string?)i?["id"] is string id) ids.Add(id);
        var root = new JsonObject { ["ids"] = ids, ["items"] = items.DeepClone() };
        Directory.CreateDirectory(AppPaths.DataDir);
        File.WriteAllText(AppPaths.IgnoredFile, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>The changes made with "Disable", read from the checkbackdoor.backup/1 files.</summary>
public static class BackupStore
{
    public static JsonArray List(int max = 50)
    {
        var list = new JsonArray();
        // Two folders: the user's and the protected one for backups made as administrator
        var files = new[] { AppPaths.BackupDir, AppPaths.ProtectedBackupDir }
            .Where(Directory.Exists)
            .SelectMany(d => { try { return new DirectoryInfo(d).GetFiles("*.json"); } catch (Exception) { return Array.Empty<FileInfo>(); } });
        foreach (var f in files.OrderByDescending(f => f.Name).Take(max))
        {
            try
            {
                if (JsonNode.Parse(File.ReadAllText(f.FullName)) is not JsonObject b || (string?)b["Schema"] != "checkbackdoor.backup/1") continue;
                list.Add(new JsonObject
                {
                    ["file"] = f.FullName,
                    ["title"] = (string?)b["Title"],
                    ["date"] = (string?)b["Date"],
                    ["kind"] = (string?)b["Remedy"]?["Kind"],
                    ["undone"] = b["Undone"]?.GetValue<bool>() == true,
                });
            }
            catch (Exception) { }
        }
        return list;
    }

    /// <summary>
    /// What is in quarantine: files and browser extensions moved away by "Disable",
    /// "Quarantine" or "Remove extension", not put back yet and still there next to the backup.
    /// </summary>
    public static JsonArray Quarantine()
    {
        var list = new JsonArray();
        foreach (var dir in new[] { AppPaths.BackupDir, AppPaths.ProtectedBackupDir }.Where(Directory.Exists))
        {
            FileInfo[] files;
            try { files = new DirectoryInfo(dir).GetFiles("*.json"); } catch (Exception) { continue; }
            foreach (var f in files.OrderByDescending(f => f.Name))
            {
                try
                {
                    if (JsonNode.Parse(File.ReadAllText(f.FullName)) is not JsonObject b || (string?)b["Schema"] != "checkbackdoor.backup/1") continue;
                    if (b["Undone"]?.GetValue<bool>() == true) continue;
                    var kind = (string?)b["Remedy"]?["Kind"];
                    var moved = kind switch { "File" or "QuarantineFile" => Path.ChangeExtension(f.FullName, ".file"), "BrowserExtension" => Path.ChangeExtension(f.FullName, ".ext"), _ => null };
                    if (moved is null || !(File.Exists(moved) || Directory.Exists(moved))) continue;
                    list.Add(new JsonObject
                    {
                        ["file"] = f.FullName,
                        ["title"] = (string?)b["Title"],
                        ["date"] = (string?)b["Date"],
                        ["kind"] = kind,
                        ["path"] = (string?)b["Remedy"]?["Path"],
                        ["folder"] = Directory.Exists(moved),
                    });
                }
                catch (Exception) { }
            }
        }
        return list;
    }

    /// <summary>True if the file is a backup in one of the two CheckBackdoor folders.</summary>
    public static bool IsBackupFile(string? file) =>
        AppPaths.IsInside(file, AppPaths.BackupDir) || AppPaths.IsInside(file, AppPaths.ProtectedBackupDir);

    /// <summary>
    /// Whether undoing needs the administrator. The folder decides, not the content of the
    /// file: only backups in the protected folder are restored with those rights, because
    /// any program can rewrite the ones in the user's profile.
    /// </summary>
    public static bool NeedsAdmin(string backupFile) => AppPaths.IsInside(backupFile, AppPaths.ProtectedBackupDir);
}

/// <summary>App settings (for now: the day of the scheduled scan).</summary>
public static class SettingsStore
{
    public static JsonObject Load()
    {
        try
        {
            if (File.Exists(AppPaths.SettingsFile) && JsonNode.Parse(File.ReadAllText(AppPaths.SettingsFile)) is JsonObject o) return o;
        }
        catch (JsonException) { }
        return new JsonObject();
    }

    public static void Save(JsonObject settings)
    {
        Directory.CreateDirectory(AppPaths.DataDir);
        File.WriteAllText(AppPaths.SettingsFile, settings.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}
