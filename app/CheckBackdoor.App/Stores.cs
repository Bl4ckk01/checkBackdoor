using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CheckBackdoor.App;

/// <summary>
/// Chiave di VirusTotal cifrata con DPAPI (ambito utente corrente): solo lo stesso utente
/// Windows sullo stesso PC puo' leggerla. Il motore la decifra da solo (Read-ProtectedSecret),
/// cosi' non passa mai dalla riga di comando o dalle variabili d'ambiente.
/// </summary>
public static class Secrets
{
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("CheckBackdoor.VirusTotal/1");

    public static bool HasVirusTotalKey => File.Exists(AppPaths.VirusTotalKeyFile);

    /// <summary>Le chiavi API di VirusTotal sono 64 cifre esadecimali.</summary>
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
/// Elementi che l'utente ha scelto di ignorare. Il motore legge "ids" come lista bianca
/// (-AllowlistFile); "items" serve all'app per mostrarli e ripristinarli.
/// </summary>
public static class IgnoreStore
{
    public static JsonArray Items()
    {
        var root = Load();
        return root["items"] as JsonArray ?? [];
    }

    /// <summary>
    /// sha256: impronta del file al momento della scelta. Il motore smette di ignorare
    /// l'elemento se il file cambia: "ignora" vale per quel file, non per quel percorso.
    /// </summary>
    public static void Add(string id, string? title, string? category, string? sha256)
    {
        var root = Load();
        var items = root["items"] as JsonArray ?? [];
        if (items.Any(i => (string?)i?["id"] == id)) return;
        items.Add(new JsonObject { ["id"] = id, ["title"] = title, ["category"] = category, ["sha256"] = sha256, ["date"] = DateTime.Now.ToString("dd/MM/yyyy HH:mm") });
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

/// <summary>Le modifiche fatte con "Disattiva", lette dai file checkbackdoor.backup/1.</summary>
public static class BackupStore
{
    public static JsonArray List(int max = 50)
    {
        var list = new JsonArray();
        // Due cartelle: quella dell'utente e quella protetta dei backup fatti come amministratore
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

    /// <summary>Vero se il file e' un backup di una delle due cartelle di CheckBackdoor.</summary>
    public static bool IsBackupFile(string? file) =>
        AppPaths.IsInside(file, AppPaths.BackupDir) || AppPaths.IsInside(file, AppPaths.ProtectedBackupDir);

    /// <summary>
    /// Se annullare richiede l'amministratore. Lo decide la cartella, non il contenuto del
    /// file: solo i backup della cartella protetta si ripristinano con quei privilegi, perche'
    /// quelli nel profilo dell'utente li puo' riscrivere qualsiasi programma.
    /// </summary>
    public static bool NeedsAdmin(string backupFile) => AppPaths.IsInside(backupFile, AppPaths.ProtectedBackupDir);
}

/// <summary>Impostazioni dell'app (per ora: il giorno della verifica programmata).</summary>
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
