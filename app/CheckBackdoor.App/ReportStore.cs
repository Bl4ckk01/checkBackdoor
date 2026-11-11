using System.Text.Json;
using System.Text.Json.Nodes;

namespace CheckBackdoor.App;

/// <summary>Riassunto delle verifiche gia' fatte, letto dai report JSON (checkbackdoor.report/1).</summary>
public static class ReportStore
{
    public const string ReportHost = "report.checkbackdoor.example";

    public static JsonArray Recent(string reportsDir, int max = 6)
    {
        var list = new JsonArray();
        if (!Directory.Exists(reportsDir)) return list;
        var files = new DirectoryInfo(reportsDir).GetFiles("*.json")
            .Where(f => f.Name.StartsWith("scansione_") || f.Name.StartsWith("controllo_"))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(max);
        foreach (var f in files)
        {
            var summary = Summarize(f.FullName);
            if (summary is not null) list.Add(summary);
        }
        return list;
    }

    public static JsonObject? Summarize(string jsonPath)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
            var root = doc.RootElement;
            var meta = root.GetProperty("Meta");
            var counts = new Dictionary<string, int> { ["Alto"] = 0, ["Medio"] = 0, ["Basso"] = 0, ["Info"] = 0 };
            if (root.TryGetProperty("Findings", out var findings) && findings.ValueKind == JsonValueKind.Array)
                foreach (var f in findings.EnumerateArray())
                    if (f.TryGetProperty("Severity", out var s) && s.GetString() is string sev && counts.ContainsKey(sev)) counts[sev]++;

            int examined = 0;
            if (meta.TryGetProperty("Examined", out var ex) && ex.ValueKind == JsonValueKind.Object)
                foreach (var p in ex.EnumerateObject()) if (p.Value.TryGetInt32(out var n)) examined += n;

            var html = Path.ChangeExtension(jsonPath, ".html");
            return new JsonObject
            {
                ["mode"] = Str(meta, "Mode") ?? "Scan",
                ["target"] = Str(meta, "Target"),
                ["date"] = Str(meta, "Date"),
                ["duration"] = Str(meta, "Duration"),
                ["admin"] = meta.TryGetProperty("Admin", out var a) && a.ValueKind == JsonValueKind.True,
                ["examined"] = examined,
                ["counts"] = new JsonObject { ["Alto"] = counts["Alto"], ["Medio"] = counts["Medio"], ["Basso"] = counts["Basso"], ["Info"] = counts["Info"] },
                ["htmlUrl"] = File.Exists(html) ? $"https://{ReportHost}/{Uri.EscapeDataString(Path.GetFileName(html))}" : null,
                ["htmlPath"] = File.Exists(html) ? html : null,
                ["jsonPath"] = jsonPath,
            };
        }
        catch (Exception) { return null; }   // report di una versione diversa o incompleto: si salta
    }

    /// <summary>Una segnalazione del report, cercata per ID (per le azioni dell'app).</summary>
    public static JsonObject? FindFinding(string jsonPath, string id)
    {
        var root = JsonNode.Parse(File.ReadAllText(jsonPath));
        if (root?["Findings"] is not JsonArray findings) return null;
        foreach (var f in findings)
            if (f is JsonObject o && string.Equals((string?)o["Id"], id, StringComparison.OrdinalIgnoreCase)) return o;
        return null;
    }

    /// <summary>
    /// Cosa e' cambiato tra due verifiche: segnalazioni nuove e risolte (per ID), elementi
    /// installati e rimossi (inventario). Le connessioni di rete cambiano di continuo e
    /// restano fuori; le aree non controllate in una delle due non contano come "rimosse".
    /// </summary>
    public static JsonObject Compare(string olderJson, string newerJson)
    {
        var a = JsonNode.Parse(File.ReadAllText(olderJson))!;
        var b = JsonNode.Parse(File.ReadAllText(newerJson))!;

        static Dictionary<string, JsonObject> FindingsOf(JsonNode r)
        {
            var d = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
            if (r["Findings"] is JsonArray arr)
                foreach (var f in arr.OfType<JsonObject>())
                    if ((string?)f["Id"] is string id && (string?)f["Severity"] != "Info" && !((string?)f["Category"] ?? "").StartsWith("Novit")) d[id] = f;
            return d;
        }
        static Dictionary<string, JsonObject> InventoryOf(JsonNode r)
        {
            var d = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
            if (r["Inventory"] is JsonArray arr)
                foreach (var i in arr.OfType<JsonObject>())
                {
                    string cat = (string?)i["Category"] ?? "", key = (string?)i["Key"] ?? "";
                    if (cat == "Rete" && (key.StartsWith("Listen |") || key.StartsWith("Established |"))) continue;
                    if (key == "File eseguibili esaminati") continue;
                    d[$"{cat}|{key}"] = i;
                }
            return d;
        }
        static JsonObject Pick(JsonObject f) => new()
        {
            ["id"] = (string?)f["Id"], ["severity"] = (string?)f["Severity"], ["category"] = (string?)f["Category"],
            ["title"] = (string?)f["Title"], ["path"] = (string?)f["Path"],
        };
        static JsonObject PickInv(JsonObject i) => new()
        {
            ["category"] = (string?)i["Category"], ["key"] = (string?)i["Key"], ["value"] = (string?)i["Value"],
        };

        var fa = FindingsOf(a); var fb = FindingsOf(b);
        var ia = InventoryOf(a); var ib = InventoryOf(b);
        var catsA = ia.Values.Select(i => (string?)i["Category"]).ToHashSet();
        var catsB = ib.Values.Select(i => (string?)i["Category"]).ToHashSet();

        var order = new Dictionary<string, int> { ["Alto"] = 0, ["Medio"] = 1, ["Basso"] = 2 };
        int Sev(JsonObject f) => order.TryGetValue((string?)f["Severity"] ?? "", out var n) ? n : 3;
        const int Max = 300;
        return new JsonObject
        {
            ["older"] = Summarize(olderJson),
            ["newer"] = Summarize(newerJson),
            ["newFindings"] = new JsonArray(fb.Where(kv => !fa.ContainsKey(kv.Key)).Select(kv => kv.Value).OrderBy(Sev).Take(Max).Select(f => (JsonNode)Pick(f)).ToArray()),
            ["resolved"] = new JsonArray(fa.Where(kv => !fb.ContainsKey(kv.Key)).Select(kv => kv.Value).OrderBy(Sev).Take(Max).Select(f => (JsonNode)Pick(f)).ToArray()),
            ["added"] = new JsonArray(ib.Where(kv => !ia.ContainsKey(kv.Key) && catsA.Contains((string?)kv.Value["Category"])).Take(Max).Select(kv => (JsonNode)PickInv(kv.Value)).ToArray()),
            // Stesso elemento con un valore diverso: di solito un aggiornamento (cambia la versione nel percorso)
            ["changed"] = new JsonArray(ib.Where(kv => ia.TryGetValue(kv.Key, out var old) && (string?)old["Value"] != (string?)kv.Value["Value"])
                .Take(Max).Select(kv => { var o = PickInv(kv.Value); o["before"] = (string?)ia[kv.Key]["Value"]; return (JsonNode)o; }).ToArray()),
            ["removed"] = new JsonArray(ia.Where(kv => !ib.ContainsKey(kv.Key) && catsB.Contains((string?)kv.Value["Category"])).Take(Max).Select(kv => (JsonNode)PickInv(kv.Value)).ToArray()),
        };
    }

    static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
