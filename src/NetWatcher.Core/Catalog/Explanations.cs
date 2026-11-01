using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetWatcher.Core.Catalog;

/// <summary>What a program, a Windows service or a domain is, why it goes online and what breaks if it is blocked.</summary>
public sealed record Explanation(string Title, string What, string Block);

/// <summary>
/// "Что это за соединение?": a hand-written catalog (Catalog/explanations.json, built into the program)
/// of common Windows services, programs and domains. Like Little Snitch's Research Assistant, but offline;
/// what is not in the catalog is said to be unknown rather than guessed.
/// </summary>
public sealed class Explanations
{
    private sealed class Entry
    {
        [JsonPropertyName("service")] public string? Service { get; set; }
        [JsonPropertyName("process")] public string? Process { get; set; }
        [JsonPropertyName("domain")] public string? Domain { get; set; }
        [JsonPropertyName("prefix")] public string? Prefix { get; set; }
        [JsonPropertyName("title")] public string Title { get; set; } = "";
        [JsonPropertyName("what")] public string What { get; set; } = "";
        [JsonPropertyName("block")] public string Block { get; set; } = "";
    }

    private readonly Dictionary<string, Explanation> _services = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Explanation> _processes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Explanation> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Prefix, Explanation Text)> _prefixes = [];

    public int Count => _services.Count + _processes.Count + _domains.Count + _prefixes.Count;

    public static Explanations Load(Stream json)
    {
        var result = new Explanations();
        foreach (var e in JsonSerializer.Deserialize<List<Entry>>(json) ?? [])
        {
            var x = new Explanation(e.Title, e.What, e.Block);
            if (e.Service != null) result._services[e.Service] = x;
            else if (e.Process != null) result._processes[e.Process] = x;
            else if (e.Domain != null) result._domains[e.Domain.TrimEnd('.')] = x;
            else if (e.Prefix != null) result._prefixes.Add((e.Prefix, x));
        }
        return result;
    }

    private static Explanations? _builtin;

    /// <summary>The catalog built into NetWatcher.Core.</summary>
    public static Explanations Builtin
    {
        get
        {
            if (_builtin != null) return _builtin;
            using var stream = typeof(Explanations).Assembly.GetManifestResourceStream("explanations.json")
                               ?? throw new InvalidOperationException("explanations.json is not built in");
            return _builtin = Load(stream);
        }
    }

    /// <summary>A Windows service of the group first ("svchost.exe · BITS"), then the program by its file name.</summary>
    public Explanation? ForProgram(string process, string services)
    {
        foreach (var s in services.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (_services.TryGetValue(s, out var x)) return x;
        return _processes.GetValueOrDefault(process);
    }

    /// <summary>The domain itself or the closest parent domain; then names like "ocsp.…" by their first label.</summary>
    public Explanation? ForDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return null;
        var name = domain.TrimEnd('.');
        for (var at = 0; at >= 0 && name[at..].Contains('.'); at = name.IndexOf('.', at) is var dot and >= 0 ? dot + 1 : -1)
            if (_domains.TryGetValue(name[at..], out var x)) return x;
        foreach (var (prefix, x) in _prefixes)
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return x;
        return null;
    }
}
