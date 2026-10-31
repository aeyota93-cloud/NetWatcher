using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace NetWatcher.Core.Asn;

/// <summary>What PeeringDB (an open directory of networks) says about an AS.</summary>
public sealed record PeeringDbNet(int Asn, string Name, string Aka, string Type, string Website, string Policy)
{
    /// <summary>The network type in plain Russian.</summary>
    public string TypeText => Type switch
    {
        "Content" => "контент и CDN (сайты, видео, облака)",
        "NSP" => "магистральный оператор связи",
        "Cable/DSL/ISP" => "интернет-провайдер",
        "Enterprise" => "компания (своя сеть)",
        "Educational/Research" => "наука и образование",
        "Non-Profit" => "некоммерческая организация",
        "Route Server" => "сервер маршрутов точки обмена трафиком",
        "Network Services" => "сетевые услуги (DNS, защита от атак и т. п.)",
        "Government" => "государственная сеть",
        "" => "не указан",
        _ => Type,
    };

    public string ToText() =>
        string.Join(Environment.NewLine, new[]
        {
            $"AS{Asn}: {Name}",
            Aka != "" && Aka != Name ? $"Также известна как: {Aka}" : "",
            $"Тип сети: {TypeText}",
            Website != "" ? $"Сайт: {Website}" : "",
            "Источник: peeringdb.com",
        }.Where(s => s != ""));
}

/// <summary>
/// Looks networks up on PeeringDB on request and keeps the answers on disk,
/// so each AS is asked for once.
/// </summary>
public sealed class PeeringDbClient
{
    private readonly HttpClient _http;
    private readonly string? _cachePath;
    private readonly ConcurrentDictionary<int, PeeringDbNet?> _cache = new();
    private readonly Lock _saveLock = new();

    public PeeringDbClient(HttpClient http, string? cachePath)
    {
        _http = http;
        _cachePath = cachePath;
        Load();
    }

    /// <summary>Cached answer: null when unknown or not listed.</summary>
    public PeeringDbNet? Cached(int asn) => _cache.TryGetValue(asn, out var n) ? n : null;

    public bool WasAsked(int asn) => _cache.ContainsKey(asn);

    /// <summary>Null when the AS is not in PeeringDB.</summary>
    public async Task<PeeringDbNet?> LookupAsync(int asn, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(asn, out var cached)) return cached;
        using var response = await _http.GetAsync($"https://www.peeringdb.com/api/net?asn={asn}", ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
            throw new InvalidOperationException("PeeringDB просит подождать: слишком много запросов. Повторите через минуту.");
        response.EnsureSuccessStatusCode();
        var net = Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false), asn);
        _cache[asn] = net;
        if (net != null) AsnNames.Learned[asn] = net.Name;
        Save();
        return net;
    }

    public static PeeringDbNet? Parse(string json, int asn)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array || data.GetArrayLength() == 0)
            return null;
        var n = data[0];
        static string S(JsonElement e, string name) =>
            e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString()?.Trim() ?? "" : "";
        return new PeeringDbNet(asn, S(n, "name"), S(n, "aka"), S(n, "info_type"), S(n, "website"), S(n, "policy_general"));
    }

    private void Load()
    {
        if (_cachePath == null || !File.Exists(_cachePath)) return;
        try
        {
            var list = JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(_cachePath)) ?? [];
            foreach (var e in list)
            {
                _cache[e.Asn] = e.Net;
                if (e.Net is { Name.Length: > 0 } net) AsnNames.Learned[e.Asn] = net.Name;
            }
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            // A broken cache is just forgotten.
        }
    }

    private void Save()
    {
        if (_cachePath == null) return;
        lock (_saveLock)
        {
            try
            {
                var list = _cache.Select(kv => new Entry(kv.Key, kv.Value)).ToList();
                var tmp = _cachePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(list));
                File.Move(tmp, _cachePath, overwrite: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Not saving the cache only costs a repeated request later.
            }
        }
    }

    private sealed record Entry(int Asn, PeeringDbNet? Net);
}
