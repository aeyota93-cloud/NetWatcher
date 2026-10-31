using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Asn;

/// <summary>What the regional registry says about an address block.</summary>
public sealed record RdapResult(
    string Handle,
    string Name,
    string Country,
    string StartAddress,
    string EndAddress,
    IReadOnlyList<Cidr> Networks,
    IReadOnlyList<string> Organizations,
    string Source)
{
    public string ToText(AddressFormat format)
    {
        var sb = new StringBuilder();
        void Line(string title, string value)
        {
            if (!string.IsNullOrWhiteSpace(value)) sb.Append(title).Append(": ").AppendLine(value);
        }

        Line("Сеть", string.Join(", ", Networks.Select(n => n.Format(format))));
        Line("Диапазон", StartAddress != "" ? $"{StartAddress} – {EndAddress}" : "");
        Line("Название", Name);
        Line("Идентификатор", Handle);
        Line("Организация", string.Join("; ", Organizations));
        Line("Страна", Country);
        Line("Источник", Source);
        return sb.ToString().TrimEnd();
    }
}

/// <summary>
/// Asks RDAP (the registries' lookup service) about one address. rdap.org redirects
/// to the right registry: RIPE, ARIN, APNIC, LACNIC or AFRINIC.
/// </summary>
public sealed class RdapClient(HttpClient http)
{
    private readonly ConcurrentDictionary<string, RdapResult> _cache = new();

    public async Task<RdapResult> LookupAsync(IPAddress ip, CancellationToken ct = default)
    {
        var key = IpKey.Normalize(ip).ToString();
        if (_cache.TryGetValue(key, out var cached)) return cached;

        var url = "https://rdap.org/ip/" + Uri.EscapeDataString(key);
        using var response = await http.GetAsync(url, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
            throw new InvalidOperationException("Сервис RDAP просит подождать: слишком много запросов. Повторите через минуту.");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var result = Parse(json, response.RequestMessage?.RequestUri?.Host ?? "rdap.org");
        _cache[key] = result;
        return result;
    }

    public static RdapResult Parse(string json, string source)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var networks = new List<Cidr>();
        if (root.TryGetProperty("cidr0_cidrs", out var cidrs) && cidrs.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in cidrs.EnumerateArray())
            {
                var prefix = Str(c, "v4prefix") is { Length: > 0 } v4 ? v4 : Str(c, "v6prefix");
                if (c.TryGetProperty("length", out var len) && len.TryGetInt32(out var l)
                    && Cidr.TryParse($"{prefix}/{l}", out var cidr))
                    networks.Add(cidr);
            }
        }

        var start = Str(root, "startAddress");
        var end = Str(root, "endAddress");
        if (networks.Count == 0 && IpKey.TryParse(start, out var a) && IpKey.TryParse(end, out var b))
            networks.AddRange(CidrMath.FromRange(IpKey.From(a), IpKey.From(b)));

        var orgs = new List<string>();
        if (root.TryGetProperty("entities", out var entities) && entities.ValueKind == JsonValueKind.Array)
            CollectOrganizations(entities, orgs);

        return new RdapResult(
            Str(root, "handle"),
            Str(root, "name"),
            Str(root, "country"),
            start,
            end,
            networks,
            orgs.Distinct().ToList(),
            source);
    }

    private static void CollectOrganizations(JsonElement entities, List<string> orgs)
    {
        foreach (var e in entities.EnumerateArray())
        {
            var roles = e.TryGetProperty("roles", out var r) && r.ValueKind == JsonValueKind.Array
                ? r.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                : [];
            if (roles.Contains("registrant") || roles.Contains("administrative") && orgs.Count == 0)
            {
                var fn = VcardName(e);
                if (fn != "") orgs.Add(fn);
            }
            if (e.TryGetProperty("entities", out var nested) && nested.ValueKind == JsonValueKind.Array)
                CollectOrganizations(nested, orgs);
        }
    }

    // vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"], ...]]
    private static string VcardName(JsonElement entity)
    {
        if (!entity.TryGetProperty("vcardArray", out var v) || v.ValueKind != JsonValueKind.Array || v.GetArrayLength() < 2)
            return "";
        foreach (var prop in v[1].EnumerateArray())
        {
            if (prop.ValueKind == JsonValueKind.Array && prop.GetArrayLength() >= 4 && prop[0].GetString() == "fn")
                return prop[3].ValueKind == JsonValueKind.String ? prop[3].GetString() ?? "" : "";
        }
        return "";
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";
}
