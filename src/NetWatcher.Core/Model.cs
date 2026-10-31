using System.Net;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Net;

namespace NetWatcher.Core;

/// <summary>One sighting of "process talks to address:port".</summary>
public sealed record Observation(
    string Process,
    string Services,
    string Path,
    string Proto,
    IPAddress RemoteIp,
    int RemotePort,
    DateTimeOffset Time);

/// <summary>A DNS answer: the process asked for Domain and got Ip.</summary>
public sealed record DnsObservation(string Process, string Domain, IPAddress Ip, DateTimeOffset Time);

/// <summary>A row on screen: one process (or service) and one destination over the chosen period.</summary>
public sealed class DestinationRow
{
    public required string Process { get; init; }

    /// <summary>Short service names, comma separated: "Dnscache,BITS". Empty for ordinary programs.</summary>
    public required string Services { get; init; }

    public string Path { get; init; } = "";
    public required string Proto { get; init; }
    public required IPAddress RemoteIp { get; init; }
    public required int RemotePort { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public long Hits { get; init; }

    // Filled after reading from the log.
    public IReadOnlyList<string> Domains { get; set; } = [];
    public AsnInfo? Asn { get; set; }

    /// <summary>Service names as people read them: "DNS-клиент (Dnscache)".</summary>
    public string ServicesDisplay { get; set; } = "";

    public string GroupKey => Services == "" ? Process : $"{Process} · {Services}";

    /// <summary>Identifies the row across refreshes: group, protocol, address and port.</summary>
    public string Key => $"{GroupKey}|{Proto}|{RemoteIpText}|{RemotePort}";

    /// <summary>The program first went to this address recently (see <see cref="Analysis.NewSince"/>).</summary>
    public bool IsNew { get; set; }

    public string PrimaryDomain => Domains.Count > 0 ? Domains[0] : "";
    public string RemoteIpText => RemoteIp.ToString();
    public string DomainsText => string.Join(", ", Domains);
    public string OwnerText => Asn?.OwnerText ?? "";
    public string CountryText => Asn?.Country ?? "";

    public string NetworkText(AddressFormat format)
    {
        if (Asn == null) return "";
        try
        {
            return Asn.NetworkOf(RemoteIp).Format(format);
        }
        catch (InvalidOperationException)
        {
            return "";
        }
    }

    /// <summary>
    /// Every word of the query must be found somewhere in the row. A word with "/"
    /// such as 142.250.0.0/15 matches addresses inside that network.
    /// </summary>
    public bool Matches(IReadOnlyList<string> words)
    {
        foreach (var word in words)
        {
            if (word.Contains('/') && Cidr.TryParse(word, out var net))
            {
                if (!net.Contains(RemoteIp)) return false;
                continue;
            }
            if (!Has(word)) return false;
        }
        return true;
    }

    private bool Has(string w) =>
        Contains(Process, w) || Contains(Services, w) || Contains(ServicesDisplay, w) || Contains(Path, w)
        || Contains(RemoteIpText, w) || RemotePort.ToString() == w || Contains(Proto, w)
        || Domains.Any(d => Contains(d, w)) || Contains(OwnerText, w) || Contains(CountryText, w);

    private static bool Contains(string text, string word) =>
        text.Contains(word, StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string> SplitQuery(string? query) =>
        (query ?? "").Split([' ', '\t', ','], StringSplitOptions.RemoveEmptyEntries);
}
