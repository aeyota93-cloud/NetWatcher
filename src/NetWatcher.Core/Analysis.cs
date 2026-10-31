using System.Net;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Net;

namespace NetWatcher.Core;

public enum SubnetMode
{
    /// <summary>Only the seen addresses, neighbours merged.</summary>
    Exact,

    /// <summary>Widen to /24 for IPv4 and /48 for IPv6.</summary>
    Wide24,

    /// <summary>Widen to /16 for IPv4 and /32 for IPv6.</summary>
    Wide16,

    /// <summary>The owner's announced networks from the AS database.</summary>
    Owner,
}

public static class Analysis
{
    /// <summary>Adds domains, owners and readable service names to rows from the log.</summary>
    public static void Enrich(
        IEnumerable<DestinationRow> rows,
        DnsIndex dns,
        AsnDatabase asn,
        IReadOnlyDictionary<string, string> serviceDisplayNames)
    {
        foreach (var row in rows)
        {
            row.Domains = dns.Get(row.RemoteIp, row.Process);
            row.Asn = asn.Lookup(row.RemoteIp);
            row.ServicesDisplay = ServicesDisplay(row.Services, serviceDisplayNames);
        }
    }

    public static string ServicesDisplay(string services, IReadOnlyDictionary<string, string> displayNames)
    {
        if (services == "") return "";
        return string.Join(", ", services.Split(',').Select(s =>
            displayNames.TryGetValue(s, out var d) && !string.Equals(d, s, StringComparison.OrdinalIgnoreCase)
                ? $"{d} ({s})"
                : s));
    }

    /// <summary>Networks covering the addresses of the rows, in the chosen mode.</summary>
    public static List<Cidr> Subnets(IEnumerable<DestinationRow> rows, SubnetMode mode, bool ipv4Only)
    {
        var list = rows.Where(r => !ipv4Only || r.RemoteIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
        var ips = list.Select(r => r.RemoteIp).Distinct().ToList();
        return mode switch
        {
            SubnetMode.Exact => CidrMath.Summarize(ips),
            SubnetMode.Wide24 => CidrMath.Aggregate(ips, 24, 48),
            SubnetMode.Wide16 => CidrMath.Aggregate(ips, 16, 32),
            SubnetMode.Owner => CidrMath.Merge(list
                .GroupBy(r => r.RemoteIp)
                .Select(g => g.First())
                .Select(r => r.Asn is { } a ? a.NetworkOf(r.RemoteIp) : Cidr.Of(r.RemoteIp, r.RemoteIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))),
            _ => [],
        };
    }

    /// <summary>A group in the left list: one program, or svchost with its services.</summary>
    public sealed record Group(string Key, string Process, string ServicesDisplay, string Path, int Destinations, int Addresses, DateTimeOffset LastSeen);

    public static List<Group> Groups(IEnumerable<DestinationRow> rows) =>
        rows.GroupBy(r => r.GroupKey)
            .Select(g => new Group(
                g.Key,
                g.First().Process,
                g.First().ServicesDisplay,
                g.Select(r => r.Path).FirstOrDefault(p => p != "") ?? "",
                g.Count(),
                g.Select(r => r.RemoteIp).Distinct().Count(),
                g.Max(r => r.LastSeen)))
            .OrderBy(g => g.Process, StringComparer.OrdinalIgnoreCase)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>
    /// From when a destination counts as "new": the last 24 hours, but not the first hour
    /// of the log — on the first run everything would be new. Null means nothing is new yet.
    /// </summary>
    public static DateTimeOffset? NewSince(DateTimeOffset now, DateTimeOffset? logStart)
    {
        if (logStart is not { } start) return null;
        var since = new[] { now.AddHours(-24), start.AddHours(1) }.Max();
        return since > now ? null : since;
    }

    /// <summary>Marks rows whose destination was first seen at or after <paramref name="since"/>.</summary>
    public static void MarkNew(IEnumerable<DestinationRow> rows, IReadOnlyDictionary<string, DateTimeOffset> firstSeen, DateTimeOffset? since)
    {
        foreach (var r in rows)
            r.IsNew = since is { } s && firstSeen.TryGetValue(r.Key, out var first) && first >= s;
    }

    /// <summary>Distinct addresses of the rows, sorted, one per line.</summary>
    public static List<IPAddress> Addresses(IEnumerable<DestinationRow> rows) =>
        rows.Select(r => r.RemoteIp).DistinctBy(IpKey.From).OrderBy(IpKey.From).ToList();
}
