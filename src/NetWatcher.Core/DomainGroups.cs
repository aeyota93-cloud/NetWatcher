namespace NetWatcher.Core;

/// <summary>
/// "Program → domain → addresses": rows are folded under their main domain, the way
/// people think about traffic. Addresses without a known domain stay on their own.
/// </summary>
public sealed class DomainGroup
{
    public required string Key { get; init; }

    /// <summary>"" when no domain is known for the address.</summary>
    public required string Domain { get; init; }

    public required IReadOnlyList<DestinationRow> Rows { get; init; }

    public DateTimeOffset LastSeen => Rows.Max(r => r.LastSeen);
    public long Hits => Rows.Sum(r => r.Hits);
    public int Addresses => Rows.Select(r => r.RemoteIp).Distinct().Count();
    public bool IsNew => Rows.Any(r => r.IsNew);

    public static List<DomainGroup> Build(IEnumerable<DestinationRow> rows) =>
        rows.GroupBy(r => r.PrimaryDomain != "" ? "d:" + r.PrimaryDomain : "i:" + r.Key)
            .Select(g => new DomainGroup
            {
                Key = g.Key,
                Domain = g.First().PrimaryDomain,
                Rows = g.OrderByDescending(r => r.LastSeen).ThenBy(r => r.RemoteIpText, StringComparer.Ordinal).ToList(),
            })
            .OrderByDescending(g => g.LastSeen)
            .ThenBy(g => g.Domain == "" ? 1 : 0)
            .ThenBy(g => g.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
}
