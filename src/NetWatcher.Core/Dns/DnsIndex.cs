using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Dns;

/// <summary>
/// In-memory "IP → domains" built from DNS answers. A domain asked by the same
/// process is preferred: one CDN address can serve dozens of sites.
/// </summary>
public sealed class DnsIndex
{
    private readonly Lock _lock = new();
    private readonly Dictionary<UInt128, List<Entry>> _byIp = [];

    public void Add(IPAddress ip, string domain, string process, DateTimeOffset time)
    {
        var key = IpKey.From(ip);
        domain = DnsResultParser.NormalizeName(domain);
        if (domain == "") return;
        lock (_lock)
        {
            if (!_byIp.TryGetValue(key, out var list)) _byIp[key] = list = [];
            var i = list.FindIndex(e => e.Domain == domain && string.Equals(e.Process, process, StringComparison.OrdinalIgnoreCase));
            if (i >= 0)
            {
                if (list[i].LastSeen < time) list[i] = list[i] with { LastSeen = time };
            }
            else list.Add(new Entry(domain, process, time));
        }
    }

    /// <summary>Domains for the address: those the process itself asked first, newest first.</summary>
    public IReadOnlyList<string> Get(IPAddress ip, string? process, int max = 5)
    {
        lock (_lock)
        {
            if (!_byIp.TryGetValue(IpKey.From(ip), out var list)) return [];
            return list
                .OrderByDescending(e => process != null && string.Equals(e.Process, process, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(e => e.LastSeen)
                .Select(e => e.Domain)
                .Distinct()
                .Take(max)
                .ToList();
        }
    }

    public void RemoveOlderThan(DateTimeOffset cutoff)
    {
        lock (_lock)
        {
            foreach (var key in _byIp.Keys.ToList())
            {
                var list = _byIp[key];
                list.RemoveAll(e => e.LastSeen < cutoff);
                if (list.Count == 0) _byIp.Remove(key);
            }
        }
    }

    public int Count
    {
        get
        {
            lock (_lock) return _byIp.Count;
        }
    }

    private sealed record Entry(string Domain, string Process, DateTimeOffset LastSeen);
}
