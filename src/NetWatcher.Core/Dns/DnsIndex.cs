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

    /// <summary>Domains the process itself asked, or all known if none, newest first.</summary>
    public IReadOnlyList<string> Get(IPAddress ip, string? process, int max = 5)
    {
        lock (_lock)
        {
            if (!_byIp.TryGetValue(IpKey.From(ip), out var list)) return [];
            var entries = process != null && list.Any(e => string.Equals(e.Process, process, StringComparison.OrdinalIgnoreCase))
                ? list.Where(e => string.Equals(e.Process, process, StringComparison.OrdinalIgnoreCase))
                : list;
            return entries
                .OrderByDescending(e => e.LastSeen)
                .Select(e => e.Domain)
                .Distinct()
                .Take(max)
                .ToList();
        }
    }

    /// <summary>DNS answers seen by a process (or by everyone when null), newest first.</summary>
    public List<DnsAnswer> Answers(Func<string, bool>? process, DateTimeOffset since)
    {
        lock (_lock)
        {
            return _byIp
                .SelectMany(kv => kv.Value
                    .Where(e => e.LastSeen >= since && (process == null || process(e.Process)))
                    .Select(e => (Ip: kv.Key, e)))
                .GroupBy(x => (x.e.Domain, Process: x.e.Process.ToLowerInvariant()))
                .Select(g => new DnsAnswer(
                    g.Key.Domain,
                    g.First().e.Process,
                    g.Select(x => IpKey.ToAddress(x.Ip)).OrderBy(IpKey.From).ToList(),
                    g.Max(x => x.e.LastSeen)))
                .OrderByDescending(a => a.LastSeen)
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

    /// <summary>Forgets everything, e.g. when the user clears the history.</summary>
    public void Clear()
    {
        lock (_lock) _byIp.Clear();
    }

    public int Count
    {
        get
        {
            lock (_lock) return _byIp.Count;
        }
    }

    public sealed record DnsAnswer(string Domain, string Process, IReadOnlyList<IPAddress> Addresses, DateTimeOffset LastSeen);

    private sealed record Entry(string Domain, string Process, DateTimeOffset LastSeen);
}
