using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Dns;

/// <summary>
/// Reads the QueryResults field of the Windows DNS client event 3008, e.g.
/// "type:  5 star-mini.c10r.facebook.com;::ffff:157.240.1.35;2a03:2880::1;".
/// Entries are separated by ';'. "type: N name" are aliases (CNAME), the rest are addresses.
/// </summary>
public static class DnsResultParser
{
    public static (List<IPAddress> Addresses, List<string> Aliases) Parse(string? results)
    {
        var addresses = new List<IPAddress>();
        var aliases = new List<string>();
        if (string.IsNullOrWhiteSpace(results)) return (addresses, aliases);

        foreach (var raw in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3) aliases.Add(NormalizeName(parts[^1]));
                continue;
            }
            if (IpKey.TryParse(raw, out var ip) && !addresses.Contains(ip)) addresses.Add(ip);
        }
        return (addresses, aliases);
    }

    public static string NormalizeName(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();
}
