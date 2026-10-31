using System.Net;

namespace NetWatcher.Core.Net;

/// <summary>Turns address lists and ranges into the smallest set of networks.</summary>
public static class CidrMath
{
    /// <summary>
    /// Exact cover of a range: 10.0.0.0–10.0.2.255 becomes 10.0.0.0/23 and 10.0.2.0/24.
    /// Both ends must be the same family.
    /// </summary>
    public static List<Cidr> FromRange(UInt128 start, UInt128 end)
    {
        if (start > end) (start, end) = (end, start);
        var v4 = IpKey.IsV4(start);
        if (v4 != IpKey.IsV4(end)) throw new ArgumentException("Начало и конец диапазона из разных семейств адресов.");

        var result = new List<Cidr>();
        while (true)
        {
            // Largest block aligned on start that does not pass end.
            var size = start == 0 ? 128 : (int)UInt128.TrailingZeroCount(start);
            if (v4) size = Math.Min(size, 32);
            while (size > 0)
            {
                if (size == 128)
                {
                    // Only the whole IPv6 space; 1 << 128 cannot be computed.
                    if (start == 0 && end == UInt128.MaxValue) break;
                    size--;
                    continue;
                }
                // start is aligned on 2^size, so this sum cannot overflow.
                if (start + ((UInt128.One << size) - 1) <= end) break;
                size--;
            }
            if (size == 128)
            {
                result.Add(new Cidr(start, 0, false));
                break;
            }

            var prefix = (v4 ? 32 : 128) - size;
            result.Add(new Cidr(start, prefix, v4));
            var last = start + ((UInt128.One << size) - 1);
            if (last >= end) break;
            start = last + 1;
        }
        return result;
    }

    /// <summary>Lossless: the given addresses only, contiguous ones merged.</summary>
    public static List<Cidr> Summarize(IEnumerable<IPAddress> addresses) =>
        Merge(addresses.Select(a => Cidr.Of(a, IpKey.IsV4(IpKey.From(a)) ? 32 : 128)));

    /// <summary>
    /// Widens every address to its /v4Prefix or /v6Prefix network, then merges.
    /// For example all addresses within 1.2.3.0/24 become one line.
    /// </summary>
    public static List<Cidr> Aggregate(IEnumerable<IPAddress> addresses, int v4Prefix, int v6Prefix) =>
        Merge(addresses.Select(a =>
        {
            var key = IpKey.From(a);
            return IpKey.IsV4(key) ? new Cidr(key, v4Prefix, true) : new Cidr(key, v6Prefix, false);
        }));

    /// <summary>Removes networks covered by others and joins neighbours into the fewest blocks.</summary>
    public static List<Cidr> Merge(IEnumerable<Cidr> networks)
    {
        var ranges = networks
            .Select(n => (n.Start, n.End, n.IsV4))
            .OrderBy(r => r.Start)
            .ToList();

        var result = new List<Cidr>();
        var i = 0;
        while (i < ranges.Count)
        {
            var (start, end, v4) = ranges[i++];
            while (i < ranges.Count && ranges[i].IsV4 == v4 && (end == UInt128.MaxValue || ranges[i].Start <= end + 1))
            {
                if (ranges[i].End > end) end = ranges[i].End;
                i++;
            }
            result.AddRange(FromRange(start, end));
        }
        return result;
    }
}
