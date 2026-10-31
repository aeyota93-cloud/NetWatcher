using System.Net;
using System.Net.Sockets;

namespace NetWatcher.Core.Net;

/// <summary>
/// One number for any address: IPv6 as is, IPv4 as ::ffff:a.b.c.d. This lets
/// IPv4 and IPv6 share sorting, range lookups and CIDR math.
/// </summary>
public static class IpKey
{
    /// <summary>Start of the IPv4-mapped block ::ffff:0:0/96.</summary>
    public static readonly UInt128 V4Base = (UInt128)0xFFFF << 32;

    public static UInt128 From(IPAddress ip)
    {
        ip = Normalize(ip);
        Span<byte> b = stackalloc byte[16];
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> v4 = stackalloc byte[4];
            ip.TryWriteBytes(v4, out _);
            return V4Base | ((UInt128)v4[0] << 24 | (UInt128)v4[1] << 16 | (UInt128)v4[2] << 8 | v4[3]);
        }

        ip.TryWriteBytes(b, out _);
        UInt128 key = 0;
        foreach (var x in b) key = key << 8 | x;
        return key;
    }

    public static bool IsV4(UInt128 key) => key >> 32 == 0xFFFF;

    public static IPAddress ToAddress(UInt128 key)
    {
        if (IsV4(key))
        {
            var v = (uint)(key & 0xFFFF_FFFF);
            return new IPAddress([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);
        }

        var b = new byte[16];
        for (var i = 15; i >= 0; i--)
        {
            b[i] = (byte)(key & 0xFF);
            key >>= 8;
        }
        return new IPAddress(b);
    }

    /// <summary>::ffff:1.2.3.4 becomes 1.2.3.4; scope ids are dropped.</summary>
    public static IPAddress Normalize(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) return ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.ScopeId != 0)
            return new IPAddress(ip.GetAddressBytes());
        return ip;
    }

    public static bool TryParse(string? text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (!IPAddress.TryParse(text.Trim(), out var parsed)) return false;
        ip = Normalize(parsed);
        return true;
    }

    /// <summary>Home and office networks, carrier NAT and link-local: not the internet.</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        ip = Normalize(ip);
        if (IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return b[0] == 10
                   || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                   || (b[0] == 192 && b[1] == 168)
                   || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                   || (b[0] == 169 && b[1] == 254);
        return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80);
    }

    /// <summary>0.0.0.0, 127.x and :: — what DNS filters answer for a blocked name.</summary>
    public static bool IsSinkhole(IPAddress ip)
    {
        ip = Normalize(ip);
        return ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(ip);
    }

    /// <summary>
    /// Addresses not worth showing as a destination: unspecified, loopback,
    /// multicast and broadcast.
    /// </summary>
    public static bool IsUninteresting(IPAddress ip, bool hideLoopback)
    {
        ip = Normalize(ip);
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast)) return true;
        if (hideLoopback && IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var first = ip.GetAddressBytes()[0];
            return first >= 224; // multicast and reserved
        }
        return ip.IsIPv6Multicast;
    }
}
